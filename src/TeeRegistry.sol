// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.25;

import {Ownable2Step} from "./Ownable2Step.sol";
import {IVtpmAttestation} from "./interfaces/IVtpmAttestation.sol";
import {ITeeMachineRegistry} from "./interfaces/ITeeMachineRegistry.sol";

/// @title TeeRegistry
/// @notice Binds the scorer TEE's on-chain identity (an secp256k1 wallet generated inside the
/// Confidential Space container at boot) to a verified workload measurement (the container image
/// digest). This is the Flare analog of Quadra's Sui `enclave::register_enclave` + PCR check, and the
/// M0 trust spine: only code whose image digest matches the pinned one, attested by a real vTPM JWT,
/// can bind the wallet whose signature the settlement contracts trust.
///
/// Two paths exist today:
///  - `register` (attestation-gated): verifies the Confidential Space JWT through our own vTPM
///    verifier, pins `submods.container.image_digest == expectedImageDigest`, and binds the wallet
///    iff the token's `eat_nonce` commits to exactly that (wallet, pubkey). Its trust root is
///    owner-set JWKS keys, which is the weakness Flare Confidential Compute removes.
///  - `setActiveTee` (DEV): owner-only direct set, so the rest of the stack runs before the
///    verifier is wired.
///
/// A third path, `registerFccTee`, arrives with the Flare Confidential Compute layer. It binds a TEE
/// machine that Flare's `TeeMachineRegistry` already serves our extension — meaning its code hash was
/// whitelisted and its attestation accepted by Flare's data-provider consensus, so we verify nothing
/// about the enclave ourselves. See FCC-MIGRATION.md.
///
/// All paths converge on `activeTeeWallet`, so JobEscrow and SealedCompetition are unaware of which
/// one bound it and need no rewiring to switch modes.
contract TeeRegistry is Ownable2Step {
    /// The currently trusted TEE wallet (recovers EIP-712 settlement signatures against this).
    address public activeTeeWallet;
    /// The TEE's secp256k1 public key, so agents can ECIES-seal submissions to it.
    bytes public activeTeePublicKey;
    /// The expected Confidential Space container image digest (the code identity).
    string public expectedImageDigest;
    /// The on-chain vTPM attestation verifier. Zero = attestation-gated `register` disabled (dev).
    IVtpmAttestation public immutable vtpm;

    // --- Flare Confidential Compute ------------------------------------------------------------
    /// Flare's TEE machine registry. Zero = FCC mode not configured yet.
    ITeeMachineRegistry public teeMachineRegistry;
    /// Our extension id, as allocated by `TeeExtensionRegistry` when the extension was registered.
    uint256 public fccExtensionId;
    /// True once `activeTeeWallet` was bound through the FCC path rather than vTPM or dev.
    bool public fccMode;

    event TeeRegistered(address indexed teeWallet, string imageDigest);
    event FccTeeRegistered(address indexed teeMachine, uint256 extensionId);
    event FccConfigured(address indexed teeMachineRegistry, uint256 extensionId);

    error VtpmUnset();
    error BadImageDigest();
    error BadNonce();
    error FccUnset();
    error NoTeeAvailable();

    constructor(string memory expectedImageDigest_, address vtpm_) {
        expectedImageDigest = expectedImageDigest_;
        vtpm = IVtpmAttestation(vtpm_);
    }

    /// DEV path: register the TEE identity directly. Owner-only; for local/testnet before the real
    /// attestation verifier is wired.
    ///
    /// Note that this also overwrites `expectedImageDigest`. That means a dev call silently moves
    /// the production attestation pin, so once `register` is the real trust root this setter has to
    /// go (or the digest has to become write-once). Left as-is for now because the dev path is the
    /// only way to run the stack before attestation is stood up.
    function setActiveTee(address teeWallet, bytes calldata teePublicKey, string calldata imageDigest)
        external
        onlyOwner
    {
        activeTeeWallet = teeWallet;
        activeTeePublicKey = teePublicKey;
        expectedImageDigest = imageDigest;
        emit TeeRegistered(teeWallet, imageDigest);
    }

    /// Attestation-gated registration. Permissionless by design — the security is the token, not
    /// msg.sender, so anyone may relay a valid Confidential Space attestation. It (1) verifies the
    /// vTPM JWT, (2) requires the attested image digest == the pinned code identity, and (3) requires
    /// the token's `eat_nonce` == keccak(teeWallet, teePublicKey) so a valid token can only bind the
    /// exact key the enclave requested it for. On success binds the active identity.
    function register(
        bytes calldata header,
        bytes calldata payload,
        bytes calldata signature,
        address teeWallet,
        bytes calldata teePublicKey
    ) external {
        if (address(vtpm) == address(0)) revert VtpmUnset();
        (string memory imageDigest, bytes32 eatNonce) = vtpm.verifyAttestation(header, payload, signature);
        if (keccak256(bytes(imageDigest)) != keccak256(bytes(expectedImageDigest))) revert BadImageDigest();
        if (eatNonce != nonceFor(teeWallet, teePublicKey)) revert BadNonce();
        activeTeeWallet = teeWallet;
        activeTeePublicKey = teePublicKey;
        emit TeeRegistered(teeWallet, imageDigest);
    }

    /// Point the registry at Flare's TEE machine registry and our allocated extension id. Owner-only,
    /// and re-settable: if the `FlareTeeManager` diamond is redeployed every registration is wiped
    /// and the extension is re-registered under a fresh id, which this has to be able to follow.
    function configureFcc(address teeMachineRegistry_, uint256 extensionId_) external onlyOwner {
        if (teeMachineRegistry_ == address(0)) revert ZeroAddress();
        teeMachineRegistry = ITeeMachineRegistry(teeMachineRegistry_);
        fccExtensionId = extensionId_;
        emit FccConfigured(teeMachineRegistry_, extensionId_);
    }

    /// FCC path: bind `teeMachine` as the trusted settlement signer.
    ///
    /// Deliberately NOT re-deriving attestation here. Under FCC the enclave's code hash is
    /// whitelisted via `allow-tee-version` and the machine is admitted by `register-tee` only after
    /// Flare's data providers accept its Confidential Space attestation. A machine serving our
    /// extension has already passed all of that; re-checking it here would mean re-implementing
    /// Flare's attestation consensus in this contract, which is exactly the burden the migration
    /// sheds.
    ///
    /// The `getRandomTeeIds` call is a liveness assertion, not a membership proof: it fails fast if
    /// the extension has no serving machines at all (a mis-set `fccExtensionId`, or a wiped
    /// registry), which is the mistake actually worth catching here. It does NOT prove that
    /// `teeMachine` specifically serves us, so an owner typo still binds the wrong signer - which is
    /// why this is owner-gated rather than permissionless.
    function registerFccTee(address teeMachine, bytes calldata teePublicKey) external onlyOwner {
        if (address(teeMachineRegistry) == address(0)) revert FccUnset();
        if (teeMachine == address(0)) revert ZeroAddress();
        if (teeMachineRegistry.getRandomTeeIds(fccExtensionId, 1).length == 0) revert NoTeeAvailable();

        activeTeeWallet = teeMachine;
        activeTeePublicKey = teePublicKey;
        fccMode = true;
        emit FccTeeRegistered(teeMachine, fccExtensionId);
        emit TeeRegistered(teeMachine, expectedImageDigest);
    }

    /// The attestation nonce the enclave MUST request when fetching its token, binding the token to
    /// exactly this (wallet, pubkey). The TEE computes the same value off-chain before requesting.
    function nonceFor(address teeWallet, bytes memory teePublicKey) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(teeWallet, teePublicKey));
    }

    function isTee(address who) external view returns (bool) {
        return who != address(0) && who == activeTeeWallet;
    }
}
