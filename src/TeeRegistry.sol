// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.25;

import {IVtpmAttestation} from "./interfaces/IVtpmAttestation.sol";

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
contract TeeRegistry {
    address public owner;

    /// The currently trusted TEE wallet (recovers EIP-712 settlement signatures against this).
    address public activeTeeWallet;
    /// The TEE's secp256k1 public key, so agents can ECIES-seal submissions to it.
    bytes public activeTeePublicKey;
    /// The expected Confidential Space container image digest (the code identity).
    string public expectedImageDigest;
    /// The on-chain vTPM attestation verifier. Zero = attestation-gated `register` disabled (dev).
    IVtpmAttestation public immutable vtpm;

    event TeeRegistered(address indexed teeWallet, string imageDigest);

    error NotOwner();
    error VtpmUnset();
    error BadImageDigest();
    error BadNonce();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(string memory expectedImageDigest_, address vtpm_) {
        owner = msg.sender;
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

    /// The attestation nonce the enclave MUST request when fetching its token, binding the token to
    /// exactly this (wallet, pubkey). The TEE computes the same value off-chain before requesting.
    function nonceFor(address teeWallet, bytes memory teePublicKey) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(teeWallet, teePublicKey));
    }

    function isTee(address who) external view returns (bool) {
        return who != address(0) && who == activeTeeWallet;
    }
}
