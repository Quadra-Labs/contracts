// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.25;

import {SignatureLib} from "./SignatureLib.sol";

/// @title TeeActionResult
/// @notice Recovers the signer of a Flare Confidential Compute `ActionResult`. This is the FCC
/// counterpart of the EIP-712 recovery the two market contracts already do for the self-operated
/// TEE: same job (prove these bytes came from the attested enclave), different scheme.
///
/// The TEE node does NOT sign the result hash directly. It signs a domain-separated payload:
///
///     resultHash  = keccak256(abi.encodePacked(
///                       keccak256(data), actionId, keccak256(bytes(submissionTag)), status))
///     payloadHash = keccak256(abi.encode(bytes32("TEE_ACTION_RESULT"), chainId, resultHash))
///     signature   = eth_sign(payloadHash)        // EIP-191 personal-sign prefix
///
/// Both wrappers matter. The `TEE_ACTION_RESULT` tag stops a signature over some other TEE payload
/// type being replayed as an action result, and `chainId` stops a Coston2 result being replayed on
/// mainnet. Verifying against the bare `resultHash` compiles, looks right, and rejects every real
/// signature the node produces - so this library is the single place the layout is written down.
///
/// NOTE ON THE MISSING `verifyingContract`: unlike our EIP-712 domains, this digest does not bind
/// to a contract address, so a result signed for one deployment verifies against any deployment on
/// the same chain that trusts the same TEE machine. That is NOT a defect to patch here - the layout
/// is normative, mirroring go-flare-common `signing.TEEActionResult`, and changing it unilaterally
/// would mean no real signature from a Flare TEE node ever verifies again. It is mitigated instead
/// by the per-deployment `consumedActionId` guard in the consuming contracts, and by rotating the
/// registered TEE wallet on redeploy.
///
/// Mirrors go-flare-common `signing.TEEActionResult` and the reference verification in
/// flare-foundation/fce-weather-insurance `WeatherInsurance.sol`.
library TeeActionResult {
    /// The domain tag the node prefixes action-result payloads with. bytes32, not a hash.
    bytes32 internal constant PREFIX = bytes32("TEE_ACTION_RESULT");

    /// Only a successful action carries meaningful `data` (extension contract section 4.6).
    uint8 internal constant STATUS_OK = 1;

    /// The hash the node computed over the action result, before domain separation.
    function resultHash(bytes calldata data, bytes32 actionId, string calldata submissionTag, uint8 status)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(keccak256(data), actionId, keccak256(bytes(submissionTag)), status));
    }

    /// The digest the node actually signed: domain tag + chain id + result hash, EIP-191 wrapped.
    function digest(bytes calldata data, bytes32 actionId, string calldata submissionTag, uint8 status)
        internal
        view
        returns (bytes32)
    {
        bytes32 payloadHash =
            keccak256(abi.encode(PREFIX, block.chainid, resultHash(data, actionId, submissionTag, status)));
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", payloadHash));
    }

    /// Recover the TEE machine that produced this result, or address(0) if the signature is
    /// malformed. Rejects any non-success status outright: a status-0 result carries an error
    /// string rather than data, and settling on one would settle on nothing.
    ///
    /// Recovery goes through SignatureLib, so the same malleability and `v` checks apply here as on
    /// the EIP-712 path. That is a constraint on the SIGNATURE encoding, not on the digest, so it
    /// stays compatible with the node.
    function recoverSigner(
        bytes calldata data,
        bytes32 actionId,
        string calldata submissionTag,
        uint8 status,
        bytes calldata signature
    ) internal view returns (address) {
        if (status != STATUS_OK) return address(0);
        return SignatureLib.recover(digest(data, actionId, submissionTag, status), signature);
    }
}
