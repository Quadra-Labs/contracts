// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.25;

/// @title IVtpmAttestation
/// @notice The seam to Flare's on-chain vTPM attestation verifier (flare-foundation/flare-vtpm-
/// attestation, `FlareVtpmAttestation`). It parses a Google Confidential Space attestation JWT and
/// validates its signature (RS256/JWKS or x5c) and standard claims (exp/iat/iss/secboot/hwmodel/
/// swname). `TeeRegistry.register` calls this, then enforces the two app-specific bindings itself:
/// the container image digest == the pinned code identity, and the `eat_nonce` == this exact
/// (wallet, pubkey) — so a valid token cannot register a different key.
///
/// Defined locally (no heavy dependency) to keep TeeRegistry's LOGIC testable with a mock. The real
/// `FlareVtpmAttestation` validates most claims against a baseline config and its raw API differs, so
/// production wires it through a thin adapter that surfaces the verified `imageDigest` + `eatNonce`.
/// This interface is the contract that adapter must satisfy; validate it against the real library.
///
/// The adapter does not exist yet and `flare-vtpm-attestation` is not vendored, so `register` is
/// currently unreachable in practice: it reverts `VtpmUnset` whenever the verifier is unset, which
/// is the deployed configuration. The working paths are `setActiveTee` (dev) and, once the FCC layer
/// lands, `registerFccTee`.
interface IVtpmAttestation {
    /// Verify the attestation JWT `(header, payload, signature)`. MUST revert if the signature,
    /// issuer, expiry, or secure-boot claims are invalid. On success returns the verified container
    /// image digest and the token's `eat_nonce` claim (as bytes32) for the caller to bind.
    function verifyAttestation(bytes calldata header, bytes calldata payload, bytes calldata signature)
        external
        returns (string memory imageDigest, bytes32 eatNonce);
}
