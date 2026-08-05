// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.25;

/// @title SignatureLib
/// @notice secp256k1 recovery for the settlement paths.
///
/// Signature recovery IS the authorization model here: a settlement is accepted because the
/// recovered signer equals the registered TEE wallet. That makes this the most security-critical
/// twenty lines in the repo, so the checks `ecrecover` does not do itself are done here.
///
/// Two hazards `ecrecover` leaves to the caller:
///
///  - **Malleability.** For any valid `(r, s, v)` the pair `(r, n - s, v ^ 1)` recovers the same
///    signer, so one authorization has two distinct encodings. Anything that treats the signature
///    bytes as an identifier - a replay-protection set, a dedupe key, an off-chain log - can be
///    bypassed by flipping to the sibling form. EIP-2 fixes this by declaring only the low half of
///    the curve order canonical, which is what the `s` bound below enforces.
///  - **Unvalidated `v`.** `ecrecover` returns zero for a malformed `v`, which is safe only if the
///    caller checks the result. Normalizing with a bare `if (v < 27) v += 27` leaves every other
///    value untouched and passes it straight through, so `v = 100` reaches the precompile. Here `v`
///    is normalized from the 0/1 convention and then required to be exactly 27 or 28.
///
/// Returns `address(0)` rather than reverting on any invalid input, matching `ecrecover` itself;
/// every caller already treats a zero signer as a failed check.
library SignatureLib {
    /// secp256k1 group order / 2. An `s` above this is the non-canonical half of the pair.
    uint256 private constant HALF_CURVE_ORDER =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    /// Recover the signer of `digest` from a 65-byte (r, s, v) signature.
    function recover(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        if (sig.length != 65) return address(0);

        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }

        // Accept the 0/1 convention some signers emit, then require a canonical value.
        if (v < 27) v += 27;
        if (v != 27 && v != 28) return address(0);
        if (uint256(s) > HALF_CURVE_ORDER) return address(0);

        return ecrecover(digest, v, r, s);
    }
}
