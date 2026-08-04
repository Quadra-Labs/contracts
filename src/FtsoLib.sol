// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.25;

import {IFtsoFeedVerifier} from "./interfaces/IFtsoFeedVerifier.sol";

/// @title FtsoLib
/// @notice Shared ground-truth cross-check used by BOTH settlement markets (JobEscrow +
/// SealedCompetition). It confirms the `groundTruthValue` the TEE signed in the EIP-712 settlement
/// is a REAL, finalized FTSO anchor feed value — so trust is not only in the attested TEE but also
/// in an enshrined oracle proof the contract verifies itself.
///
/// Units: the app scores in 1e-8 fixed point (`PRICE_DECIMALS`), the same canonical unit the bots'
/// skills emit for minPrice/maxPrice (ported from the Sui engine's 1e-8 discipline). An FTSO anchor
/// feed carries `value` in the feed's own `decimals`, so the canonical price is
/// `value * 10**(PRICE_DECIMALS - decimals)`. The TEE and this library MUST agree on this formula
/// exactly (it is part of the ABI of trust, alongside the EIP-712 struct hashes).
library FtsoLib {
    /// The app's canonical price precision (1e-8 fixed point).
    ///
    /// Exposed through a public getter on both markets so off-chain code reads the value rather
    /// than re-declaring it — a silent disagreement here mis-scales every price by a power of ten.
    uint256 internal constant PRICE_DECIMALS = 8;

    /// The Merkle proof did not verify against the FTSO verifier (or the feed value is negative).
    error BadFtsoProof();
    /// The proven feed value (normalized to 1e-8) does not equal the signed groundTruthValue.
    error GroundTruthMismatch();
    /// The feed's decimals are outside the supported [0, PRICE_DECIMALS] range.
    error BadFtsoDecimals();

    /// Require that `proof` verifies AND its normalized value equals `groundTruthValue`. When
    /// `verifier` is the zero address the check is skipped — the dev/simulate path used before the
    /// real FtsoV2 address is wired (mirrors the TeeRegistry dev path).
    ///
    /// The zero-address skip is a full bypass of the oracle half of "double verification", so a
    /// deployment that leaves it unset is NOT doing what the design claims. Both markets hold the
    /// verifier as `immutable`, meaning the only way to switch it on later is a redeploy; the
    /// deploy script guards against shipping it unset.
    ///
    /// Takes `memory`, not `calldata`: the FCC settlement paths decode the proof out of the signed
    /// ActionResult blob, so it only ever exists in memory there. Calldata callers (the legacy
    /// EIP-712 paths) convert implicitly, so one implementation still serves both.
    function checkGroundTruth(
        IFtsoFeedVerifier verifier,
        uint256 groundTruthValue,
        IFtsoFeedVerifier.FeedDataWithProof memory proof
    ) internal view {
        if (address(verifier) == address(0)) return;
        if (!verifier.verifyFeedData(proof)) revert BadFtsoProof();
        if (normalizedPrice(proof.body) != groundTruthValue) revert GroundTruthMismatch();
    }

    /// Convert an FTSO feed reading to the app's 1e-8 fixed-point price. Reverts on a negative value
    /// or unsupported decimals so a malformed proof can never silently pass the equality check.
    function normalizedPrice(IFtsoFeedVerifier.FeedData memory body) internal pure returns (uint256) {
        if (body.value < 0) revert BadFtsoProof();
        int256 d = int256(body.decimals);
        // casting to 'int256' is safe because PRICE_DECIMALS is the constant 8
        // forge-lint: disable-next-line(unsafe-typecast)
        if (d < 0 || d > int256(PRICE_DECIMALS)) revert BadFtsoDecimals();
        // casting to 'uint256' is safe because the line above bounds d to [0, PRICE_DECIMALS],
        // so the difference is in [0, 8] and can never be negative
        // forge-lint: disable-next-line(unsafe-typecast)
        uint256 scale = 10 ** uint256(int256(PRICE_DECIMALS) - d);
        // casting to 'uint256' is safe because body.value was checked non-negative above
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint256(int256(body.value)) * scale;
    }
}
