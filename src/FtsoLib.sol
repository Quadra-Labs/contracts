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
    /// `feedIds`, `groundTruthValues` and `proofs` are not the same length.
    error GroundTruthLengthMismatch();
    /// A settlement arrived with no ground truth at all. Never a valid shape — see checkGroundTruths.
    error NoGroundTruth();
    /// A proof was supplied for a feed the signature does not name. THE bug this exists to stop.
    error FeedIdMismatch(bytes21 signed, bytes21 proven);
    /// `feedIds` is not strictly increasing, so it either repeats a feed or is unsorted.
    error FeedIdsNotSorted(bytes21 previous, bytes21 next);
    /// The proof is a real reading of the right feed, from the WRONG TIME.
    error StaleVotingRound(uint256 expected, uint256 proven);
    /// The epoch geometry is unusable, or the settlement time predates FTSO itself.
    error BadVotingEpoch();

    /// How far a proof's voting round may sit from the one covering the settlement time.
    ///
    /// The engine derives the round from `resolveAt` (or `lifetimeEnd`) EXACTLY and with no
    /// fallback — `quadra-core/groundTruth.ts` requests `votingRoundIdForTimestamp(resolveAt)` and
    /// re-checks that the DA layer answered for that round — so in the normal case this could be an
    /// equality. It is a window instead for one reason: if the epoch geometry held here ever
    /// disagreed with the engine's by even one round, an equality would revert EVERY settlement,
    /// and a competition whose settlement always reverts can only be unwound by `cancel` after
    /// CANCEL_WINDOW. That trades a silent wrong answer for a three-day outage, which is not the
    /// better failure.
    ///
    /// 40 rounds is one hour at Coston2's 90-second epochs. That is a rounding-error allowance, not
    /// a meaningful attack surface: it collapses "any reading in FTSO history" (millions of rounds)
    /// to "a reading from around the resolution time", which removes the whole class of picking a
    /// favourable historical price. An enclave that wanted a price from an hour away could simply
    /// have waited an hour.
    uint256 internal constant MAX_ROUND_DRIFT = 40;

    /// Everything needed to decide whether a proof is BOTH the right feed and the right time.
    ///
    /// Bundled because the three fields are meaningless apart: a verifier with no epoch geometry
    /// checks the price but not the instant, which is exactly the gap this struct closes.
    struct GroundTruthWindow {
        IFtsoFeedVerifier verifier;
        /// FTSO epoch geometry, from `FlareSystemsManager`. NEVER hardcode these — `dev.flare.network`
        /// publishes a different `firstVotingRoundStartTs` for a sibling network, and a wrong
        /// geometry produces a plausible round, a real finalized feed and a verifying Merkle proof
        /// for the WRONG INSTANT, with nothing reporting an error.
        uint64 firstVotingRoundStartTs;
        uint64 votingEpochDurationSeconds;
        /// When the item resolves: `resolveAt` for a competition, `lifetimeEnd` for a paid job.
        uint256 settlementTimeSecs;
    }

    /// The FTSO voting round covering `unixSeconds`, by the same formula the off-chain side uses
    /// (`quadra-core/feeds.ts votingRoundIdForTimestampIn`). Integer division, so both sides land on
    /// the same round for the same inputs.
    function votingRoundFor(GroundTruthWindow memory w, uint256 unixSeconds)
        internal
        pure
        returns (uint256)
    {
        if (w.votingEpochDurationSeconds == 0) revert BadVotingEpoch();
        if (unixSeconds < w.firstVotingRoundStartTs) revert BadVotingEpoch();
        return (unixSeconds - w.firstVotingRoundStartTs) / w.votingEpochDurationSeconds;
    }

    /// Require the proof to come from around the settlement time, not merely from some time.
    ///
    /// WHY THIS EXISTS. Verifying the feed id and the Merkle proof establishes "this feed really did
    /// carry this value" — and says nothing about WHEN. Without this, a competition resolving today
    /// settles on a genuine, finalized reading from FTSO's first voting round in July 2022: the
    /// proof verifies, the value matches what the TEE signed, the feed is the right one. A
    /// compromised enclave could pick whichever historical price makes its preferred agent win, and
    /// both the chain and `quadra-verify` would confirm it. More likely in practice, a wrong epoch
    /// geometry off chain scores every settlement against the wrong instant and nothing notices.
    function checkVotingRound(GroundTruthWindow memory w, uint32 provenRound) internal pure {
        uint256 expected = votingRoundFor(w, w.settlementTimeSecs);
        uint256 drift = provenRound > expected ? provenRound - expected : expected - provenRound;
        if (drift > MAX_ROUND_DRIFT) revert StaleVotingRound(expected, provenRound);
    }

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
        GroundTruthWindow memory w,
        uint256 groundTruthValue,
        IFtsoFeedVerifier.FeedDataWithProof memory proof
    ) internal view {
        if (address(w.verifier) == address(0)) return;
        if (!w.verifier.verifyFeedData(proof)) revert BadFtsoProof();
        if (normalizedPrice(proof.body) != groundTruthValue) revert GroundTruthMismatch();
        // The proof is the right VALUE; this is what makes it the right TIME.
        checkVotingRound(w, proof.body.votingRoundId);
    }

    /// The multi-feed form: require that EVERY (feedId, value) pair the TEE signed is backed by a
    /// verifying proof for THAT feed.
    ///
    /// WHY THIS EXISTS. A settlement used to carry one `groundTruthValue` and one proof, so a
    /// portfolio competition naming BTC, ETH and SOL had two of its three legs attested by the TEE
    /// signature alone — the contract cross-checked one asset and took the rest on trust. That was
    /// a real gap between what the product claims ("double verification") and what the code does.
    ///
    /// THE FEED ID CHECK IS THE LOAD-BEARING PART, and it is why `feedIds` is inside the signed
    /// struct rather than read off the proofs. Without it, a relayer holding a signed settlement
    /// could swap in a proof from a DIFFERENT feed that happens to carry the same normalized
    /// value, and every check here would pass: the Merkle proof is real, the round is finalized,
    /// the value matches. The settlement would be verifiably wrong — scored against the wrong
    /// asset, and `quadra-verify` would faithfully confirm it. This is the same failure shape as
    /// the `?? list[0]` fallback in `groundTruth.ts` (BUGS.md 6), one layer down.
    ///
    /// SHAPE IS CHECKED EVEN ON THE DEV PATH. The length and non-empty guards run BEFORE the
    /// zero-verifier early return, so a settlement whose arrays are malformed fails identically
    /// with and without a wired verifier. The alternative — dev accepting shapes prod rejects — is
    /// how a settlement passes every local test and reverts on chain.
    ///
    /// AN EMPTY ARRAY IS REJECTED, not treated as "nothing to check". Passing empty arrays would
    /// otherwise be a complete, silent bypass of the oracle half of the design, reachable by a bug
    /// rather than by an attack — which is the kind of bypass worth spending a comparison on.
    function checkGroundTruths(
        GroundTruthWindow memory w,
        bytes21[] memory feedIds,
        uint256[] memory groundTruthValues,
        IFtsoFeedVerifier.FeedDataWithProof[] memory proofs
    ) internal view {
        uint256 n = feedIds.length;
        if (n == 0) revert NoGroundTruth();
        if (groundTruthValues.length != n || proofs.length != n) revert GroundTruthLengthMismatch();

        // STRICTLY INCREASING, which is how `feedIds.length` becomes evidence of coverage rather
        // than just a count. Without it a two-asset portfolio settles with feedIds = [BTC, BTC] and
        // two different BTC readings: the array lengths agree, every proof verifies, every value
        // matches, and ETH is covered by nothing — while an auditor reading `feedIds.length == 2`
        // on chain has no way to tell. Sorting is free for the producer (the engine already emits
        // assets in sorted order) and makes duplicates impossible to express.
        //
        // Part of the shape contract, so it runs on the dev path too.
        for (uint256 i = 1; i < n; i++) {
            if (feedIds[i] <= feedIds[i - 1]) revert FeedIdsNotSorted(feedIds[i - 1], feedIds[i]);
        }

        if (address(w.verifier) == address(0)) return;

        // Computed ONCE, outside the loop: every leg of one settlement resolves at the same instant
        // (`resolveForPortfolio` passes a single `resolveAtSecs` for every asset), so a per-asset
        // expected round would be the same value recomputed N times.
        uint256 expectedRound = votingRoundFor(w, w.settlementTimeSecs);

        for (uint256 i = 0; i < n; i++) {
            if (proofs[i].body.id != feedIds[i]) revert FeedIdMismatch(feedIds[i], proofs[i].body.id);
            if (!w.verifier.verifyFeedData(proofs[i])) revert BadFtsoProof();
            if (normalizedPrice(proofs[i].body) != groundTruthValues[i]) revert GroundTruthMismatch();

            uint256 provenRound = proofs[i].body.votingRoundId;
            uint256 drift = provenRound > expectedRound ? provenRound - expectedRound : expectedRound - provenRound;
            if (drift > MAX_ROUND_DRIFT) revert StaleVotingRound(expectedRound, provenRound);
        }
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
