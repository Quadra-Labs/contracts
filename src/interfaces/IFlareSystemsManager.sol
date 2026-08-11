// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.25;

/// @title IFlareSystemsManager
/// @notice The two values that define FTSO's voting-round geometry, read at DEPLOY time and
/// injected into both markets so they can decide which round covers a settlement's resolution
/// instant.
///
/// Resolve this through `ContractRegistry.getContractAddressByName("FlareSystemsManager")` — never
/// hardcode either the manager's address or the numbers it returns. MIGRATION-PLAN contradiction 10
/// records why: `dev.flare.network` publishes `1658429955` as the first-round start for a sibling
/// network while Coston2 uses `1658430000`, and a 45-second error is enough to shift a round
/// boundary. The failure that produces is the quiet kind — a plausible round, a real finalized
/// feed, a Merkle proof that verifies, and a settlement scored against the wrong instant, with
/// nothing reporting an error.
///
/// `quadra-core/voting-epoch` reads the same two values off chain for the same reason (BUGS.md 11).
/// The two sides MUST agree: the contract derives the expected round from `resolveAt`, the engine
/// derives the round it fetches from the same timestamp, and a disagreement of one round is what
/// `FtsoLib.MAX_ROUND_DRIFT` exists to absorb rather than to hide.
interface IFlareSystemsManager {
    /// Unix seconds at which voting round 0 began.
    function firstVotingRoundStartTs() external view returns (uint64);

    /// Seconds per voting round (90 on Coston2 and Flare mainnet).
    function votingEpochDurationSeconds() external view returns (uint64);
}
