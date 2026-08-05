// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.25;

import {Ownable2Step} from "./Ownable2Step.sol";

/// @title Passport
/// @notice Portable, tamper-proof agent reputation — the durable "memory" that replaces Quadra's
/// Walrus `agent_scores` doc. Each settled job or competition folds every entrant's score into a
/// running per-category track. A paid job and a competition both raise the SAME reputation — one
/// track record, two sources. This is what makes a one-shot into a proving ground: sealed inputs,
/// public track record. Only the authorized market contracts (JobEscrow AND SealedCompetition) may
/// write, via the `recorders` allow-list.
contract Passport is Ownable2Step {
    struct Track {
        uint32 scored; // number of scored jobs/competitions in this category
        uint64 totalScore; // sum of [0,MAX_SCORE] scores (average = totalScore / scored)
        uint8 best; // best single score seen
    }

    /// The upper bound on a single score, carried over from Quadra `competition.move`
    /// (`MAX_SCORE = 100`, enforced by `assert!(score <= MAX_SCORE, EBadScore)`).
    ///
    /// This is enforced HERE rather than at each caller on purpose: `record` is the one chokepoint
    /// every present and future recorder passes through, and `overall` below is only meaningful for
    /// scores in [0,100]. Without it a buggy or compromised scorer could inflate a track past the
    /// documented ceiling and permanently top the leaderboard.
    uint8 public constant MAX_SCORE = 100;

    /// Bayesian leaderboard params (Quadra's SCORE_CONFIDENCE = 20): a fresh agent starts at the
    /// prior mean and needs ~CONFIDENCE scored results before its own record dominates, so a single
    /// lucky 100 cannot top the board.
    uint256 private constant PRIOR_MEAN = 50;
    uint256 private constant CONFIDENCE = 20;

    /// The market contracts allowed to record scores (JobEscrow + SealedCompetition).
    mapping(address => bool) public recorders;

    mapping(address => mapping(bytes32 => Track)) private tracks;
    // Per-category participant set, maintained on first record, so `rank`/leaderboards can enumerate.
    mapping(bytes32 => address[]) private categoryAgents;
    mapping(bytes32 => mapping(address => bool)) private inCategory;

    event Recorded(address indexed agent, bytes32 indexed category, uint8 score);
    event RecorderSet(address indexed recorder, bool allowed);

    error NotRecorder();
    /// A score above MAX_SCORE was submitted. Ported from Quadra `competition::EBadScore`.
    error BadScore();

    /// Authorize (or revoke) a market contract to record scores. Owner-only.
    function setRecorder(address recorder, bool allowed) external onlyOwner {
        recorders[recorder] = allowed;
        emit RecorderSet(recorder, allowed);
    }

    /// Fold one settled result into the agent's track for this category.
    ///
    /// Reverts rather than clamping an out-of-range score: a score above the ceiling means the
    /// scorer is wrong, and silently clamping would write a plausible-looking record derived from
    /// a value nobody signed off on. Callers that batch (SealedCompetition.settle) therefore fail
    /// the whole settlement on bad data instead of paying against it.
    function record(address agent, bytes32 category, uint8 score) external {
        if (!recorders[msg.sender]) revert NotRecorder();
        if (score > MAX_SCORE) revert BadScore();
        Track storage t = tracks[agent][category];
        t.scored += 1;
        t.totalScore += score;
        if (score > t.best) t.best = score;
        if (!inCategory[category][agent]) {
            inCategory[category][agent] = true;
            categoryAgents[category].push(agent);
        }
        emit Recorded(agent, category, score);
    }

    function getTrack(address agent, bytes32 category)
        external
        view
        returns (uint32 scored, uint64 totalScore, uint8 best)
    {
        Track storage t = tracks[agent][category];
        return (t.scored, t.totalScore, t.best);
    }

    /// The Bayesian reputation for a track, scaled x100 (0..10000 = 0.00..100.00). A fresh agent
    /// (scored 0) reads the prior mean (5000); with more results it converges to totalScore/scored.
    function overall(address agent, bytes32 category) public view returns (uint256) {
        Track storage t = tracks[agent][category];
        return ((uint256(t.totalScore) + PRIOR_MEAN * CONFIDENCE) * 100) / (uint256(t.scored) + CONFIDENCE);
    }

    /// Every agent that has a track in `category` (for off-chain leaderboards / sorting).
    function agentsIn(bytes32 category) external view returns (address[] memory) {
        return categoryAgents[category];
    }

    /// 1-based rank of an agent within a category by `overall` (ties share a rank). 0 if unranked.
    function rank(address agent, bytes32 category) external view returns (uint256) {
        if (!inCategory[category][agent]) return 0;
        uint256 mine = overall(agent, category);
        address[] storage list = categoryAgents[category];
        uint256 higher = 0;
        for (uint256 i = 0; i < list.length; i++) {
            if (overall(list[i], category) > mine) higher += 1;
        }
        return higher + 1;
    }
}
