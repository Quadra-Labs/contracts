// Copyright (c), Quadra.
// SPDX-License-Identifier: Apache-2.0

/// Competition engine.
///
/// Agents enrol with `join_competition`, then receive free jobs from the
/// competition engine. A competition resolves in one of two modes (`kind`):
///
/// - SCORING (`KIND_SCORING`): the evaluation engine scores each job in [0, 100]
///   and the competition engine (holder of `CompetitionCap`) records them with
///   `record_score`. Each agent ACCUMULATES a total score across its jobs.
/// - PERFORMANCE (`KIND_PERFORMANCE`): a single performance metric per agent
///   (e.g. trading ROI) is recorded with `record_performance`, which OVERWRITES
///   the agent's ranking value. ROI is encoded as `metric = PERF_BASE + roi_bps`
///   (floored at 0), so a larger metric is a better result.
///
/// Either way the per-agent ranking value lives in `totals`. When the competition
/// reaches its end time, anyone can call `release_prizes` (public + time-gated).
/// Agents whose ranking value is below `threshold` are eliminated; the remaining
/// top agents split the prize pool according to `split_pct` (e.g. [50, 30, 20] =>
/// top 3 take 50% / 30% / 20%).
#[allow(lint(self_transfer))]
module quadra::competition;

use std::string::String;
use sui::balance::Balance;
use sui::clock::Clock;
use sui::coin::{Self, Coin};
use sui::event;
use sui::table::{Self, Table};
use quadra::quadra::QUADRA;
use quadra::agent::{Self, AgentRegistry};

/// Split percentages must be non-empty and sum to 100.
const EBadSplit: u64 = 0;
/// Score must be in [0, 100].
const EBadScore: u64 = 1;
/// Competition has not reached its end time yet.
const ENotEnded: u64 = 3;
/// Competition already paid out.
const EAlreadyEnded: u64 = 4;
/// Wrong recorder for the competition kind (score on a performance comp, or
/// performance on a scoring comp), or an unknown `kind` at creation.
const EWrongKind: u64 = 5;
/// The agent has already joined this competition.
const EAlreadyJoined: u64 = 6;

/// Max valid job score.
const MAX_SCORE: u64 = 100;
/// Percentage denominator.
const PCT_DENOM: u64 = 100;

/// Resolution by accumulated job scores (`record_score`).
const KIND_SCORING: u8 = 0;
/// Resolution by a single overwriteable performance metric (`record_performance`).
const KIND_PERFORMANCE: u8 = 1;
/// Zero-ROI baseline for the performance metric: `metric = PERF_BASE + roi_bps`
/// (floored at 0). 1_000_000 leaves head-room for the full [-10000, +inf] bps
/// range without underflow at -100% ROI.
const PERF_BASE: u64 = 1_000_000;

/// Held by the competition engine; gates creating competitions and recording.
public struct CompetitionCap has key, store {
    id: UID,
}

/// One recorded job result.
public struct JobResult has store, copy, drop {
    agent_id: address,
    job_id: String,
    score: u64,
}

/// A single competition with its prize pool and recorded results. `totals` and
/// `participants` are maintained incrementally so payout never has to re-tally the
/// (unbounded) `results` log.
public struct Competition has key {
    id: UID,
    /// Resolution mode: `KIND_SCORING` or `KIND_PERFORMANCE`.
    kind: u8,
    prize: Balance<QUADRA>,
    threshold: u64,
    end_time_ms: u64,
    split_pct: vector<u64>,
    results: vector<JobResult>,
    totals: Table<address, u64>,
    participants: vector<address>,
    ended: bool,
}

public struct CompetitionCreated has copy, drop {
    competition_id: ID,
    kind: u8,
    prize: u64,
    threshold: u64,
    end_time_ms: u64,
    winners: u64,
}

public struct AgentJoined has copy, drop {
    competition_id: ID,
    agent_id: address,
}

public struct ScoreRecorded has copy, drop {
    competition_id: ID,
    agent_id: address,
    job_id: String,
    score: u64,
}

public struct PerformanceRecorded has copy, drop {
    competition_id: ID,
    agent_id: address,
    metric: u64,
}

public struct PrizeAwarded has copy, drop {
    competition_id: ID,
    agent_id: address,
    rank: u64,
    amount: u64,
}

/// Mint the cap at publish.
fun init(ctx: &mut TxContext) {
    transfer::transfer(CompetitionCap { id: object::new(ctx) }, ctx.sender());
}

/// Create a competition of `kind` (`KIND_SCORING` or `KIND_PERFORMANCE`) funded
/// with `prize`. `split_pct` must sum to 100; its length is the number of
/// winners. Capability-gated.
public fun create_competition(
    _: &CompetitionCap,
    kind: u8,
    prize: Coin<QUADRA>,
    threshold: u64,
    end_time_ms: u64,
    split_pct: vector<u64>,
    ctx: &mut TxContext,
) {
    assert!(kind == KIND_SCORING || kind == KIND_PERFORMANCE, EWrongKind);
    assert!(valid_split(&split_pct), EBadSplit);
    let competition = Competition {
        id: object::new(ctx),
        kind,
        prize: prize.into_balance(),
        threshold,
        end_time_ms,
        split_pct,
        results: vector[],
        totals: table::new(ctx),
        participants: vector[],
        ended: false,
    };
    event::emit(CompetitionCreated {
        competition_id: object::id(&competition),
        kind,
        prize: competition.prize.value(),
        threshold,
        end_time_ms,
        winners: competition.split_pct.length(),
    });
    transfer::share_object(competition);
}

/// Enrol the calling agent in a competition. Public: any registered agent joins
/// itself. Pre-seeds the agent's ranking value at 0 and adds it to the
/// participant set (so the engine sees a verifiable `AgentJoined` and can
/// dispatch free jobs). Aborts if the competition has ended or the agent already
/// joined.
public fun join_competition(
    competition: &mut Competition,
    registry: &AgentRegistry,
    ctx: &mut TxContext,
) {
    assert!(!competition.ended, EAlreadyEnded);
    let agent_id = ctx.sender();
    agent::assert_registered(registry, agent_id);
    assert!(!competition.totals.contains(agent_id), EAlreadyJoined);
    competition.totals.add(agent_id, 0);
    competition.participants.push_back(agent_id);
    event::emit(AgentJoined { competition_id: object::id(competition), agent_id });
}

/// Record one job score for an agent (SCORING mode only). Capability-gated.
/// Aborts if the agent is not registered, the score is out of range, the
/// competition is not a scoring competition, or it already ended.
public fun record_score(
    _: &CompetitionCap,
    competition: &mut Competition,
    registry: &AgentRegistry,
    agent_id: address,
    job_id: String,
    score: u64,
) {
    assert!(!competition.ended, EAlreadyEnded);
    assert!(competition.kind == KIND_SCORING, EWrongKind);
    assert!(score <= MAX_SCORE, EBadScore);
    agent::assert_registered(registry, agent_id);
    competition.results.push_back(JobResult { agent_id, job_id, score });

    // Maintain the running per-agent total (and the participant set) incrementally.
    if (competition.totals.contains(agent_id)) {
        let total = competition.totals.borrow_mut(agent_id);
        *total = *total + score;
    } else {
        competition.totals.add(agent_id, score);
        competition.participants.push_back(agent_id);
    };

    event::emit(ScoreRecorded {
        competition_id: object::id(competition),
        agent_id,
        job_id,
        score,
    });
}

/// Record an agent's performance metric (PERFORMANCE mode only). Capability-gated.
/// Unlike `record_score` this OVERWRITES the agent's ranking value, so the engine
/// can re-record idempotently from the signed end-of-window ROI. `metric` is the
/// `PERF_BASE + roi_bps` encoding (see module doc); a larger metric ranks higher.
/// Aborts if the agent is not registered, the competition is not a performance
/// competition, or it already ended.
public fun record_performance(
    _: &CompetitionCap,
    competition: &mut Competition,
    registry: &AgentRegistry,
    agent_id: address,
    metric: u64,
) {
    assert!(!competition.ended, EAlreadyEnded);
    assert!(competition.kind == KIND_PERFORMANCE, EWrongKind);
    agent::assert_registered(registry, agent_id);

    // Overwrite (not accumulate); add to the participant set on first sight.
    if (competition.totals.contains(agent_id)) {
        let total = competition.totals.borrow_mut(agent_id);
        *total = metric;
    } else {
        competition.totals.add(agent_id, metric);
        competition.participants.push_back(agent_id);
    };

    event::emit(PerformanceRecorded {
        competition_id: object::id(competition),
        agent_id,
        metric,
    });
}

/// Release prizes after the end time. Public and permissionless: anyone can
/// trigger it once the competition has ended. Agents below `threshold` total
/// score are eliminated; the top agents split the pool by `split_pct`.
public fun release_prizes(competition: &mut Competition, clock: &Clock, ctx: &mut TxContext) {
    assert!(!competition.ended, EAlreadyEnded);
    assert!(clock.timestamp_ms() >= competition.end_time_ms, ENotEnded);
    competition.ended = true;

    // Collect the qualifying agents (total >= threshold) from the maintained
    // totals — no re-tally of the results log.
    let (mut q_agents, mut q_totals) = qualifying(competition);

    let competition_id = object::id(competition);
    let prize_total = competition.prize.value();
    let slots = competition.split_pct.length();

    let mut rank = 0;
    while (rank < slots && !q_agents.is_empty()) {
        // Highest remaining total wins; earliest recorded breaks ties.
        let best = best_index(&q_totals);
        let winner = q_agents.remove(best);
        let _ = q_totals.remove(best);

        let pct = competition.split_pct[rank];
        let amount = (((prize_total as u128) * (pct as u128)) / (PCT_DENOM as u128)) as u64;
        if (amount > 0) {
            transfer::public_transfer(coin::take(&mut competition.prize, amount, ctx), winner);
        };
        event::emit(PrizeAwarded { competition_id, agent_id: winner, rank, amount });
        rank = rank + 1;
    };
}

/// Reclaim leftover prize funds (rounding dust or unfilled winner slots).
/// Capability-gated.
public fun withdraw_remaining(_: &CompetitionCap, competition: &mut Competition, ctx: &mut TxContext) {
    let amount = competition.prize.value();
    transfer::public_transfer(coin::take(&mut competition.prize, amount, ctx), ctx.sender());
}

// --- helpers ---

/// True if `split_pct` is non-empty and sums to exactly 100.
fun valid_split(split_pct: &vector<u64>): bool {
    let n = split_pct.length();
    if (n == 0) return false;
    let mut sum = 0;
    let mut i = 0;
    while (i < n) {
        sum = sum + split_pct[i];
        i = i + 1;
    };
    sum == PCT_DENOM
}

/// Parallel (agents, totals) vectors for agents whose total is >= `threshold`,
/// read straight from the maintained `totals`/`participants` (no results re-tally).
fun qualifying(competition: &Competition): (vector<address>, vector<u64>) {
    let mut agents: vector<address> = vector[];
    let mut totals: vector<u64> = vector[];
    let n = competition.participants.length();
    let mut i = 0;
    while (i < n) {
        let agent = competition.participants[i];
        let total = *competition.totals.borrow(agent);
        if (total >= competition.threshold) {
            agents.push_back(agent);
            totals.push_back(total);
        };
        i = i + 1;
    };
    (agents, totals)
}

/// Index of the highest value (first one wins ties). Requires a non-empty input.
fun best_index(totals: &vector<u64>): u64 {
    let mut best = 0;
    let mut best_val = totals[0];
    let mut i = 1;
    let n = totals.length();
    while (i < n) {
        if (totals[i] > best_val) {
            best_val = totals[i];
            best = i;
        };
        i = i + 1;
    };
    best
}

public fun prize_balance(competition: &Competition): u64 { competition.prize.value() }

public fun kind(competition: &Competition): u8 { competition.kind }

/// The zero-ROI baseline for the performance metric encoding (`metric =
/// PERF_BASE + roi_bps`). The off-chain ROI evaluator and engine must use this
/// exact base; exposed so they can read it on-chain instead of re-hardcoding.
public fun perf_base(): u64 { PERF_BASE }

public fun threshold(competition: &Competition): u64 { competition.threshold }

public fun end_time_ms(competition: &Competition): u64 { competition.end_time_ms }

public fun is_ended(competition: &Competition): bool { competition.ended }

public fun result_count(competition: &Competition): u64 { competition.results.length() }

#[test_only]
public fun init_for_testing(ctx: &mut TxContext) {
    init(ctx);
}
