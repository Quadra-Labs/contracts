// Copyright (c), Quadra.
// SPDX-License-Identifier: Apache-2.0

/// Competition engine.
///
/// Agents run a fixed set of predefined jobs; the evaluation engine scores each
/// in [0, 100]; the competition engine (holder of `CompetitionCap`) records
/// those scores on-chain with `record_score`. Each agent accumulates a total
/// score across the jobs.
///
/// When the competition reaches its end time, anyone can call `release_prizes`
/// (public + time-gated). Agents whose total score is below `threshold` are
/// eliminated; the remaining top agents split the prize pool according to
/// `split_pct` (e.g. [50, 30, 20] => top 3 take 50% / 30% / 20%).
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

/// Max valid job score.
const MAX_SCORE: u64 = 100;
/// Percentage denominator.
const PCT_DENOM: u64 = 100;

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
    prize: u64,
    threshold: u64,
    end_time_ms: u64,
    winners: u64,
}

public struct ScoreRecorded has copy, drop {
    competition_id: ID,
    agent_id: address,
    job_id: String,
    score: u64,
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

/// Create a competition funded with `prize`. `split_pct` must sum to 100; its
/// length is the number of winners. Capability-gated.
public fun create_competition(
    _: &CompetitionCap,
    prize: Coin<QUADRA>,
    threshold: u64,
    end_time_ms: u64,
    split_pct: vector<u64>,
    ctx: &mut TxContext,
) {
    assert!(valid_split(&split_pct), EBadSplit);
    let competition = Competition {
        id: object::new(ctx),
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
        prize: competition.prize.value(),
        threshold,
        end_time_ms,
        winners: competition.split_pct.length(),
    });
    transfer::share_object(competition);
}

/// Record one job score for an agent. Capability-gated. Aborts if the agent is
/// not registered, the score is out of range, or the competition already ended.
public fun record_score(
    _: &CompetitionCap,
    competition: &mut Competition,
    registry: &AgentRegistry,
    agent_id: address,
    job_id: String,
    score: u64,
) {
    assert!(!competition.ended, EAlreadyEnded);
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

public fun threshold(competition: &Competition): u64 { competition.threshold }

public fun end_time_ms(competition: &Competition): u64 { competition.end_time_ms }

public fun is_ended(competition: &Competition): bool { competition.ended }

public fun result_count(competition: &Competition): u64 { competition.results.length() }

#[test_only]
public fun init_for_testing(ctx: &mut TxContext) {
    init(ctx);
}
