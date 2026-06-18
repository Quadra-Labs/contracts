// Copyright (c), Quadra.
// SPDX-License-Identifier: Apache-2.0

/// Happy-path and key-assertion tests for the Quadra modules.
#[test_only]
module quadra::quadra_tests;

use sui::test_scenario::{Self as ts};
use sui::coin::{Self, Coin};
use sui::sui::SUI;
use sui::clock;
use std::string::{Self, String};

use quadra::quadra::{Self, QUADRA};
use quadra::agent::{Self, AgentRegistry};
use quadra::intake::{Self, IntakeCap, IntakeConfig, Escrow};
use quadra::job_access::{Self, JobAccessRegistry, JobAccessCap};
use quadra::competition::{Self, CompetitionCap, Competition};
use quadra::staking::{Self, StakingAdminCap, StakingPool, Stake};
use quadra::amm::{Self, Pool};

const ADMIN: address = @0xAD;
const AGENT: address = @0xA1;
const AGENT2: address = @0xA2;
const USER: address = @0xC1;
const SCHEDULER: address = @0x5C;
const COMPETITION: address = @0xC0;

fun str(bytes: vector<u8>): String { string::utf8(bytes) }

fun register(scenario: &mut ts::Scenario, who: address) {
    register_kind(scenario, who, false);
}

fun register_kind(scenario: &mut ts::Scenario, who: address, scoreless: bool) {
    scenario.next_tx(who);
    let mut reg = scenario.take_shared<AgentRegistry>();
    agent::register_agent(&mut reg, who, str(b"name"), str(b"desc"), str(b"finance"), scoreless, scenario.ctx());
    ts::return_shared(reg);
}

#[test]
fun test_token_mints_full_supply() {
    let mut sc = ts::begin(ADMIN);
    quadra::init_for_testing(sc.ctx());
    sc.next_tx(ADMIN);
    let coins = sc.take_from_sender<Coin<QUADRA>>();
    assert!(coins.value() == quadra::total_supply(), 0);
    sc.return_to_sender(coins);
    sc.end();
}

#[test]
fun test_register_and_lookup() {
    let mut sc = ts::begin(ADMIN);
    agent::init_for_testing(sc.ctx());
    register(&mut sc, AGENT);
    sc.next_tx(AGENT);
    let reg = sc.take_shared<AgentRegistry>();
    assert!(agent::is_registered(&reg, AGENT), 0);
    assert!(!agent::is_registered(&reg, AGENT2), 1);
    ts::return_shared(reg);
    sc.end();
}

#[test]
#[expected_failure]
fun test_double_register_fails() {
    let mut sc = ts::begin(ADMIN);
    agent::init_for_testing(sc.ctx());
    register(&mut sc, AGENT);
    register(&mut sc, AGENT); // aborts: already registered
    sc.end();
}

#[test]
fun test_intake_pay_and_release() {
    let mut sc = ts::begin(ADMIN);
    agent::init_for_testing(sc.ctx());
    intake::init_for_testing(sc.ctx());
    job_access::init_for_testing(sc.ctx());
    register(&mut sc, AGENT);

    // User pays 1000 for a job to the registered agent.
    sc.next_tx(USER);
    {
        let reg = sc.take_shared<AgentRegistry>();
        let mut access = sc.take_shared<JobAccessRegistry>();
        let clk = clock::create_for_testing(sc.ctx());
        let pay = coin::mint_for_testing<QUADRA>(1000, sc.ctx());
        intake::pay_for_job(&reg, &mut access, str(b"sess-1"), str(b"job-1"), AGENT, pay, &clk, sc.ctx());
        clk.destroy_for_testing();
        ts::return_shared(access);
        ts::return_shared(reg);
    };

    // Intake engine (holds the cap) releases; default fee is 10%.
    sc.next_tx(ADMIN);
    {
        let cap = sc.take_from_sender<IntakeCap>();
        let config = sc.take_shared<IntakeConfig>();
        let escrow = sc.take_shared<Escrow>();
        intake::release_payment(&cap, &config, escrow, sc.ctx());
        ts::return_shared(config);
        sc.return_to_sender(cap);
    };

    // Agent received 1000 - 10% = 900.
    sc.next_tx(AGENT);
    {
        let received = sc.take_from_sender<Coin<QUADRA>>();
        assert!(received.value() == 900, 0);
        received.burn_for_testing();
    };
    sc.end();
}

#[test]
fun test_refund_not_delivered() {
    let mut sc = ts::begin(ADMIN);
    agent::init_for_testing(sc.ctx());
    intake::init_for_testing(sc.ctx());
    job_access::init_for_testing(sc.ctx());
    register(&mut sc, AGENT);

    // User pays 1000 at t = 0.
    sc.next_tx(USER);
    {
        let reg = sc.take_shared<AgentRegistry>();
        let mut access = sc.take_shared<JobAccessRegistry>();
        let clk = clock::create_for_testing(sc.ctx());
        let pay = coin::mint_for_testing<QUADRA>(1000, sc.ctx());
        intake::pay_for_job(&reg, &mut access, str(b"sess-1"), str(b"job-1"), AGENT, pay, &clk, sc.ctx());
        clk.destroy_for_testing();
        ts::return_shared(access);
        ts::return_shared(reg);
    };

    // Intake engine refunds after the 30-minute wait (agent scored 0).
    sc.next_tx(ADMIN);
    {
        let cap = sc.take_from_sender<IntakeCap>();
        let escrow = sc.take_shared<Escrow>();
        let mut clk = clock::create_for_testing(sc.ctx());
        clk.set_for_testing(30 * 60 * 1000);
        intake::refund_not_delivered(&cap, escrow, &clk, sc.ctx());
        clk.destroy_for_testing();
        sc.return_to_sender(cap);
    };

    // User got the full 1000 back.
    sc.next_tx(USER);
    {
        let back = sc.take_from_sender<Coin<QUADRA>>();
        assert!(back.value() == 1000, 0);
        back.burn_for_testing();
    };
    sc.end();
}

#[test]
#[expected_failure(abort_code = intake::ETooEarly)]
fun test_refund_too_early_fails() {
    let mut sc = ts::begin(ADMIN);
    agent::init_for_testing(sc.ctx());
    intake::init_for_testing(sc.ctx());
    job_access::init_for_testing(sc.ctx());
    register(&mut sc, AGENT);

    sc.next_tx(USER);
    {
        let reg = sc.take_shared<AgentRegistry>();
        let mut access = sc.take_shared<JobAccessRegistry>();
        let clk = clock::create_for_testing(sc.ctx());
        let pay = coin::mint_for_testing<QUADRA>(1000, sc.ctx());
        intake::pay_for_job(&reg, &mut access, str(b"sess-1"), str(b"job-1"), AGENT, pay, &clk, sc.ctx());
        clk.destroy_for_testing();
        ts::return_shared(access);
        ts::return_shared(reg);
    };

    // Only 1 minute later -> too early, aborts.
    sc.next_tx(ADMIN);
    {
        let cap = sc.take_from_sender<IntakeCap>();
        let escrow = sc.take_shared<Escrow>();
        let mut clk = clock::create_for_testing(sc.ctx());
        clk.set_for_testing(60 * 1000);
        intake::refund_not_delivered(&cap, escrow, &clk, sc.ctx());
        clk.destroy_for_testing();
        sc.return_to_sender(cap);
    };
    sc.end();
}

#[test]
#[expected_failure]
fun test_pay_unregistered_fails() {
    let mut sc = ts::begin(ADMIN);
    agent::init_for_testing(sc.ctx());
    job_access::init_for_testing(sc.ctx());
    sc.next_tx(USER);
    let reg = sc.take_shared<AgentRegistry>();
    let mut access = sc.take_shared<JobAccessRegistry>();
    let clk = clock::create_for_testing(sc.ctx());
    let pay = coin::mint_for_testing<QUADRA>(1000, sc.ctx());
    // AGENT is not registered -> aborts.
    intake::pay_for_job(&reg, &mut access, str(b"s"), str(b"j"), AGENT, pay, &clk, sc.ctx());
    clk.destroy_for_testing();
    ts::return_shared(access);
    ts::return_shared(reg);
    sc.end();
}

/// After payment, both the paying user and the agent pass the Seal policy, and a
/// third party is rejected.
#[test]
fun test_seal_access_user_and_agent() {
    let mut sc = ts::begin(ADMIN);
    agent::init_for_testing(sc.ctx());
    intake::init_for_testing(sc.ctx());
    job_access::init_for_testing(sc.ctx());
    register(&mut sc, AGENT);

    sc.next_tx(USER);
    {
        let reg = sc.take_shared<AgentRegistry>();
        let mut access = sc.take_shared<JobAccessRegistry>();
        let clk = clock::create_for_testing(sc.ctx());
        let pay = coin::mint_for_testing<QUADRA>(1000, sc.ctx());
        intake::pay_for_job(&reg, &mut access, str(b"sess-1"), str(b"job-1"), AGENT, pay, &clk, sc.ctx());
        clk.destroy_for_testing();
        ts::return_shared(access);
        ts::return_shared(reg);
    };

    // Both parties are allowed to read job-1.
    sc.next_tx(USER);
    {
        let access = sc.take_shared<JobAccessRegistry>();
        job_access::assert_can_read(&access, b"job-1", USER);
        job_access::assert_can_read(&access, b"job-1", AGENT);
        ts::return_shared(access);
    };
    sc.end();
}

#[test]
#[expected_failure(abort_code = job_access::ENoAccess)]
fun test_seal_access_third_party_denied() {
    let mut sc = ts::begin(ADMIN);
    agent::init_for_testing(sc.ctx());
    intake::init_for_testing(sc.ctx());
    job_access::init_for_testing(sc.ctx());
    register(&mut sc, AGENT);

    sc.next_tx(USER);
    {
        let reg = sc.take_shared<AgentRegistry>();
        let mut access = sc.take_shared<JobAccessRegistry>();
        let clk = clock::create_for_testing(sc.ctx());
        let pay = coin::mint_for_testing<QUADRA>(1000, sc.ctx());
        intake::pay_for_job(&reg, &mut access, str(b"sess-1"), str(b"job-1"), AGENT, pay, &clk, sc.ctx());
        clk.destroy_for_testing();
        ts::return_shared(access);
        ts::return_shared(reg);
    };

    // A stranger is rejected.
    sc.next_tx(AGENT2);
    {
        let access = sc.take_shared<JobAccessRegistry>();
        job_access::assert_can_read(&access, b"job-1", AGENT2); // aborts: ENoAccess
        ts::return_shared(access);
    };
    sc.end();
}

/// The scheduler engine may decrypt any result (recorded or not) so it can feed
/// the evaluation engines; a stranger still cannot.
#[test]
fun test_seal_access_scheduler() {
    let mut sc = ts::begin(ADMIN);
    agent::init_for_testing(sc.ctx());
    intake::init_for_testing(sc.ctx());
    job_access::init_for_testing(sc.ctx());
    register(&mut sc, AGENT);

    // Admin points the policy at the scheduler engine wallet.
    sc.next_tx(ADMIN);
    {
        let cap = sc.take_from_sender<JobAccessCap>();
        let mut access = sc.take_shared<JobAccessRegistry>();
        job_access::set_scheduler(&cap, &mut access, SCHEDULER);
        ts::return_shared(access);
        sc.return_to_sender(cap);
    };

    sc.next_tx(USER);
    {
        let reg = sc.take_shared<AgentRegistry>();
        let mut access = sc.take_shared<JobAccessRegistry>();
        let clk = clock::create_for_testing(sc.ctx());
        let pay = coin::mint_for_testing<QUADRA>(1000, sc.ctx());
        intake::pay_for_job(&reg, &mut access, str(b"sess-1"), str(b"job-1"), AGENT, pay, &clk, sc.ctx());
        clk.destroy_for_testing();
        ts::return_shared(access);
        ts::return_shared(reg);
    };

    sc.next_tx(SCHEDULER);
    {
        let access = sc.take_shared<JobAccessRegistry>();
        job_access::assert_can_read(&access, b"job-1", SCHEDULER);          // recorded job
        job_access::assert_can_read(&access, b"never-recorded", SCHEDULER); // any job
        ts::return_shared(access);
    };
    sc.end();
}

/// A job's decryptors are bound once: reusing a job id (the ACL-hijack attempt)
/// aborts, so an attacker can't re-record someone else's job to themselves.
#[test]
#[expected_failure(abort_code = job_access::EAlreadyBound)]
fun test_record_rebind_fails() {
    let mut sc = ts::begin(ADMIN);
    agent::init_for_testing(sc.ctx());
    intake::init_for_testing(sc.ctx());
    job_access::init_for_testing(sc.ctx());
    register(&mut sc, AGENT);
    register(&mut sc, AGENT2);

    // First payment binds job-1 to (USER, AGENT).
    sc.next_tx(USER);
    {
        let reg = sc.take_shared<AgentRegistry>();
        let mut access = sc.take_shared<JobAccessRegistry>();
        let clk = clock::create_for_testing(sc.ctx());
        let pay = coin::mint_for_testing<QUADRA>(1000, sc.ctx());
        intake::pay_for_job(&reg, &mut access, str(b"sess-1"), str(b"job-1"), AGENT, pay, &clk, sc.ctx());
        clk.destroy_for_testing();
        ts::return_shared(access);
        ts::return_shared(reg);
    };

    // A second payment reusing job-1 must abort (one-time binding).
    sc.next_tx(AGENT2);
    {
        let reg = sc.take_shared<AgentRegistry>();
        let mut access = sc.take_shared<JobAccessRegistry>();
        let clk = clock::create_for_testing(sc.ctx());
        let pay = coin::mint_for_testing<QUADRA>(1000, sc.ctx());
        intake::pay_for_job(&reg, &mut access, str(b"sess-2"), str(b"job-1"), AGENT2, pay, &clk, sc.ctx());
        clk.destroy_for_testing();
        ts::return_shared(access);
        ts::return_shared(reg);
    };
    sc.end();
}

#[test]
fun test_competition_split_and_threshold() {
    let mut sc = ts::begin(ADMIN);
    agent::init_for_testing(sc.ctx());
    competition::init_for_testing(sc.ctx());
    register(&mut sc, AGENT);
    register(&mut sc, AGENT2);

    // Prize 1000, threshold 50, split [60, 40].
    sc.next_tx(ADMIN);
    {
        let cap = sc.take_from_sender<CompetitionCap>();
        let prize = coin::mint_for_testing<QUADRA>(1000, sc.ctx());
        // kind 0 = KIND_SCORING.
        competition::create_competition(&cap, 0, prize, 50, 100, vector[60, 40], sc.ctx());
        sc.return_to_sender(cap);
    };

    // AGENT scores 80 (qualifies); AGENT2 scores 40 (below threshold -> eliminated).
    sc.next_tx(ADMIN);
    {
        let cap = sc.take_from_sender<CompetitionCap>();
        let mut comp = sc.take_shared<Competition>();
        let reg = sc.take_shared<AgentRegistry>();
        competition::record_score(&cap, &mut comp, &reg, AGENT, str(b"j1"), 80);
        competition::record_score(&cap, &mut comp, &reg, AGENT2, str(b"j1"), 40);
        ts::return_shared(reg);
        ts::return_shared(comp);
        sc.return_to_sender(cap);
    };

    // Release after the end time.
    sc.next_tx(ADMIN);
    {
        let mut comp = sc.take_shared<Competition>();
        let mut clk = clock::create_for_testing(sc.ctx());
        clk.set_for_testing(200);
        competition::release_prizes(&mut comp, &clk, sc.ctx());
        clk.destroy_for_testing();
        ts::return_shared(comp);
    };

    // Only AGENT qualifies; as rank 0 it takes 60% of 1000 = 600.
    sc.next_tx(AGENT);
    {
        let won = sc.take_from_sender<Coin<QUADRA>>();
        assert!(won.value() == 600, 0);
        won.burn_for_testing();
    };
    sc.end();
}

#[test]
#[expected_failure]
fun test_release_before_end_fails() {
    let mut sc = ts::begin(ADMIN);
    competition::init_for_testing(sc.ctx());
    sc.next_tx(ADMIN);
    {
        let cap = sc.take_from_sender<CompetitionCap>();
        let prize = coin::mint_for_testing<QUADRA>(1000, sc.ctx());
        // kind 0 = KIND_SCORING.
        competition::create_competition(&cap, 0, prize, 50, 1_000_000, vector[100], sc.ctx());
        sc.return_to_sender(cap);
    };
    sc.next_tx(ADMIN);
    {
        let mut comp = sc.take_shared<Competition>();
        let clk = clock::create_for_testing(sc.ctx()); // timestamp 0 < end 1_000_000
        competition::release_prizes(&mut comp, &clk, sc.ctx()); // aborts: not ended
        clk.destroy_for_testing();
        ts::return_shared(comp);
    };
    sc.end();
}

/// Joining pre-seeds the agent at 0 and adds it to the participant set; an enrolled
/// but idle agent stays below a positive threshold and wins nothing, while a scored
/// joiner is paid. Proves `join_competition` doesn't corrupt the payout.
#[test]
fun test_join_pre_seeds_and_idle_eliminated() {
    let mut sc = ts::begin(ADMIN);
    agent::init_for_testing(sc.ctx());
    competition::init_for_testing(sc.ctx());
    register(&mut sc, AGENT);
    register(&mut sc, AGENT2);

    // Scoring comp, threshold 1 (so a 0 total is eliminated), winner takes 100%.
    sc.next_tx(ADMIN);
    {
        let cap = sc.take_from_sender<CompetitionCap>();
        let prize = coin::mint_for_testing<QUADRA>(1000, sc.ctx());
        competition::create_competition(&cap, 0, prize, 1, 100, vector[100], sc.ctx());
        sc.return_to_sender(cap);
    };

    // Both agents enrol themselves on-chain.
    sc.next_tx(AGENT);
    {
        let mut comp = sc.take_shared<Competition>();
        let reg = sc.take_shared<AgentRegistry>();
        competition::join_competition(&mut comp, &reg, sc.ctx());
        ts::return_shared(reg);
        ts::return_shared(comp);
    };
    sc.next_tx(AGENT2);
    {
        let mut comp = sc.take_shared<Competition>();
        let reg = sc.take_shared<AgentRegistry>();
        competition::join_competition(&mut comp, &reg, sc.ctx());
        ts::return_shared(reg);
        ts::return_shared(comp);
    };

    // Only AGENT2 gets a score; AGENT stays idle at its pre-seeded 0.
    sc.next_tx(ADMIN);
    {
        let cap = sc.take_from_sender<CompetitionCap>();
        let mut comp = sc.take_shared<Competition>();
        let reg = sc.take_shared<AgentRegistry>();
        competition::record_score(&cap, &mut comp, &reg, AGENT2, str(b"j1"), 50);
        ts::return_shared(reg);
        ts::return_shared(comp);
        sc.return_to_sender(cap);
    };

    sc.next_tx(ADMIN);
    {
        let mut comp = sc.take_shared<Competition>();
        let mut clk = clock::create_for_testing(sc.ctx());
        clk.set_for_testing(200);
        competition::release_prizes(&mut comp, &clk, sc.ctx());
        clk.destroy_for_testing();
        ts::return_shared(comp);
    };

    // AGENT2 (50 >= 1) takes the whole 1000; AGENT (0 < 1) is eliminated.
    sc.next_tx(AGENT2);
    {
        let won = sc.take_from_sender<Coin<QUADRA>>();
        assert!(won.value() == 1000, 0);
        won.burn_for_testing();
    };
    sc.end();
}

/// Enrolment is one-time per agent.
#[test]
#[expected_failure(abort_code = competition::EAlreadyJoined)]
fun test_double_join_fails() {
    let mut sc = ts::begin(ADMIN);
    agent::init_for_testing(sc.ctx());
    competition::init_for_testing(sc.ctx());
    register(&mut sc, AGENT);

    sc.next_tx(ADMIN);
    {
        let cap = sc.take_from_sender<CompetitionCap>();
        let prize = coin::mint_for_testing<QUADRA>(1000, sc.ctx());
        competition::create_competition(&cap, 0, prize, 1, 100, vector[100], sc.ctx());
        sc.return_to_sender(cap);
    };

    sc.next_tx(AGENT);
    {
        let mut comp = sc.take_shared<Competition>();
        let reg = sc.take_shared<AgentRegistry>();
        competition::join_competition(&mut comp, &reg, sc.ctx());
        competition::join_competition(&mut comp, &reg, sc.ctx()); // aborts: already joined
        ts::return_shared(reg);
        ts::return_shared(comp);
    };
    sc.end();
}

/// A scoreless agent cannot join a competition.
#[test]
#[expected_failure(abort_code = competition::EScorelessAgent)]
fun test_scoreless_cannot_join() {
    let mut sc = ts::begin(ADMIN);
    agent::init_for_testing(sc.ctx());
    competition::init_for_testing(sc.ctx());
    register_kind(&mut sc, AGENT, true); // scoreless

    sc.next_tx(ADMIN);
    {
        let cap = sc.take_from_sender<CompetitionCap>();
        let prize = coin::mint_for_testing<QUADRA>(1000, sc.ctx());
        competition::create_competition(&cap, 0, prize, 1, 100, vector[100], sc.ctx());
        sc.return_to_sender(cap);
    };

    sc.next_tx(AGENT);
    {
        let mut comp = sc.take_shared<Competition>();
        let reg = sc.take_shared<AgentRegistry>();
        competition::join_competition(&mut comp, &reg, sc.ctx()); // aborts: scoreless
        ts::return_shared(reg);
        ts::return_shared(comp);
    };
    sc.end();
}

/// `record_score` is rejected on a PERFORMANCE competition.
#[test]
#[expected_failure(abort_code = competition::EWrongKind)]
fun test_record_score_wrong_kind_fails() {
    let mut sc = ts::begin(ADMIN);
    agent::init_for_testing(sc.ctx());
    competition::init_for_testing(sc.ctx());
    register(&mut sc, AGENT);

    // kind 1 = KIND_PERFORMANCE.
    sc.next_tx(ADMIN);
    {
        let cap = sc.take_from_sender<CompetitionCap>();
        let prize = coin::mint_for_testing<QUADRA>(1000, sc.ctx());
        competition::create_competition(&cap, 1, prize, 1, 100, vector[100], sc.ctx());
        sc.return_to_sender(cap);
    };

    sc.next_tx(ADMIN);
    {
        let cap = sc.take_from_sender<CompetitionCap>();
        let mut comp = sc.take_shared<Competition>();
        let reg = sc.take_shared<AgentRegistry>();
        competition::record_score(&cap, &mut comp, &reg, AGENT, str(b"j1"), 50); // aborts: wrong kind
        ts::return_shared(reg);
        ts::return_shared(comp);
        sc.return_to_sender(cap);
    };
    sc.end();
}

/// `record_performance` is rejected on a SCORING competition.
#[test]
#[expected_failure(abort_code = competition::EWrongKind)]
fun test_record_performance_wrong_kind_fails() {
    let mut sc = ts::begin(ADMIN);
    agent::init_for_testing(sc.ctx());
    competition::init_for_testing(sc.ctx());
    register(&mut sc, AGENT);

    // kind 0 = KIND_SCORING.
    sc.next_tx(ADMIN);
    {
        let cap = sc.take_from_sender<CompetitionCap>();
        let prize = coin::mint_for_testing<QUADRA>(1000, sc.ctx());
        competition::create_competition(&cap, 0, prize, 1, 100, vector[100], sc.ctx());
        sc.return_to_sender(cap);
    };

    sc.next_tx(ADMIN);
    {
        let cap = sc.take_from_sender<CompetitionCap>();
        let mut comp = sc.take_shared<Competition>();
        let reg = sc.take_shared<AgentRegistry>();
        competition::record_performance(&cap, &mut comp, &reg, AGENT, 1_005_000); // aborts: wrong kind
        ts::return_shared(reg);
        ts::return_shared(comp);
        sc.return_to_sender(cap);
    };
    sc.end();
}

/// PERFORMANCE mode: `record_performance` OVERWRITES (does not accumulate). AGENT is
/// recorded high then overwritten low, so AGENT2 (recorded once, higher final metric)
/// wins. If the metric had accumulated, AGENT would wrongly win.
#[test]
fun test_performance_overwrite_and_pays() {
    let mut sc = ts::begin(ADMIN);
    agent::init_for_testing(sc.ctx());
    competition::init_for_testing(sc.ctx());
    register(&mut sc, AGENT);
    register(&mut sc, AGENT2);

    // kind 1 = KIND_PERFORMANCE; threshold = PERF_BASE (1_000_000) = require >= 0% ROI.
    sc.next_tx(ADMIN);
    {
        let cap = sc.take_from_sender<CompetitionCap>();
        let prize = coin::mint_for_testing<QUADRA>(1000, sc.ctx());
        competition::create_competition(&cap, 1, prize, 1_000_000, 100, vector[100], sc.ctx());
        sc.return_to_sender(cap);
    };

    sc.next_tx(ADMIN);
    {
        let cap = sc.take_from_sender<CompetitionCap>();
        let mut comp = sc.take_shared<Competition>();
        let reg = sc.take_shared<AgentRegistry>();
        competition::record_performance(&cap, &mut comp, &reg, AGENT, 1_009_000);  // +9% (first)
        competition::record_performance(&cap, &mut comp, &reg, AGENT2, 1_005_000); // +5%
        competition::record_performance(&cap, &mut comp, &reg, AGENT, 1_001_000);  // overwrite -> +0.1%
        ts::return_shared(reg);
        ts::return_shared(comp);
        sc.return_to_sender(cap);
    };

    sc.next_tx(ADMIN);
    {
        let mut comp = sc.take_shared<Competition>();
        let mut clk = clock::create_for_testing(sc.ctx());
        clk.set_for_testing(200);
        competition::release_prizes(&mut comp, &clk, sc.ctx());
        clk.destroy_for_testing();
        ts::return_shared(comp);
    };

    // AGENT2 (1_005_000) now outranks AGENT (overwritten to 1_001_000) and takes 1000.
    sc.next_tx(AGENT2);
    {
        let won = sc.take_from_sender<Coin<QUADRA>>();
        assert!(won.value() == 1000, 0);
        won.burn_for_testing();
    };
    sc.end();
}

/// The competition engine wallet may decrypt any competition result (which is never
/// recorded in `access`, since competition jobs are free), just like the scheduler.
#[test]
fun test_seal_access_competition_engine() {
    let mut sc = ts::begin(ADMIN);
    agent::init_for_testing(sc.ctx());
    job_access::init_for_testing(sc.ctx());

    sc.next_tx(ADMIN);
    {
        let cap = sc.take_from_sender<JobAccessCap>();
        let mut access = sc.take_shared<JobAccessRegistry>();
        job_access::set_competition(&cap, &mut access, COMPETITION);
        ts::return_shared(access);
        sc.return_to_sender(cap);
    };

    sc.next_tx(COMPETITION);
    {
        let access = sc.take_shared<JobAccessRegistry>();
        // No access record exists for this id, but the competition engine reads any result.
        job_access::assert_can_read(&access, b"comp-job-1", COMPETITION);
        ts::return_shared(access);
    };
    sc.end();
}

#[test]
fun test_staking_principal_plus_reward() {
    let mut sc = ts::begin(ADMIN);
    staking::init_for_testing(sc.ctx());

    // Admin funds the reward reserve and emits 100 per epoch.
    sc.next_tx(ADMIN);
    {
        let cap = sc.take_from_sender<StakingAdminCap>();
        let mut pool = sc.take_shared<StakingPool>();
        staking::fund_rewards(&cap, &mut pool, coin::mint_for_testing<QUADRA>(1_000_000, sc.ctx()));
        staking::set_emission(&cap, &mut pool, 100, sc.ctx());
        ts::return_shared(pool);
        sc.return_to_sender(cap);
    };

    // User stakes 1000 (the only staker).
    sc.next_tx(USER);
    {
        let mut pool = sc.take_shared<StakingPool>();
        staking::stake_and_keep(&mut pool, coin::mint_for_testing<QUADRA>(1000, sc.ctx()), sc.ctx());
        ts::return_shared(pool);
    };

    // Advance one epoch, then unstake: sole staker takes the full 100 emission.
    sc.next_epoch(USER);
    sc.next_tx(USER);
    {
        let mut pool = sc.take_shared<StakingPool>();
        let stake = sc.take_from_sender<Stake>();
        let out = staking::unstake(&mut pool, stake, sc.ctx());
        assert!(out.value() == 1100, 0);
        out.burn_for_testing();
        ts::return_shared(pool);
    };
    sc.end();
}

#[test]
fun test_staking_pro_rata_split() {
    let mut sc = ts::begin(ADMIN);
    staking::init_for_testing(sc.ctx());

    // Emit 300 per epoch.
    sc.next_tx(ADMIN);
    {
        let cap = sc.take_from_sender<StakingAdminCap>();
        let mut pool = sc.take_shared<StakingPool>();
        staking::fund_rewards(&cap, &mut pool, coin::mint_for_testing<QUADRA>(1_000_000, sc.ctx()));
        staking::set_emission(&cap, &mut pool, 300, sc.ctx());
        ts::return_shared(pool);
        sc.return_to_sender(cap);
    };

    // AGENT stakes 1000, AGENT2 stakes 2000 (same epoch) -> shares 1/3 and 2/3.
    sc.next_tx(AGENT);
    {
        let mut pool = sc.take_shared<StakingPool>();
        staking::stake_and_keep(&mut pool, coin::mint_for_testing<QUADRA>(1000, sc.ctx()), sc.ctx());
        ts::return_shared(pool);
    };
    sc.next_tx(AGENT2);
    {
        let mut pool = sc.take_shared<StakingPool>();
        staking::stake_and_keep(&mut pool, coin::mint_for_testing<QUADRA>(2000, sc.ctx()), sc.ctx());
        ts::return_shared(pool);
    };

    sc.next_epoch(ADMIN);

    // AGENT gets 1/3 of 300 = 100; AGENT2 gets 2/3 = 200.
    sc.next_tx(AGENT);
    {
        let mut pool = sc.take_shared<StakingPool>();
        let stake = sc.take_from_sender<Stake>();
        let out = staking::unstake(&mut pool, stake, sc.ctx());
        assert!(out.value() == 1100, 0);
        out.burn_for_testing();
        ts::return_shared(pool);
    };
    sc.next_tx(AGENT2);
    {
        let mut pool = sc.take_shared<StakingPool>();
        let stake = sc.take_from_sender<Stake>();
        let out = staking::unstake(&mut pool, stake, sc.ctx());
        assert!(out.value() == 2200, 1);
        out.burn_for_testing();
        ts::return_shared(pool);
    };
    sc.end();
}

#[test]
fun test_amm_add_and_swap() {
    let mut sc = ts::begin(ADMIN);
    amm::init_for_testing(sc.ctx());

    // Add 10000 / 10000 -> first LP = sqrt(10000*10000) = 10000.
    sc.next_tx(ADMIN);
    {
        let mut pool = sc.take_shared<Pool>();
        let q = coin::mint_for_testing<QUADRA>(10000, sc.ctx());
        let s = coin::mint_for_testing<SUI>(10000, sc.ctx());
        let lp = amm::add_liquidity(&mut pool, q, s, sc.ctx());
        assert!(lp.value() == 10000, 0);
        lp.burn_for_testing();
        ts::return_shared(pool);
    };

    // Swap 1000 QUADRA -> SUI. in_after_fee = 997; out = 997*10000/10997 = 906.
    sc.next_tx(ADMIN);
    {
        let mut pool = sc.take_shared<Pool>();
        let out = amm::swap_quadra_for_sui(&mut pool, coin::mint_for_testing<QUADRA>(1000, sc.ctx()), 0, sc.ctx());
        assert!(out.value() == 906, 1);
        out.burn_for_testing();
        ts::return_shared(pool);
    };
    sc.end();
}
