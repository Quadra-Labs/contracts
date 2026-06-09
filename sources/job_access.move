// Copyright (c), Quadra.
// SPDX-License-Identifier: Apache-2.0

/// Seal access policy for private job results.
///
/// Job results are stored encrypted on Walrus via Seal. The user who paid for a
/// job and the agent that performed it may decrypt the result. The scheduler
/// engine may decrypt every result, since it feeds them to the evaluation
/// engines for scoring. The Seal key servers hand out a decryption key only if
/// the on-chain `seal_approve` here succeeds, so the whole policy lives on chain.
///
/// `intake::pay_for_job` records `{ job_id -> (user, agent) }` here at payment
/// time — the only moment the paying user's address is on chain (the escrow is
/// deleted on release and never stores the user). The record outlives the
/// escrow, so results stay readable by the two parties.
module quadra::job_access;

use std::string::{Self, String};
use sui::event;
use sui::table::{Self, Table};

/// No access record exists for the requested job id.
const ENoRecord: u64 = 0;
/// The requester is neither the job's user nor its agent nor the scheduler.
const ENoAccess: u64 = 1;

/// The two addresses allowed to read one job's result.
public struct Parties has store, copy, drop {
    user: address,
    agent: address,
}

/// Admin capability to point the policy at the scheduler engine wallet.
public struct JobAccessCap has key, store {
    id: UID,
}

/// Shared registry of `{ job_id -> Parties }`, written at payment time, plus the
/// scheduler engine that may read any result.
public struct JobAccessRegistry has key {
    id: UID,
    access: Table<String, Parties>,
    /// The scheduler engine wallet; allowed to decrypt every job result so the
    /// evaluation engines can score it.
    scheduler: address,
}

/// Emitted when access is recorded for a job.
public struct AccessRecorded has copy, drop {
    job_id: String,
    user: address,
    agent: address,
}

/// Emitted when the scheduler address is set.
public struct SchedulerSet has copy, drop {
    scheduler: address,
}

/// Mint the cap and share the registry once at publish. The scheduler defaults
/// to the deployer; point it at the real scheduler wallet via `set_scheduler`.
fun init(ctx: &mut TxContext) {
    transfer::transfer(JobAccessCap { id: object::new(ctx) }, ctx.sender());
    transfer::share_object(JobAccessRegistry {
        id: object::new(ctx),
        access: table::new(ctx),
        scheduler: ctx.sender(),
    });
}

/// Record who may read a job's result. Called by `intake::pay_for_job`.
/// `String` is copyable, so the caller keeps ownership of `job_id`. Overwrites
/// any existing record for the same job id.
public fun record(reg: &mut JobAccessRegistry, job_id: String, user: address, agent: address) {
    if (reg.access.contains(job_id)) {
        let parties = reg.access.borrow_mut(job_id);
        parties.user = user;
        parties.agent = agent;
    } else {
        reg.access.add(job_id, Parties { user, agent });
    };
    event::emit(AccessRecorded { job_id, user, agent });
}

/// Point the policy at the scheduler engine wallet. Capability-gated.
public fun set_scheduler(_: &JobAccessCap, reg: &mut JobAccessRegistry, scheduler: address) {
    reg.scheduler = scheduler;
    event::emit(SchedulerSet { scheduler });
}

/// Core policy check, shared by `seal_approve` and tests. The scheduler may read
/// any result; otherwise the requester must be the job's recorded user or agent.
public fun assert_can_read(reg: &JobAccessRegistry, id: vector<u8>, requester: address) {
    // The scheduler engine decrypts every result to feed the evaluation engines.
    if (requester == reg.scheduler) return;
    let job_id = string::utf8(id);
    assert!(reg.access.contains(job_id), ENoRecord);
    let parties = reg.access.borrow(job_id);
    assert!(requester == parties.user || requester == parties.agent, ENoAccess);
}

/// Seal entry point. The key servers dry-run this transaction; `ctx.sender()`
/// is the address requesting the decryption key. `id` is the Seal identity
/// bytes — the UTF-8 job id used when the result was encrypted.
entry fun seal_approve(id: vector<u8>, reg: &JobAccessRegistry, ctx: &TxContext) {
    assert_can_read(reg, id, ctx.sender());
}

public fun scheduler(reg: &JobAccessRegistry): address { reg.scheduler }

#[test_only]
public fun init_for_testing(ctx: &mut TxContext) {
    init(ctx);
}
