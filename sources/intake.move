// Copyright (c), Quadra.
// SPDX-License-Identifier: Apache-2.0

/// Intake engine: escrows user payments for jobs and releases them to agents.
///
/// Flow:
/// 1. The intake engine hands the user a session `{ session_id, job_id,
///    agent_wallet, cost }`.
/// 2. The user calls `pay_for_job` with those fields and locks `cost` $QUADRA in
///    a shared `Escrow`. The contract emits `JobPaid`, which the intake engine
///    watches for on-chain.
/// 3. When the job is done, the intake engine (holder of `IntakeCap`) calls
///    `release_payment`, paying the agent wallet the cost minus a percentage
///    platform fee (sent to the treasury).
///
/// The off-chain "agent signs a random key" handshake is verified by the intake
/// engine off-chain; the on-chain release is purely capability-gated.
module quadra::intake;

use std::string::String;
use sui::balance::Balance;
use sui::coin::{Self, Coin};
use sui::event;
use quadra::quadra::QUADRA;
use quadra::agent::{Self, AgentRegistry};
use quadra::job_access::{Self, JobAccessRegistry};

/// The target agent wallet is not registered.
const ENotRegistered: u64 = 0;
/// Fee basis points must be <= 10000.
const EBadFee: u64 = 1;

/// Basis-points denominator (100% = 10000).
const BPS_DENOM: u64 = 10000;

/// Held by the intake engine. Its holder can release payments.
public struct IntakeCap has key, store {
    id: UID,
}

/// Shared fee settings, editable with the `IntakeCap`.
public struct IntakeConfig has key {
    id: UID,
    /// Platform fee in basis points, taken from each released payment.
    fee_bps: u64,
    /// Address that receives the fee.
    treasury: address,
}

/// One escrowed user payment. This is what the contract stores after a user
/// pays, matching the session object `{ session_id, job_id, agent_wallet, cost }`
/// (`funds` holds `cost`).
public struct Escrow has key {
    id: UID,
    session_id: String,
    job_id: String,
    agent_wallet: address,
    funds: Balance<QUADRA>,
}

/// Emitted on `pay_for_job`; the intake engine watches for this.
public struct JobPaid has copy, drop {
    escrow_id: ID,
    session_id: String,
    job_id: String,
    agent_wallet: address,
    cost: u64,
}

/// Emitted when a payment is released to an agent.
public struct PaymentReleased has copy, drop {
    escrow_id: ID,
    agent_wallet: address,
    agent_amount: u64,
    fee: u64,
}

/// Mint the cap and share the config at publish. Default fee is 10%.
fun init(ctx: &mut TxContext) {
    transfer::transfer(IntakeCap { id: object::new(ctx) }, ctx.sender());
    transfer::share_object(IntakeConfig {
        id: object::new(ctx),
        fee_bps: 1000,
        treasury: ctx.sender(),
    });
}

/// User pays for a job; locks `payment` in a shared `Escrow`. Aborts if the
/// target agent wallet is not registered (users cannot pay unregistered agents).
///
/// Records `{ job_id -> (payer, agent_wallet) }` in the Seal access registry so
/// only those two addresses can later decrypt the job result. The payer is the
/// transaction sender — captured here because it is never stored on the escrow.
public fun pay_for_job(
    registry: &AgentRegistry,
    access_registry: &mut JobAccessRegistry,
    session_id: String,
    job_id: String,
    agent_wallet: address,
    payment: Coin<QUADRA>,
    ctx: &mut TxContext,
) {
    assert!(agent::is_registered(registry, agent_wallet), ENotRegistered);
    job_access::record(access_registry, job_id, ctx.sender(), agent_wallet);
    let escrow = Escrow {
        id: object::new(ctx),
        session_id,
        job_id,
        agent_wallet,
        funds: payment.into_balance(),
    };
    event::emit(JobPaid {
        escrow_id: object::id(&escrow),
        session_id: escrow.session_id,
        job_id: escrow.job_id,
        agent_wallet,
        cost: escrow.funds.value(),
    });
    transfer::share_object(escrow);
}

/// Release an escrow to the agent wallet, minus the platform fee.
/// Capability-gated: only the intake engine can call this.
public fun release_payment(
    _: &IntakeCap,
    config: &IntakeConfig,
    escrow: Escrow,
    ctx: &mut TxContext,
) {
    let Escrow { id, session_id: _, job_id: _, agent_wallet, mut funds } = escrow;
    let escrow_id = id.to_inner();
    let total = funds.value();
    let fee = (((total as u128) * (config.fee_bps as u128)) / (BPS_DENOM as u128)) as u64;

    // Fee to the treasury, remainder to the agent.
    if (fee > 0) {
        transfer::public_transfer(coin::take(&mut funds, fee, ctx), config.treasury);
    };
    let agent_amount = funds.value();
    transfer::public_transfer(coin::from_balance(funds, ctx), agent_wallet);

    event::emit(PaymentReleased { escrow_id, agent_wallet, agent_amount, fee });
    id.delete();
}

/// Update the fee and treasury. Capability-gated.
public fun set_fee(_: &IntakeCap, config: &mut IntakeConfig, fee_bps: u64, treasury: address) {
    assert!(fee_bps <= BPS_DENOM, EBadFee);
    config.fee_bps = fee_bps;
    config.treasury = treasury;
}

public fun fee_bps(config: &IntakeConfig): u64 { config.fee_bps }

public fun treasury(config: &IntakeConfig): address { config.treasury }

public fun escrow_cost(escrow: &Escrow): u64 { escrow.funds.value() }

public fun escrow_agent(escrow: &Escrow): address { escrow.agent_wallet }

#[test_only]
public fun init_for_testing(ctx: &mut TxContext) {
    init(ctx);
}
