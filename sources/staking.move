// Copyright (c), Quadra.
// SPDX-License-Identifier: Apache-2.0

/// Staking: lock $QUADRA to earn $QUADRA rewards from an admin-funded pool.
///
/// Reward accrues per epoch:
///   reward = amount * reward_rate_bps * epochs_elapsed / 10000
/// and is capped by the funds available in the reward reserve. Unstake any time
/// to get the principal back plus the accrued reward.
#[allow(lint(self_transfer))]
module quadra::staking;

use sui::balance::{Self, Balance};
use sui::coin::{Self, Coin};
use sui::event;
use quadra::quadra::QUADRA;

/// Stake amount must be > 0.
const EZeroStake: u64 = 0;
/// Reward rate basis points too large.
const EBadRate: u64 = 1;

/// Basis-points denominator.
const BPS_DENOM: u64 = 10000;
/// Cap the configurable rate at 100% per epoch.
const MAX_RATE_BPS: u64 = 10000;

/// Admin capability for funding rewards and setting the rate.
public struct StakingAdminCap has key, store {
    id: UID,
}

/// Shared staking pool holding the reward reserve.
public struct StakingPool has key {
    id: UID,
    rewards: Balance<QUADRA>,
    staked_total: u64,
    reward_rate_bps: u64,
}

/// A user's stake receipt; holds the locked principal.
public struct Stake has key {
    id: UID,
    owner: address,
    principal: Balance<QUADRA>,
    amount: u64,
    start_epoch: u64,
}

public struct Staked has copy, drop { stake_id: ID, owner: address, amount: u64, start_epoch: u64 }
public struct Unstaked has copy, drop { stake_id: ID, owner: address, principal: u64, reward: u64 }
public struct RewardsFunded has copy, drop { amount: u64 }

/// Create the admin cap and share the pool at publish (rate starts at 0).
fun init(ctx: &mut TxContext) {
    transfer::transfer(StakingAdminCap { id: object::new(ctx) }, ctx.sender());
    transfer::share_object(StakingPool {
        id: object::new(ctx),
        rewards: balance::zero(),
        staked_total: 0,
        reward_rate_bps: 0,
    });
}

/// Stake `coins`; returns a `Stake` receipt holding the principal.
public fun stake(pool: &mut StakingPool, coins: Coin<QUADRA>, ctx: &mut TxContext): Stake {
    let amount = coins.value();
    assert!(amount > 0, EZeroStake);
    pool.staked_total = pool.staked_total + amount;
    let stake = Stake {
        id: object::new(ctx),
        owner: ctx.sender(),
        principal: coins.into_balance(),
        amount,
        start_epoch: ctx.epoch(),
    };
    event::emit(Staked {
        stake_id: object::id(&stake),
        owner: stake.owner,
        amount,
        start_epoch: stake.start_epoch,
    });
    stake
}

/// Convenience: stake and keep the receipt.
public fun stake_and_keep(pool: &mut StakingPool, coins: Coin<QUADRA>, ctx: &mut TxContext) {
    transfer::transfer(stake(pool, coins, ctx), ctx.sender());
}

/// Unstake: returns principal + accrued reward (reward capped by the reserve).
public fun unstake(pool: &mut StakingPool, stake: Stake, ctx: &mut TxContext): Coin<QUADRA> {
    let Stake { id, owner: _, mut principal, amount, start_epoch } = stake;
    let stake_id = id.to_inner();
    let epochs = ctx.epoch() - start_epoch;
    let reward = reward_for(amount, pool.reward_rate_bps, epochs, pool.rewards.value());

    pool.staked_total = pool.staked_total - amount;
    if (reward > 0) {
        principal.join(pool.rewards.split(reward));
    };
    event::emit(Unstaked { stake_id, owner: ctx.sender(), principal: amount, reward });
    id.delete();
    coin::from_balance(principal, ctx)
}

/// Convenience: unstake and keep the coins.
public fun unstake_and_keep(pool: &mut StakingPool, stake: Stake, ctx: &mut TxContext) {
    transfer::public_transfer(unstake(pool, stake, ctx), ctx.sender());
}

/// Fund the reward reserve. Admin-gated.
public fun fund_rewards(_: &StakingAdminCap, pool: &mut StakingPool, coins: Coin<QUADRA>) {
    let amount = coins.value();
    pool.rewards.join(coins.into_balance());
    event::emit(RewardsFunded { amount });
}

/// Set the per-epoch reward rate (basis points). Admin-gated.
public fun set_reward_rate(_: &StakingAdminCap, pool: &mut StakingPool, bps: u64) {
    assert!(bps <= MAX_RATE_BPS, EBadRate);
    pool.reward_rate_bps = bps;
}

/// reward = amount * rate_bps * epochs / 10000, capped by `available`.
fun reward_for(amount: u64, rate_bps: u64, epochs: u64, available: u64): u64 {
    let raw = ((amount as u128) * (rate_bps as u128) * (epochs as u128)) / (BPS_DENOM as u128);
    if (raw > (available as u128)) available else (raw as u64)
}

public fun staked_total(pool: &StakingPool): u64 { pool.staked_total }

public fun reward_rate_bps(pool: &StakingPool): u64 { pool.reward_rate_bps }

public fun rewards_balance(pool: &StakingPool): u64 { pool.rewards.value() }

public fun stake_amount(stake: &Stake): u64 { stake.amount }

#[test_only]
public fun init_for_testing(ctx: &mut TxContext) {
    init(ctx);
}
