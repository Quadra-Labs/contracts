// Copyright (c), Quadra.
// SPDX-License-Identifier: Apache-2.0

/// Staking: lock $QUADRA to earn $QUADRA rewards from an admin-funded pool.
///
/// Rewards use a pro-rata accumulator: the admin sets a fixed `emission_per_epoch`
/// that is split across all staked tokens by share, so no single staker can drain
/// the reserve disproportionately (a flash-stake earns at most one epoch's
/// emission). Unstake any time to get principal + accrued reward (the reward is
/// capped by the funded reserve).
#[allow(lint(self_transfer))]
module quadra::staking;

use sui::balance::{Self, Balance};
use sui::coin::{Self, Coin};
use sui::event;
use quadra::quadra::QUADRA;

/// Stake amount must be > 0.
const EZeroStake: u64 = 0;

/// Fixed-point precision for `acc_reward_per_share`.
const ACC_PRECISION: u128 = 1_000_000_000_000;

/// Admin capability for funding rewards and setting the emission.
public struct StakingAdminCap has key, store {
    id: UID,
}

/// Shared staking pool: the reward reserve plus the accumulator state.
public struct StakingPool has key {
    id: UID,
    rewards: Balance<QUADRA>,
    total_staked: u64,
    /// Total reward emitted per epoch, split pro-rata across all staked tokens.
    emission_per_epoch: u64,
    /// Cumulative reward per staked token, scaled by `ACC_PRECISION`.
    acc_reward_per_share: u128,
    /// Epoch the accumulator was last advanced to.
    last_update_epoch: u64,
}

/// A user's stake receipt; holds the locked principal and a reward checkpoint.
public struct Stake has key {
    id: UID,
    owner: address,
    principal: Balance<QUADRA>,
    amount: u64,
    /// `amount * acc_reward_per_share / ACC_PRECISION` at the last checkpoint.
    reward_debt: u128,
}

public struct Staked has copy, drop { stake_id: ID, owner: address, amount: u64 }
public struct Unstaked has copy, drop { stake_id: ID, owner: address, principal: u64, reward: u64 }
public struct RewardsFunded has copy, drop { amount: u64 }
public struct EmissionSet has copy, drop { emission_per_epoch: u64 }

/// Create the admin cap and share the pool at publish (emission starts at 0).
fun init(ctx: &mut TxContext) {
    transfer::transfer(StakingAdminCap { id: object::new(ctx) }, ctx.sender());
    transfer::share_object(StakingPool {
        id: object::new(ctx),
        rewards: balance::zero(),
        total_staked: 0,
        emission_per_epoch: 0,
        acc_reward_per_share: 0,
        last_update_epoch: ctx.epoch(),
    });
}

/// Advance the accumulator to `now_epoch` before any state change.
fun update_pool(pool: &mut StakingPool, now_epoch: u64) {
    if (now_epoch <= pool.last_update_epoch) return;
    let epochs = (now_epoch - pool.last_update_epoch) as u128;
    if (pool.total_staked > 0 && pool.emission_per_epoch > 0) {
        let emitted = (pool.emission_per_epoch as u128) * epochs;
        pool.acc_reward_per_share =
            pool.acc_reward_per_share + emitted * ACC_PRECISION / (pool.total_staked as u128);
    };
    pool.last_update_epoch = now_epoch;
}

/// Stake `coins`; returns a `Stake` receipt holding the principal.
public fun stake(pool: &mut StakingPool, coins: Coin<QUADRA>, ctx: &mut TxContext): Stake {
    update_pool(pool, ctx.epoch());
    let amount = coins.value();
    assert!(amount > 0, EZeroStake);
    pool.total_staked = pool.total_staked + amount;
    let stake = Stake {
        id: object::new(ctx),
        owner: ctx.sender(),
        principal: coins.into_balance(),
        amount,
        reward_debt: (amount as u128) * pool.acc_reward_per_share / ACC_PRECISION,
    };
    event::emit(Staked { stake_id: object::id(&stake), owner: stake.owner, amount });
    stake
}

/// Convenience: stake and keep the receipt.
public fun stake_and_keep(pool: &mut StakingPool, coins: Coin<QUADRA>, ctx: &mut TxContext) {
    transfer::transfer(stake(pool, coins, ctx), ctx.sender());
}

/// Unstake: returns principal + accrued reward (reward capped by the reserve).
public fun unstake(pool: &mut StakingPool, stake: Stake, ctx: &mut TxContext): Coin<QUADRA> {
    update_pool(pool, ctx.epoch());
    let Stake { id, owner: _, mut principal, amount, reward_debt } = stake;
    let stake_id = id.to_inner();

    let accumulated = (amount as u128) * pool.acc_reward_per_share / ACC_PRECISION;
    let pending = if (accumulated > reward_debt) accumulated - reward_debt else 0;
    let available = pool.rewards.value() as u128;
    let reward = (if (pending > available) available else pending) as u64;

    pool.total_staked = pool.total_staked - amount;
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

/// Set the per-epoch emission (total reward shared across all stakers). Advances
/// the accumulator first so elapsed epochs keep the old rate. Admin-gated.
public fun set_emission(
    _: &StakingAdminCap,
    pool: &mut StakingPool,
    emission_per_epoch: u64,
    ctx: &TxContext,
) {
    update_pool(pool, ctx.epoch());
    pool.emission_per_epoch = emission_per_epoch;
    event::emit(EmissionSet { emission_per_epoch });
}

public fun total_staked(pool: &StakingPool): u64 { pool.total_staked }

public fun emission_per_epoch(pool: &StakingPool): u64 { pool.emission_per_epoch }

public fun rewards_balance(pool: &StakingPool): u64 { pool.rewards.value() }

public fun stake_amount(stake: &Stake): u64 { stake.amount }

#[test_only]
public fun init_for_testing(ctx: &mut TxContext) {
    init(ctx);
}
