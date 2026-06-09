// Copyright (c), Quadra.
// SPDX-License-Identifier: Apache-2.0

/// A minimal constant-product AMM for the QUADRA/SUI pair.
///
/// Reserves follow x*y=k with a 0.3% fee taken from each swap input. Liquidity
/// providers receive `Coin<LP>` proportional to their share and burn it to
/// withdraw. All intermediate math uses u128 to avoid overflow.
#[allow(lint(self_transfer))]
module quadra::amm;

use sui::balance::{Self, Balance, Supply};
use sui::coin::{Self, Coin};
use sui::event;
use sui::sui::SUI;
use quadra::quadra::QUADRA;

/// Amount must be > 0.
const EZeroAmount: u64 = 0;
/// Pool has no liquidity yet.
const ENoLiquidity: u64 = 1;
/// Output below the caller's minimum.
const ESlippage: u64 = 2;

/// Swap fee = 0.3%.
const FEE_BPS: u64 = 30;
const BPS_DENOM: u64 = 10000;

/// LP token type.
public struct LP has drop {}

/// The shared QUADRA/SUI pool.
public struct Pool has key {
    id: UID,
    quadra: Balance<QUADRA>,
    sui: Balance<SUI>,
    lp_supply: Supply<LP>,
}

public struct LiquidityAdded has copy, drop { quadra: u64, sui: u64, lp: u64 }
public struct LiquidityRemoved has copy, drop { quadra: u64, sui: u64, lp: u64 }
public struct Swapped has copy, drop { quadra_in: u64, sui_in: u64, quadra_out: u64, sui_out: u64 }

/// Share an empty pool at publish.
fun init(ctx: &mut TxContext) {
    transfer::share_object(Pool {
        id: object::new(ctx),
        quadra: balance::zero(),
        sui: balance::zero(),
        lp_supply: balance::create_supply(LP {}),
    });
}

/// Add liquidity. The first provider sets the price; later providers should
/// supply both sides in the current ratio. Returns the minted LP coin.
public fun add_liquidity(
    pool: &mut Pool,
    quadra: Coin<QUADRA>,
    sui: Coin<SUI>,
    ctx: &mut TxContext,
): Coin<LP> {
    let dq = quadra.value();
    let ds = sui.value();
    assert!(dq > 0 && ds > 0, EZeroAmount);

    let rq = pool.quadra.value();
    let rs = pool.sui.value();
    let supply = pool.lp_supply.supply_value();

    let lp_amount = if (supply == 0) {
        sqrt((dq as u128) * (ds as u128))
    } else {
        let by_q = (dq as u128) * (supply as u128) / (rq as u128);
        let by_s = (ds as u128) * (supply as u128) / (rs as u128);
        (if (by_q < by_s) by_q else by_s) as u64
    };
    assert!(lp_amount > 0, EZeroAmount);

    pool.quadra.join(quadra.into_balance());
    pool.sui.join(sui.into_balance());
    let lp_balance = pool.lp_supply.increase_supply(lp_amount);

    event::emit(LiquidityAdded { quadra: dq, sui: ds, lp: lp_amount });
    coin::from_balance(lp_balance, ctx)
}

/// Remove liquidity by burning `lp`. Returns proportional QUADRA and SUI.
public fun remove_liquidity(
    pool: &mut Pool,
    lp: Coin<LP>,
    ctx: &mut TxContext,
): (Coin<QUADRA>, Coin<SUI>) {
    let lp_amount = lp.value();
    assert!(lp_amount > 0, EZeroAmount);
    let supply = pool.lp_supply.supply_value();
    let rq = pool.quadra.value();
    let rs = pool.sui.value();

    let q_out = ((rq as u128) * (lp_amount as u128) / (supply as u128)) as u64;
    let s_out = ((rs as u128) * (lp_amount as u128) / (supply as u128)) as u64;

    pool.lp_supply.decrease_supply(lp.into_balance());
    let q = coin::take(&mut pool.quadra, q_out, ctx);
    let s = coin::take(&mut pool.sui, s_out, ctx);

    event::emit(LiquidityRemoved { quadra: q_out, sui: s_out, lp: lp_amount });
    (q, s)
}

/// Swap QUADRA in for SUI out.
public fun swap_quadra_for_sui(
    pool: &mut Pool,
    quadra_in: Coin<QUADRA>,
    min_out: u64,
    ctx: &mut TxContext,
): Coin<SUI> {
    let amount_in = quadra_in.value();
    assert!(amount_in > 0, EZeroAmount);
    let rq = pool.quadra.value();
    let rs = pool.sui.value();
    assert!(rq > 0 && rs > 0, ENoLiquidity);

    let out = amount_out(amount_in, rq, rs);
    assert!(out >= min_out, ESlippage);

    pool.quadra.join(quadra_in.into_balance());
    let sui_out = coin::take(&mut pool.sui, out, ctx);
    event::emit(Swapped { quadra_in: amount_in, sui_in: 0, quadra_out: 0, sui_out: out });
    sui_out
}

/// Swap SUI in for QUADRA out.
public fun swap_sui_for_quadra(
    pool: &mut Pool,
    sui_in: Coin<SUI>,
    min_out: u64,
    ctx: &mut TxContext,
): Coin<QUADRA> {
    let amount_in = sui_in.value();
    assert!(amount_in > 0, EZeroAmount);
    let rq = pool.quadra.value();
    let rs = pool.sui.value();
    assert!(rq > 0 && rs > 0, ENoLiquidity);

    let out = amount_out(amount_in, rs, rq);
    assert!(out >= min_out, ESlippage);

    pool.sui.join(sui_in.into_balance());
    let quadra_out = coin::take(&mut pool.quadra, out, ctx);
    event::emit(Swapped { quadra_in: 0, sui_in: amount_in, quadra_out: out, sui_out: 0 });
    quadra_out
}

// --- entry wrappers that transfer outputs to the caller (easy CLI use) ---

public fun add_liquidity_and_keep(pool: &mut Pool, quadra: Coin<QUADRA>, sui: Coin<SUI>, ctx: &mut TxContext) {
    transfer::public_transfer(add_liquidity(pool, quadra, sui, ctx), ctx.sender());
}

public fun remove_liquidity_and_keep(pool: &mut Pool, lp: Coin<LP>, ctx: &mut TxContext) {
    let (q, s) = remove_liquidity(pool, lp, ctx);
    transfer::public_transfer(q, ctx.sender());
    transfer::public_transfer(s, ctx.sender());
}

public fun swap_quadra_for_sui_and_keep(pool: &mut Pool, quadra_in: Coin<QUADRA>, min_out: u64, ctx: &mut TxContext) {
    transfer::public_transfer(swap_quadra_for_sui(pool, quadra_in, min_out, ctx), ctx.sender());
}

public fun swap_sui_for_quadra_and_keep(pool: &mut Pool, sui_in: Coin<SUI>, min_out: u64, ctx: &mut TxContext) {
    transfer::public_transfer(swap_sui_for_quadra(pool, sui_in, min_out, ctx), ctx.sender());
}

// --- helpers ---

/// Constant-product output, with the fee applied to the input.
fun amount_out(amount_in: u64, reserve_in: u64, reserve_out: u64): u64 {
    let in_after_fee = (amount_in as u128) * ((BPS_DENOM - FEE_BPS) as u128) / (BPS_DENOM as u128);
    let numerator = in_after_fee * (reserve_out as u128);
    let denominator = (reserve_in as u128) + in_after_fee;
    (numerator / denominator) as u64
}

/// Integer square root (Babylonian method).
fun sqrt(x: u128): u64 {
    if (x == 0) return 0;
    let mut z = x;
    let mut y = (x + 1) / 2;
    while (y < z) {
        z = y;
        y = (x / y + y) / 2;
    };
    z as u64
}

public fun reserves(pool: &Pool): (u64, u64) { (pool.quadra.value(), pool.sui.value()) }

public fun lp_supply_value(pool: &Pool): u64 { pool.lp_supply.supply_value() }

#[test_only]
public fun init_for_testing(ctx: &mut TxContext) {
    init(ctx);
}
