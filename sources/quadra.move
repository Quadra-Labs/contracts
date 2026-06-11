// Copyright (c), Quadra.
// SPDX-License-Identifier: Apache-2.0

/// $QUADRA: the Quadra agent-network token.
///
/// Fixed supply of 100,000,000,000 tokens at 6 decimals (= 1e17 base units,
/// which fits in u64). The whole supply is minted to the deployer in `init`, then
/// the `TreasuryCap` is frozen — so the supply is hard-capped forever (no further
/// mint or burn is ever possible).
module quadra::quadra;

use sui::coin;

/// 100,000,000,000 tokens * 10^6 (6 decimals) = 1e17 base units.
const TOTAL_SUPPLY: u64 = 100_000_000_000_000_000;

/// One-time witness for the currency.
public struct QUADRA has drop {}

/// Create the currency, mint the full supply to the deployer, then freeze the cap.
#[allow(deprecated_usage)]
fun init(witness: QUADRA, ctx: &mut TxContext) {
    let (mut treasury, metadata) = coin::create_currency(
        witness,
        6,
        b"QUADRA",
        b"Quadra",
        b"Quadra agent network token",
        option::none(),
        ctx,
    );

    // Mint the entire fixed supply to the deployer.
    let coins = treasury.mint(TOTAL_SUPPLY, ctx);
    transfer::public_transfer(coins, ctx.sender());

    // Freeze both metadata and the treasury cap: the supply is now immutable.
    transfer::public_freeze_object(metadata);
    transfer::public_freeze_object(treasury);
}

/// The fixed total supply, in base units.
public fun total_supply(): u64 {
    TOTAL_SUPPLY
}

#[test_only]
public fun init_for_testing(ctx: &mut TxContext) {
    init(QUADRA {}, ctx);
}
