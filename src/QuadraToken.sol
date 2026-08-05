// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.25;

import {ERC20} from "openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";

/// @title QuadraToken
/// @notice QUADRA, the network token. Jobs are paid in it, competition stakes and prizes are
/// denominated in it, and the platform fee is taken in it.
///
/// Ported from Quadra's Sui `quadra.move`, which created the currency, minted the entire supply to
/// the deployer, and then FROZE the treasury cap so no further minting was possible for the life of
/// the package. The equivalent here is structural rather than a frozen object: the whole supply is
/// minted once in the constructor and this contract declares no `mint` function at all, so there is
/// no code path that can ever increase the supply. The contract is not upgradeable, so that
/// property cannot be added later either.
///
/// DECIMALS: Sui used 6, because amounts there are `u64` and 100 billion tokens at 18 decimals
/// would overflow it. The EVM has no such limit and 18 is what every wallet, explorer and
/// integration expects, so this uses the inherited default of 18. The consequence is that every
/// amount from the Sui era is rescaled by 1e12 - a Sui-era balance of `1000` base units is `1e15`
/// here. Do not copy raw amounts across from the old tests or scripts.
///
/// Gas is still paid in native C2FLR/FLR. Holding QUADRA is not enough to transact; an account
/// needs both.
contract QuadraToken is ERC20 {
    /// 100,000,000,000 QUADRA. Same headline number as the Sui original; only the decimals differ.
    uint256 public constant TOTAL_SUPPLY = 100_000_000_000 * 1e18;

    /// Mints the entire supply to `treasury`. There is deliberately no other mint path.
    constructor(address treasury) ERC20("Quadra", "QUADRA") {
        _mint(treasury, TOTAL_SUPPLY);
    }
}
