// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.25;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {SealedCompetition} from "../src/SealedCompetition.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

/// @title CreateCompetition
/// @notice Opens a competition. This is the successor to Quadra's operator tooling
/// (`competition-engine/scripts/create-competition.ts` and friends): creation is permissioned, so
/// the caller must hold an operator slot on the contract.
///
/// Environment:
///   SEALED_COMPETITION  the market address (required).
///   COMPETITION_LABEL   human label; the id is keccak256(abi.encode(operator, label)) — see below.
///                       Default "demo-1".
///   EVALUATOR_ID        the scorer to use, e.g. "price-range-guess".
///   KIND                0 SCORING (default), 1 PERFORMANCE.
///   STAKE               what each agent posts to join, in wei. Default 0.
///   PRIZE               msg.value seeding the pot, in wei. Default 0.
///   RESOLVE_IN          seconds from now until resolution. Default 3600.
///   LIFETIME_SECS       the window entries are SCORED over, ending at resolveAt. Default 3600.
///                       This is NOT RESOLVE_IN: a competition opened six hours ahead and scored
///                       over its last hour sets RESOLVE_IN=21600 and LIFETIME_SECS=3600. Zero is
///                       rejected on chain, so there is no "let the engine decide" value.
///   PARAMS_JSON         raw JSON scope, e.g. {"asset":"ETH"} — the same convention a paid job's
///                       params use, stored as its UTF-8 bytes. Default empty, which means "no
///                       asset declared" and leaves the enclave on its default feed.
///   THRESHOLD           minimum ranking value to qualify. For PERFORMANCE, 1000000 means ROI >= 0.
///   SPLIT_PCT           comma-separated winner split summing to 100. Default "100".
///   PRIVATE_KEY         operator key.
contract CreateCompetition is Script {
    function run() external {
        address market = vm.envAddress("SEALED_COMPETITION");
        string memory label = vm.envOr("COMPETITION_LABEL", string("demo-1"));
        string memory evaluatorId = vm.envOr("EVALUATOR_ID", string("price-range-guess"));
        uint8 kind = uint8(vm.envOr("KIND", uint256(0)));
        uint256 stake = vm.envOr("STAKE", uint256(0));
        uint256 prize = vm.envOr("PRIZE", uint256(0));
        uint256 resolveIn = vm.envOr("RESOLVE_IN", uint256(3600));
        uint32 lifetimeSecs = uint32(vm.envOr("LIFETIME_SECS", uint256(3600)));
        // JSON-in-hex, exactly as `encodeJobParams` produces it: the stored bytes ARE the UTF-8
        // JSON text, so `jobAsset()` reads a competition and a paid job with one implementation.
        bytes memory params = bytes(vm.envOr("PARAMS_JSON", string("")));
        uint64 threshold = uint64(vm.envOr("THRESHOLD", uint256(0)));

        uint256[] memory defaultSplit = new uint256[](1);
        defaultSplit[0] = 100;
        uint256[] memory rawSplit = vm.envOr("SPLIT_PCT", ",", defaultSplit);
        uint16[] memory split = new uint16[](rawSplit.length);
        for (uint256 i = 0; i < rawSplit.length; i++) {
            split[i] = uint16(rawSplit[i]);
        }

        uint256 pk = vm.envOr("PRIVATE_KEY", uint256(0));

        // The id is bound to the CREATOR, not the label alone. `create` reverts AlreadyExists and
        // nothing is ever deleted, so a bare keccak(label) means the first operator to run this
        // with "demo-1" burns that id permanently for everyone else. Operator-gating already keeps
        // outsiders out; this is what keeps two of our own operators from colliding.
        //
        // `vm.addr(pk)`, NOT `msg.sender`: inside `run()` msg.sender is Foundry's DefaultSender,
        // not the key that broadcasts below, so deriving from it would produce an id nobody could
        // reproduce from the operator address that actually appears on chain as the creator.
        address operator = pk != 0 ? vm.addr(pk) : msg.sender;
        bytes32 competitionId = keccak256(abi.encode(operator, label));
        uint64 resolveAt = uint64(block.timestamp + resolveIn);

        if (pk != 0) vm.startBroadcast(pk);
        else vm.startBroadcast();

        // The market pulls the prize, so it has to be approved first.
        if (prize > 0) IERC20(SealedCompetition(market).token()).approve(market, prize);
        SealedCompetition(market).create(
            competitionId, evaluatorId, kind, stake, resolveAt, threshold, split, prize, lifetimeSecs, params
        );

        vm.stopBroadcast();

        console2.log("market      ", market);
        console2.log("operator    ", operator);
        console2.log("label       ", label);
        console2.log("evaluatorId ", evaluatorId);
        console2.log("kind        ", kind);
        console2.log("stake       ", stake);
        console2.log("prize       ", prize);
        console2.log("threshold   ", threshold);
        console2.log("resolveAt   ", resolveAt);
        console2.log("lifetimeSecs", lifetimeSecs);
        console2.log("params      ", string(params));
        console2.logBytes32(competitionId);
    }
}
