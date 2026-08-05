// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.25;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {SealedCompetition} from "../src/SealedCompetition.sol";

/// @title CreateCompetition
/// @notice Opens a competition. This is the successor to Quadra's operator tooling
/// (`competition-engine/scripts/create-competition.ts` and friends): creation is permissioned, so
/// the caller must hold an operator slot on the contract.
///
/// Environment:
///   SEALED_COMPETITION  the market address (required).
///   COMPETITION_LABEL   human label; the id is keccak(label). Default "demo-1".
///   EVALUATOR_ID        the scorer to use, e.g. "price-range-guess".
///   KIND                0 SCORING (default), 1 PERFORMANCE.
///   STAKE               what each agent posts to join, in wei. Default 0.
///   PRIZE               msg.value seeding the pot, in wei. Default 0.
///   RESOLVE_IN          seconds from now until resolution. Default 3600.
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
        uint64 threshold = uint64(vm.envOr("THRESHOLD", uint256(0)));

        uint256[] memory defaultSplit = new uint256[](1);
        defaultSplit[0] = 100;
        uint256[] memory rawSplit = vm.envOr("SPLIT_PCT", ",", defaultSplit);
        uint16[] memory split = new uint16[](rawSplit.length);
        for (uint256 i = 0; i < rawSplit.length; i++) {
            split[i] = uint16(rawSplit[i]);
        }

        bytes32 competitionId = keccak256(bytes(label));
        uint64 resolveAt = uint64(block.timestamp + resolveIn);

        uint256 pk = vm.envOr("PRIVATE_KEY", uint256(0));
        if (pk != 0) vm.startBroadcast(pk);
        else vm.startBroadcast();

        SealedCompetition(market).create{value: prize}(
            competitionId, evaluatorId, kind, stake, resolveAt, threshold, split
        );

        vm.stopBroadcast();

        console2.log("market      ", market);
        console2.log("evaluatorId ", evaluatorId);
        console2.log("kind        ", kind);
        console2.log("stake       ", stake);
        console2.log("prize       ", prize);
        console2.log("threshold   ", threshold);
        console2.log("resolveAt   ", resolveAt);
        console2.logBytes32(competitionId);
    }
}
