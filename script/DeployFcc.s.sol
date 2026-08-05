// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.25;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";

import {EvaluationInstructionSender} from "../src/EvaluationInstructionSender.sol";
import {ITeeExtensionRegistry} from "../src/interfaces/ITeeExtensionRegistry.sol";
import {ITeeMachineRegistry} from "../src/interfaces/ITeeMachineRegistry.sol";
import {TeeRegistry} from "../src/TeeRegistry.sol";

/// @title DeployFcc
/// @notice Stands up the Flare Confidential Compute layer. Deliberately separate from `Deploy` and
/// run in TWO passes, because the ordering is circular: the instruction sender must EXIST before
/// the scaffold's `register-extension` can bind it, and the extension id only exists after that.
///
///   Pass 1 (default):    deploy EvaluationInstructionSender, print its address.
///                        -> then run `register-extension` against that address, and note the id.
///   Pass 2 (FCC_BIND=true): verify the binding, discover the id, configure and bind the TEE.
///
/// Environment:
///   TEE_EXTENSION_REGISTRY  Flare's extension registry (required, both passes).
///   TEE_MACHINE_REGISTRY    Flare's machine registry (required, both passes).
///   FCC_BIND                true to run pass 2.
///   INSTRUCTION_SENDER      the address from pass 1 (pass 2).
///   EXTENSION_ID            the id allocated by register-extension (pass 2).
///   FCC_TEE_ADDRESS         the TEE machine to trust (pass 2).
///   FCC_TEE_PUBKEY          its secp256k1 public key, for sealing (pass 2, default 0x04).
///   TEE_REGISTRY            our already-deployed TeeRegistry (pass 2).
///   PRIVATE_KEY             deployer/owner key.
contract DeployFcc is Script {
    error WrongSenderBound(address expected, address actual);

    function run() external {
        address extensionRegistry = vm.envAddress("TEE_EXTENSION_REGISTRY");
        address machineRegistry = vm.envAddress("TEE_MACHINE_REGISTRY");
        bool bind = vm.envOr("FCC_BIND", false);
        uint256 pk = vm.envOr("PRIVATE_KEY", uint256(0));

        if (!bind) {
            if (pk != 0) vm.startBroadcast(pk);
            else vm.startBroadcast();
            EvaluationInstructionSender sender = new EvaluationInstructionSender(
                ITeeExtensionRegistry(extensionRegistry), ITeeMachineRegistry(machineRegistry)
            );
            vm.stopBroadcast();

            console2.log("INSTRUCTION_SENDER", address(sender));
            console2.log("next: run register-extension against that address, then re-run with FCC_BIND=true");
            return;
        }

        address senderAddr = vm.envAddress("INSTRUCTION_SENDER");
        uint256 extensionId = vm.envUint("EXTENSION_ID");
        address teeMachine = vm.envAddress("FCC_TEE_ADDRESS");
        bytes memory teePubKey = vm.envOr("FCC_TEE_PUBKEY", bytes(hex"04"));
        TeeRegistry registry = TeeRegistry(vm.envAddress("TEE_REGISTRY"));

        // Check the binding BEFORE touching anything: registering under an id that belongs to a
        // different sender would wire our markets to an enclave answering someone else's questions.
        address bound = ITeeExtensionRegistry(extensionRegistry).getTeeExtensionInstructionsSender(extensionId);
        if (bound != senderAddr) revert WrongSenderBound(senderAddr, bound);

        if (pk != 0) vm.startBroadcast(pk);
        else vm.startBroadcast();

        // Idempotent: a re-run after a partial failure must not revert on work already done.
        if (EvaluationInstructionSender(senderAddr).extensionIdOrZero() == 0) {
            EvaluationInstructionSender(senderAddr).setExtensionId();
        }
        registry.configureFcc(machineRegistry, extensionId);
        registry.registerFccTee(teeMachine, teePubKey);

        vm.stopBroadcast();

        console2.log("INSTRUCTION_SENDER", senderAddr);
        console2.log("EXTENSION_ID      ", extensionId);
        console2.log("activeTeeWallet   ", registry.activeTeeWallet());
        console2.log("fccMode           ", registry.fccMode());
        console2.log("NOTE: add INSTRUCTION_SENDER to deployments/<chainId>.json evaluationInstructionSender");
    }
}
