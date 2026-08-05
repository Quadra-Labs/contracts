// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.25;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";

import {TeeRegistry} from "../src/TeeRegistry.sol";
import {Passport} from "../src/Passport.sol";
import {JobEscrow} from "../src/JobEscrow.sol";
import {SealedCompetition} from "../src/SealedCompetition.sol";
import {QuadraToken} from "../src/QuadraToken.sol";
import {IFlareContractRegistry} from "../src/interfaces/IFlareContractRegistry.sol";

/// @title Deploy
/// @notice Deploys the four contracts, wires them, and writes the addresses every other repo reads.
///
/// Environment:
///   DEV                    true to allow a deploy with no oracle verifier and defaulted roles.
///                          Anything but an explicit `true` is treated as a real deployment.
///   EXPECTED_IMAGE_DIGEST  the Confidential Space image digest to pin (default "sha256:dev").
///   TREASURY               fee recipient.        Required unless DEV.
///   INTAKE_ADDRESS         the intake engine.    Required unless DEV.
///   FEE_BPS                platform fee, default 1000 (10%).
///   FTSO_VERIFIER          override the oracle verifier. Normally unset - it is resolved from the
///                          Flare contract registry, which is the only address safe to hardcode.
///   VTPM_VERIFIER          on-chain vTPM attestation verifier (default 0 = the dev path only).
///   TEE_WALLET/TEE_PUBKEY  optional dev TEE identity to bind immediately.
///   PRIVATE_KEY            deployer key; unset broadcasts without one (local simulation).
contract Deploy is Script {
    /// Network-independent: the same address on Flare, Songbird, Coston and Coston2.
    address internal constant FLARE_CONTRACT_REGISTRY = 0xaD67FE66660Fb8dFE9d6b1b4240d8650e30F6019;

    error MissingTreasury();
    error MissingIntake();
    error MissingFtsoVerifier();
    error RecordersNotWired();

    function run() external {
        bool dev = vm.envOr("DEV", false);
        string memory digest = vm.envOr("EXPECTED_IMAGE_DIGEST", string("sha256:dev"));
        uint16 feeBps = uint16(vm.envOr("FEE_BPS", uint256(1000)));
        address vtpmVerifier = vm.envOr("VTPM_VERIFIER", address(0));
        address teeWallet = vm.envOr("TEE_WALLET", address(0));

        // Never silently default the two privileged roles to the deployer on a real network: that
        // would quietly make one key both the fee recipient and the release authority.
        address treasury = vm.envOr("TREASURY", address(0));
        address intake = vm.envOr("INTAKE_ADDRESS", address(0));
        if (treasury == address(0)) {
            if (!dev) revert MissingTreasury();
            treasury = msg.sender;
        }
        if (intake == address(0)) {
            if (!dev) revert MissingIntake();
            intake = msg.sender;
        }

        address ftsoVerifier = _resolveFtsoVerifier();
        if (ftsoVerifier == address(0) && !dev) revert MissingFtsoVerifier();

        uint256 pk = vm.envOr("PRIVATE_KEY", uint256(0));
        if (pk != 0) vm.startBroadcast(pk);
        else vm.startBroadcast();

        // QUADRA_TOKEN lets a redeploy of the markets reuse the existing token, so agent balances
        // and the fee history survive. Unset mints a fresh supply to the treasury.
        address tokenAddr = vm.envOr("QUADRA_TOKEN", address(0));
        if (tokenAddr == address(0)) {
            tokenAddr = address(new QuadraToken(treasury));
        }

        TeeRegistry registry = new TeeRegistry(digest, vtpmVerifier);
        Passport passport = new Passport();
        JobEscrow jobEscrow =
            new JobEscrow(tokenAddr, address(registry), address(passport), treasury, feeBps, ftsoVerifier, intake);
        SealedCompetition competition =
            new SealedCompetition(tokenAddr, address(registry), address(passport), ftsoVerifier);

        passport.setRecorder(address(jobEscrow), true);
        passport.setRecorder(address(competition), true);

        // A missed wiring call is indistinguishable from a working deploy until the first refund or
        // settlement reverts NotRecorder - which, for a refund, means a user's escrow is trapped.
        if (!passport.recorders(address(jobEscrow)) || !passport.recorders(address(competition))) {
            revert RecordersNotWired();
        }

        if (teeWallet != address(0)) {
            registry.setActiveTee(teeWallet, vm.envOr("TEE_PUBKEY", bytes(hex"04")), digest);
        }

        vm.stopBroadcast();

        _write(tokenAddr, address(registry), address(passport), address(jobEscrow), address(competition), treasury, intake, ftsoVerifier);

        console2.log("quadraToken       ", tokenAddr);
        console2.log("teeRegistry       ", address(registry));
        console2.log("passport          ", address(passport));
        console2.log("jobEscrow         ", address(jobEscrow));
        console2.log("sealedCompetition ", address(competition));
        console2.log("treasury          ", treasury);
        console2.log("intake            ", intake);
        console2.log("ftsoVerifier      ", ftsoVerifier);
        console2.log("feeBps            ", feeBps);
        if (ftsoVerifier == address(0)) {
            console2.log("WARNING: no FTSO verifier - the oracle cross-check is disabled");
        }
    }

    /// An explicit override wins; otherwise ask the Flare registry. On a chain with no registry
    /// deployed (local Anvil) this returns zero, which only a DEV deploy accepts.
    function _resolveFtsoVerifier() internal view returns (address) {
        address override_ = vm.envOr("FTSO_VERIFIER", address(0));
        if (override_ != address(0)) return override_;
        if (FLARE_CONTRACT_REGISTRY.code.length == 0) return address(0);
        return IFlareContractRegistry(FLARE_CONTRACT_REGISTRY).getContractAddressByName("FtsoV2");
    }

    /// One file per chain, read by every other repo so no address is ever hardcoded downstream.
    /// `evaluationInstructionSender` is present but empty until the Flare Confidential Compute
    /// layer is deployed - the key exists from the start so consumers can parse one stable shape.
    function _write(
        address quadraToken,
        address registry,
        address passport,
        address jobEscrow,
        address competition,
        address treasury,
        address intake,
        address ftsoVerifier
    ) internal {
        string memory path = string.concat("deployments/", vm.toString(block.chainid), ".json");
        string memory json = string.concat(
            '{\n  "chainId": ',
            vm.toString(block.chainid),
            ',\n  "quadraToken": "',
            vm.toString(quadraToken),
            '",\n  "teeRegistry": "',
            vm.toString(registry),
            '",\n  "passport": "',
            vm.toString(passport),
            '",\n  "jobEscrow": "',
            vm.toString(jobEscrow),
            '",\n  "sealedCompetition": "',
            vm.toString(competition),
            '",\n  "evaluationInstructionSender": "",\n  "treasury": "',
            vm.toString(treasury),
            '",\n  "intake": "',
            vm.toString(intake),
            '",\n  "ftsoVerifier": "',
            vm.toString(ftsoVerifier),
            '"\n}\n'
        );
        vm.writeFile(path, json);
        console2.log("wrote             ", path);
    }
}
