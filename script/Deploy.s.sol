// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.25;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";

import {TeeRegistry} from "../src/TeeRegistry.sol";
import {Passport} from "../src/Passport.sol";
import {JobEscrow} from "../src/JobEscrow.sol";
import {SealedCompetition} from "../src/SealedCompetition.sol";
import {QuadraToken} from "../src/QuadraToken.sol";
import {ConfidentialSpaceVerifier} from "../src/vtpm/ConfidentialSpaceVerifier.sol";
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
///   VTPM_VERIFIER          an EXISTING on-chain vTPM attestation verifier (default 0 = dev only).
///   DEPLOY_VTPM            true to deploy a fresh ConfidentialSpaceVerifier and use it. Mutually
///                          exclusive with VTPM_VERIFIER. This is what turns on the attested
///                          `register` path, and the registry pins it immutably.
///   VTPM_SUB_PREFIX        optional GCP `sub` prefix pinning which project may register, e.g.
///                          "https://www.googleapis.com/compute/v1/projects/my-project/".
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
        bool deployVtpm = vm.envOr("DEPLOY_VTPM", false);
        address teeWallet = vm.envOr("TEE_WALLET", address(0));

        // The attestation verifier is what makes `TeeRegistry.register` reachable, and the registry
        // holds it `immutable` — so it must exist BEFORE the registry, and switching it on later
        // costs a full redeploy of the markets too. Deploying it here by default-off keeps the dev
        // path unchanged while making the attested path a one-flag decision at deploy time rather
        // than a migration.
        if (deployVtpm && vtpmVerifier != address(0)) {
            revert("set DEPLOY_VTPM or VTPM_VERIFIER, not both");
        }

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

        if (deployVtpm) {
            ConfidentialSpaceVerifier verifier = new ConfidentialSpaceVerifier();
            // The GCP project pin, which decides whether anyone running the same public image can
            // bind their own enclave key. Empty leaves it open; see the verifier's trust notes.
            string memory subPrefix = vm.envOr("VTPM_SUB_PREFIX", string(""));
            if (bytes(subPrefix).length != 0) verifier.setRequiredSubPrefix(subPrefix);
            vtpmVerifier = address(verifier);
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

        _write(
            Written({
                quadraToken: tokenAddr,
                registry: address(registry),
                passport: address(passport),
                jobEscrow: address(jobEscrow),
                competition: address(competition),
                treasury: treasury,
                intake: intake,
                ftsoVerifier: ftsoVerifier,
                vtpmVerifier: vtpmVerifier
            })
        );

        console2.log("quadraToken       ", tokenAddr);
        console2.log("teeRegistry       ", address(registry));
        console2.log("passport          ", address(passport));
        console2.log("jobEscrow         ", address(jobEscrow));
        console2.log("sealedCompetition ", address(competition));
        console2.log("treasury          ", treasury);
        console2.log("intake            ", intake);
        console2.log("ftsoVerifier      ", ftsoVerifier);
        console2.log("vtpmVerifier      ", vtpmVerifier);
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
    /// Grouped into a struct because nine positional addresses is a call nobody can read, and one
    /// transposed pair writes a deployment file every other repo then trusts.
    struct Written {
        address quadraToken;
        address registry;
        address passport;
        address jobEscrow;
        address competition;
        address treasury;
        address intake;
        address ftsoVerifier;
        address vtpmVerifier;
    }

    function _write(Written memory w) internal {
        string memory path = string.concat("deployments/", vm.toString(block.chainid), ".json");
        string memory json = string.concat(
            '{\n  "chainId": ',
            vm.toString(block.chainid),
            ',\n  "quadraToken": "',
            vm.toString(w.quadraToken),
            '",\n  "teeRegistry": "',
            vm.toString(w.registry),
            '",\n  "passport": "',
            vm.toString(w.passport),
            '",\n  "jobEscrow": "',
            vm.toString(w.jobEscrow),
            '",\n  "sealedCompetition": "',
            vm.toString(w.competition),
            '",\n  "evaluationInstructionSender": "",\n  "treasury": "',
            vm.toString(w.treasury),
            '",\n  "intake": "',
            vm.toString(w.intake),
            '",\n  "ftsoVerifier": "',
            vm.toString(w.ftsoVerifier),
            '",\n  "vtpmVerifier": "',
            vm.toString(w.vtpmVerifier),
            '"\n}\n'
        );
        vm.writeFile(path, json);
        console2.log("wrote             ", path);
    }
}
