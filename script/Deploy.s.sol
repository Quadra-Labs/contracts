// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.25;

import {Script} from "forge-std/Script.sol";
import {VmSafe} from "forge-std/Vm.sol";
import {console2} from "forge-std/console2.sol";

import {TeeRegistry} from "../src/TeeRegistry.sol";
import {Passport} from "../src/Passport.sol";
import {JobEscrow} from "../src/JobEscrow.sol";
import {SealedCompetition} from "../src/SealedCompetition.sol";
import {QuadraToken} from "../src/QuadraToken.sol";
import {ConfidentialSpaceVerifier} from "../src/vtpm/ConfidentialSpaceVerifier.sol";
import {IFlareSystemsManager} from "../src/interfaces/IFlareSystemsManager.sol";
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
    /// The FTSO voting-round geometry could not be resolved and DEV is not set.
    error MissingVotingEpoch();
    error RecordersNotWired();
    /// No `QUADRA_TOKEN`, and `MINT_NEW_TOKEN` was not set to say a fresh supply is intended.
    /// Reuse the live token, or opt in explicitly — do not arrive at a new one by omission.
    error MissingQuadraToken();

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

        (uint64 firstVotingRoundStartTs, uint64 votingEpochSecs) = _resolveVotingEpoch();
        if (votingEpochSecs == 0) {
            // Refusing rather than defaulting. A hardcoded fallback is the exact failure this is
            // resolved from chain to avoid, and on a real network guessing it means every
            // settlement is judged against a round the engine did not use.
            if (!dev) revert MissingVotingEpoch();
            // Coston2's confirmed geometry, for anvil and fork runs only. Mirrors
            // `quadra-core/feeds.ts`'s documented fallback, and is why that file labels it one.
            firstVotingRoundStartTs = 1_658_430_000;
            votingEpochSecs = 90;
        }

        uint256 pk = vm.envOr("PRIVATE_KEY", uint256(0));
        if (pk != 0) vm.startBroadcast(pk);
        else vm.startBroadcast();

        // QUADRA_TOKEN lets a redeploy of the markets reuse the existing token, so agent balances
        // and the fee history survive.
        //
        // MINTING A FRESH SUPPLY IS NOW OPT-IN. It used to be what happened when this variable was
        // simply forgotten — and it is not in `contracts/.env`, so forgetting it meant typing one
        // fewer thing on a long command line. The result was silent and expensive: markets
        // denominated in a brand-new token, every existing balance stranded on the old one, and
        // nothing anywhere reporting a problem. A fresh token is a legitimate thing to want on a
        // first deployment; it is never something to arrive at by omission.
        address tokenAddr = vm.envOr("QUADRA_TOKEN", address(0));
        if (tokenAddr == address(0)) {
            if (!vm.envOr("MINT_NEW_TOKEN", false)) revert MissingQuadraToken();
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
            new JobEscrow(
            tokenAddr,
            address(registry),
            address(passport),
            treasury,
            feeBps,
            ftsoVerifier,
            intake,
            firstVotingRoundStartTs,
            votingEpochSecs
        );
        SealedCompetition competition =
            new SealedCompetition(
            tokenAddr,
            address(registry),
            address(passport),
            ftsoVerifier,
            firstVotingRoundStartTs,
            votingEpochSecs
        );

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

    /// The FTSO voting-round geometry both markets need to bind a proof to a settlement's instant.
    ///
    /// Resolved from `FlareSystemsManager` through the registry, exactly like the verifier above,
    /// with env overrides for a fork or an anvil run. Returning zeros is only legal on the DEV
    /// path — `run()` refuses them otherwise, because a deployment that guessed this geometry
    /// accepts proofs from the wrong instant and reports nothing (see IFlareSystemsManager).
    function _resolveVotingEpoch() internal view returns (uint64 firstStart, uint64 epochSecs) {
        firstStart = uint64(vm.envOr("FIRST_VOTING_ROUND_START_TS", uint256(0)));
        epochSecs = uint64(vm.envOr("VOTING_EPOCH_SECONDS", uint256(0)));
        if (firstStart != 0 && epochSecs != 0) return (firstStart, epochSecs);

        if (FLARE_CONTRACT_REGISTRY.code.length == 0) return (0, 0);
        address manager =
            IFlareContractRegistry(FLARE_CONTRACT_REGISTRY).getContractAddressByName("FlareSystemsManager");
        if (manager == address(0)) return (0, 0);

        // `try` rather than a bare call: an older manager that does not expose these leaves the
        // deploy able to say WHICH read failed, instead of reverting inside a getter.
        try IFlareSystemsManager(manager).firstVotingRoundStartTs() returns (uint64 s) {
            firstStart = s;
        } catch {
            return (0, 0);
        }
        try IFlareSystemsManager(manager).votingEpochDurationSeconds() returns (uint64 d) {
            epochSecs = d;
        } catch {
            return (0, 0);
        }
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
        // A DRY RUN MUST NOT TOUCH THIS FILE.
        //
        // `forge script` without `--broadcast` withholds the TRANSACTIONS, not the script body — so
        // this function still runs and used to overwrite the canonical address file with addresses
        // that were computed but never deployed. Every repo reads this file to find the contracts,
        // so the result was a whole workspace pointed at empty addresses, from a command whose
        // entire purpose is to change nothing. Hit for real on 2026-08-12; see DEPLOYMENT-STATE.
        if (vm.isContext(VmSafe.ForgeContext.ScriptDryRun)) {
            console2.log("DRY RUN            ", path, "NOT written (simulated addresses above)");
            return;
        }
        vm.writeFile(path, json);
        console2.log("wrote             ", path);
    }
}
