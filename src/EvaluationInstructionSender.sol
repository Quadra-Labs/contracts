// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.25;

import {ITeeExtensionRegistry} from "./interfaces/ITeeExtensionRegistry.sol";
import {ITeeMachineRegistry} from "./interfaces/ITeeMachineRegistry.sol";

/// @title EvaluationInstructionSender
/// @notice Our single registered on-chain entry point into Flare Confidential Compute. Everything
/// the enclave is asked to do arrives through here.
///
/// This is what replaces the keeper as trusted infrastructure. Under the self-operated TEE, a
/// funded wallet watched the chain, decided what to score, signed, and submitted - so liveness
/// depended on one process staying up and its key staying secret. Under FCC the chain routes the
/// instruction and the result comes back signed by the enclave, so whoever calls these functions is
/// an untrusted requester: they can decide WHEN something is evaluated, never WHAT the answer is.
///
/// Every message is a bare ABI-encoded id. The extension resolves everything else - job state, the
/// delivery ciphertext, the competition's creation block, the FTSO round - from the chain and the
/// DA layer itself, so a lying requester cannot narrow what the enclave looks at.
contract EvaluationInstructionSender {
    // --- Operation identifiers (MUST match evaluation-engine/src/fcc/app/config.ts) -------------
    // These are right-padded bytes32 STRING LITERALS, not keccak hashes - a common porting mistake
    // that produces an id the enclave will never recognise.
    //
    // FCC reserves the `F_` prefix for system op types, plus a list of system command names
    // (TEE_INFO, KEY_GENERATE, PAY, PROVE, TEE_ATTESTATION, TEE_BACKUP, KEY_INFO, KEY_PROOF,
    // KEY_DELETE, KEY_DIRECT_BACKUP, KEY_DIRECT_RESTORE, KEY_DATA_PROVIDER_RESTORE,
    // INITIALIZE_POLICY, UPDATE_POLICY, SET_MACHINE_PATH_LIST, REISSUE, VRF). A collision is
    // accepted on-chain and then silently never delivered - no error, no revert - so the names
    // below are deliberately domain-specific, and any fourth verb must be checked against that list.
    bytes32 public constant OP_TYPE_EVALUATION = bytes32("EVALUATION");
    bytes32 public constant OP_COMMAND_VALIDATE = bytes32("VALIDATE");
    bytes32 public constant OP_COMMAND_SCORE_JOB = bytes32("SCORE_JOB");
    bytes32 public constant OP_COMMAND_SETTLE_COMP = bytes32("SETTLE_COMP");

    /// Public extension ids start here; everything below is reserved for system extensions, so
    /// discovery scans upward from this floor rather than from zero.
    uint256 private constant FIRST_PUBLIC_EXTENSION_ID = 0x10000;

    ITeeExtensionRegistry public immutable teeExtensionRegistry;
    ITeeMachineRegistry public immutable teeMachineRegistry;

    /// Discovered once, after the extension is registered against this address. Set-once.
    uint256 private _extensionId;

    /// Emitted for every routed instruction so a relayer can follow the id back to the proxy
    /// without decoding registry internals.
    event EvaluationRequested(bytes32 indexed instructionId, bytes32 indexed opCommand, bytes32 indexed subjectId);
    event ExtensionIdSet(uint256 extensionId);

    error ZeroAddress();
    error NotAContract();
    error ExtensionIdAlreadySet();
    error ExtensionIdNotFound();
    error ExtensionIdNotSet();
    error NoTeeAvailable();

    constructor(ITeeExtensionRegistry _teeExtensionRegistry, ITeeMachineRegistry _teeMachineRegistry) {
        if (address(_teeExtensionRegistry) == address(0) || address(_teeMachineRegistry) == address(0)) {
            revert ZeroAddress();
        }
        if (address(_teeExtensionRegistry).code.length == 0 || address(_teeMachineRegistry).code.length == 0) {
            revert NotAContract();
        }
        teeExtensionRegistry = _teeExtensionRegistry;
        teeMachineRegistry = _teeMachineRegistry;
    }

    /// Find the extension id this contract was registered under. Permissionless and set-once: the
    /// registry is the source of truth, so there is nothing here for a caller to influence.
    /// Must be called AFTER `register-extension`, which is why it is not done in the constructor.
    function setExtensionId() external {
        if (_extensionId != 0) revert ExtensionIdAlreadySet();
        uint256 next = teeExtensionRegistry.nextPublicExtensionId();
        for (uint256 i = FIRST_PUBLIC_EXTENSION_ID; i < next; ++i) {
            if (teeExtensionRegistry.getTeeExtensionInstructionsSender(i) == address(this)) {
                _extensionId = i;
                emit ExtensionIdSet(i);
                return;
            }
        }
        revert ExtensionIdNotFound();
    }

    function extensionId() external view returns (uint256) {
        return _getExtensionId();
    }

    /// The extension id, or 0 if `setExtensionId` has not run. Non-reverting so a deploy script can
    /// be re-run without having to guess whether the previous attempt got this far.
    function extensionIdOrZero() external view returns (uint256) {
        return _extensionId;
    }

    /// Ask the enclave whether job `jobId`'s sealed delivery fits its template. The answer comes
    /// back as a signed verdict; `JobEscrow.releasePaymentFromTee` consumes it.
    ///
    /// This is the FCC replacement for the intake engine's private HTTP call to `/validate`. The
    /// question is now public (which job is being checked) but the answer is still only a boolean
    /// plus a reason - the plaintext never leaves the enclave, exactly as before - and it is now
    /// attested rather than trusted because it arrived from the right IP.
    function requestValidate(bytes32 jobId) external payable returns (bytes32 instructionId) {
        instructionId = _send(OP_COMMAND_VALIDATE, jobId);
    }

    /// Ask the enclave to score a paid job at its lifetime end. Reputation only - the escrow was
    /// already settled - so this is safe to leave permissionless.
    function requestScoreJob(bytes32 jobId) external payable returns (bytes32 instructionId) {
        instructionId = _send(OP_COMMAND_SCORE_JOB, jobId);
    }

    /// Ask the enclave to score every entry in a competition and produce the payout split.
    function requestSettleCompetition(bytes32 competitionId) external payable returns (bytes32 instructionId) {
        instructionId = _send(OP_COMMAND_SETTLE_COMP, competitionId);
    }

    /// Route one instruction to a single TEE machine serving this extension.
    ///
    /// `claimBackAddress` is `msg.sender`: the requester funded the instruction, so any refund owed
    /// belongs to them and not to this contract, which holds no balance and has no way to forward it.
    function _send(bytes32 opCommand, bytes32 subjectId) private returns (bytes32 instructionId) {
        address[] memory teeIds = teeMachineRegistry.getRandomTeeIds(_getExtensionId(), 1);
        if (teeIds.length == 0) revert NoTeeAvailable();

        ITeeExtensionRegistry.TeeInstructionParams memory params = ITeeExtensionRegistry.TeeInstructionParams({
            opType: OP_TYPE_EVALUATION,
            opCommand: opCommand,
            message: abi.encode(subjectId),
            cosigners: new address[](0),
            cosignersThreshold: 0,
            claimBackAddress: msg.sender
        });
        instructionId = teeExtensionRegistry.sendInstructions{value: msg.value}(teeIds, params);
        emit EvaluationRequested(instructionId, opCommand, subjectId);
    }

    function _getExtensionId() private view returns (uint256) {
        uint256 id = _extensionId;
        if (id == 0) revert ExtensionIdNotSet();
        return id;
    }
}
