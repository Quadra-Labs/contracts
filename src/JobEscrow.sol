// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.25;

import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";
import {IFtsoFeedVerifier} from "./interfaces/IFtsoFeedVerifier.sol";
import {Ownable2Step} from "./Ownable2Step.sol";
import {SignatureLib} from "./SignatureLib.sol";
import {TeeActionResult} from "./TeeActionResult.sol";
import {FtsoLib} from "./FtsoLib.sol";

interface ITeeRegistry {
    function activeTeeWallet() external view returns (address);
}

interface IPassport {
    function record(address agent, bytes32 category, uint8 score, bytes32 sourceId) external;
}

/// @title JobEscrow
/// @notice The paid-job market, ported from Quadra's `intake` + `job_access` modules.
///
/// PAYMENT AND SCORING ARE SEPARATE CONCERNS, on separate clocks. This is the whole design:
///
///   1. `payForJob`      the user escrows QUADRA to hire ONE agent, and fixes TWO deadlines:
///                       `deliveryDeadline` (how long the agent has to hand something in) and
///                       `lifetimeEnd` (when the forecast is judged).
///   2. `deliver`        the agent commits the keccak of its dual-encrypted result.
///   3. `releasePayment` the INTAKE ENGINE, having had the TEE decrypt the delivery and confirm it
///                       fits the job template, pays the agent (cost minus fee). It takes no score
///                       and no oracle data: an agent is paid for delivering valid work on time, NOT
///                       for being right. Anything else and no agent could price a job.
///   4. `refundNotDelivered` if nothing valid arrived by `deliveryDeadline`, the escrow goes back to
///                       the user and the agent is scored 0.
///   5. `scoreJob`       LATER, at `lifetimeEnd`, the evaluation engine posts an EIP-712-signed score
///                       cross-checked against an FTSO anchor proof. Reputation only, no funds move.
///                       (Not in this contract yet — it arrives with the settlement layer.)
///
/// Quadra gates release on an `IntakeCap` object; Flare has no object capabilities, so the same
/// authority is an `intake` address. The Sui "agent registered" check is dropped (on Flare the
/// wallet IS the identity) and the Seal read-ACL collapses into the encryption scheme (the result is
/// envelope-encrypted to user + TEE), so only Quadra's one-time (user, agent) binding survives.
///
/// Units: Quadra measured its refund window in MILLISECONDS (`REFUND_WAIT_MS = 1_800_000`) because
/// Sui's `Clock` is millisecond-resolution. `block.timestamp` is seconds, so every deadline here is
/// a unix SECOND. Carrying a millisecond literal across would turn a 30-minute window into 500 hours.
contract JobEscrow is Ownable2Step {
    using SafeERC20 for IERC20;

    struct Job {
        address user;
        address agent;
        bytes32 category; // keccak256(evaluatorId), the Passport key
        uint256 escrow;
        uint64 deliveryDeadline; // agent must deliver by this, else the escrow refunds
        uint64 lifetimeEnd; // when the evaluation engine scores the job
        bool delivered;
        bool released; // escrow disbursed, in EITHER direction (paid out or refunded)
        bool scored; // the Passport has been written for this job
    }

    /// QUADRA. Jobs are escrowed and paid in it; gas is still native C2FLR.
    IERC20 public immutable token;
    ITeeRegistry public immutable teeRegistry;
    IPassport public immutable passport;
    /// The FTSO anchor-feed verifier used to cross-check the signed ground truth. Zero = dev/skip.
    IFtsoFeedVerifier public immutable ftsoVerifier;

    /// FTSO epoch geometry, so the contract can derive WHICH voting round covers a job's
    /// `lifetimeEnd` and refuse a proof from a different time. Resolved from `FlareSystemsManager`
    /// at deploy and injected — never hardcoded. See `FtsoLib.GroundTruthWindow`.
    uint64 public immutable firstVotingRoundStartTs;
    uint64 public immutable votingEpochDurationSeconds;

    address public treasury;
    /// The intake engine: the only address that may release a payment. It decides validity (via the
    /// TEE) off-chain; on-chain that decision is simply trusted, exactly as Quadra trusts IntakeCap.
    address public intake;
    uint16 public feeBps; // platform fee in basis points (default 1000 = 10%), taken on release

    uint16 private constant BPS_DENOM = 10000;

    /// The app's canonical price precision (1e-8 fixed point), re-exposed from `FtsoLib` so
    /// off-chain code READS this rather than re-declaring 8 independently. FtsoLib's own comment
    /// already promised this getter existed on both markets; it did not, and a silent disagreement
    /// mis-scales every price by a power of ten with no compile signal on either side.
    uint256 public constant PRICE_DECIMALS = FtsoLib.PRICE_DECIMALS;

    mapping(bytes32 => Job) public jobs;
    mapping(bytes32 => bytes32) public deliveredHash; // jobId => keccak(ciphertext)
    mapping(bytes32 => bytes32) public scoredReceiptHash;
    /// Action ids already consumed by an FCC settlement, so a signed result cannot be relayed twice.
    mapping(bytes32 => bool) public consumedActionId;

    // --- EIP-712 ---------------------------------------------------------------------------------
    // Frozen alongside SealedCompetition's typehashes; the TEE signer and the verify tool reproduce
    // this string exactly. `score` stays uint8 here: a paid job is always graded in [0,100], which
    // is the range the Passport stores. Only competitions need the wider ranking value.
    bytes32 private constant JOB_SETTLEMENT_TYPEHASH = keccak256(
        "JobSettlement(bytes32 jobId,bytes32 receiptHash,address agent,uint8 score,uint256 groundTruthValue)"
    );
    bytes32 private immutable DOMAIN_SEPARATOR;

    // reentrancy mutex (1 = unlocked, 2 = locked)
    uint256 private _lock = 1;

    event JobPaid(
        bytes32 indexed jobId,
        address indexed user,
        address indexed agent,
        string evaluatorId,
        uint256 cost,
        uint64 deliveryDeadline,
        uint64 lifetimeEnd,
        bytes userPubKey,
        bytes params
    );
    event Delivered(bytes32 indexed jobId, address indexed agent, bytes32 ciphertextHash);
    /// The intake engine accepted the delivery and paid the agent. Carries no score by design.
    event PaymentReleased(bytes32 indexed jobId, address indexed agent, uint256 agentAmount, uint256 fee);
    event JobNotDelivered(bytes32 indexed jobId, address indexed agent, address indexed user, uint256 refundAmount);
    /// The Passport rejected or reverted on a score write. The refund still went through — see
    /// `refundNotDelivered`. Emitted so the omission is visible on chain rather than silent.
    event PassportRecordFailed(bytes32 indexed jobId, address indexed agent);
    event IntakeChanged(address indexed intake);
    /// The platform fee or its recipient moved. Silent before: a fee change is read at RELEASE time,
    /// not fixed at payment time, so a user has no on-chain record of the terms shifting under them.
    event FeeChanged(uint16 feeBps, address indexed treasury);
    /// The evaluation engine judged the job at lifetime end. Reputation only - no funds move.
    event JobScored(bytes32 indexed jobId, address indexed agent, uint8 score, bytes32 receiptHash);
    /// The full canonical receipt body. A job receipt reveals NOTHING private - only the ciphertext
    /// commitment and the score - so the result stays the user's alpha while its accuracy is public.
    event ReceiptPublished(bytes32 indexed jobId, bytes receipt);

    error NotIntake();
    error NotRefunder();
    error BadFee();
    error JobExists();
    error BadAgent();
    error NoEscrow();
    error BadDeadline();
    error NoJob();
    error NotAgent();
    error AlreadyReleased();
    error NotDelivered();
    error TooEarly();
    error DeadlinePassed();
    error Reentrant();
    error StaleDelivery();
    error AlreadyScored();
    error NotReleased();
    error BadTeeSignature();
    /// The registry has no TEE bound — deliberately revoked, or never wired. Distinct from
    /// `BadTeeSignature` so a paused system is legible and a relayer can stop retrying.
    error TeeRevoked();
    error BadReceipt();
    error DeliveryRejected();
    error ActionIdConsumed();
    /// `userPubKey` is not an uncompressed secp256k1 point, so no agent could ever seal to it.
    error BadUserKey();
    /// `evaluatorId` is empty, which would open a Passport track under `keccak256("")`.
    error BadEvaluator();

    modifier nonReentrant() {
        if (_lock != 1) revert Reentrant();
        _lock = 2;
        _;
        _lock = 1;
    }

    constructor(
        address token_,
        address teeRegistry_,
        address passport_,
        address treasury_,
        uint16 feeBps_,
        address ftsoVerifier_,
        address intake_,
        uint64 firstVotingRoundStartTs_,
        uint64 votingEpochDurationSeconds_
    ) {
        if (feeBps_ > BPS_DENOM) revert BadFee();
        if (token_ == address(0)) revert ZeroAddress();
        if (feeBps_ > 0 && treasury_ == address(0)) revert ZeroAddress();
        // Zero divides by zero in every round calculation, and is only reachable by deploying
        // without resolving the geometry — caught here rather than at the first settlement.
        if (votingEpochDurationSeconds_ == 0) revert FtsoLib.BadVotingEpoch();
        token = IERC20(token_);
        teeRegistry = ITeeRegistry(teeRegistry_);
        passport = IPassport(passport_);
        ftsoVerifier = IFtsoFeedVerifier(ftsoVerifier_);
        firstVotingRoundStartTs = firstVotingRoundStartTs_;
        votingEpochDurationSeconds = votingEpochDurationSeconds_;
        treasury = treasury_;
        feeBps = feeBps_;
        intake = intake_;
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("JobEscrow"),
                keccak256("1"),
                block.chainid,
                address(this)
            )
        );
    }

    /// User escrows `cost` QUADRA to hire `agent` for `jobId` (approve this contract first). Records the (user, agent) binding ONCE
    /// per jobId — it can never be rebound, so the job's access can't be hijacked (mirrors Quadra
    /// `job_access::record`, which asserts `!access.contains(job_id)` with EAlreadyBound).
    /// `userPubKey` + `params` are emitted (not stored) so the agent, watching JobPaid, can
    /// envelope-encrypt the result to the user and know what was asked for.
    ///
    /// The two deadlines are independent: an agent might deliver in seconds a forecast that is only
    /// judgeable an hour later, so `lifetimeEnd` may be far past `deliveryDeadline`.
    ///
    /// `userPubKey` is validated BEFORE the escrow is taken, mirroring Quadra `intake::pay_for_job`,
    /// which failed the buyer on its first statement rather than after taking the coin. The
    /// predicate byte-matches the agent's own `assertUsableUserKey` (`agent/app/src/seal.ts`): an
    /// uncompressed secp256k1 point, 65 bytes starting `0x04`. That guard protects the AGENT's
    /// stake; only the contract can protect the BUYER, who would otherwise fund a job that no agent
    /// can ever deliver to and wait out `deliveryDeadline` for a refund.
    function payForJob(
        bytes32 jobId,
        address agent,
        string calldata evaluatorId,
        bytes calldata params,
        bytes calldata userPubKey,
        uint64 deliveryDeadline,
        uint64 lifetimeEnd,
        uint256 cost
    ) external {
        if (jobs[jobId].user != address(0)) revert JobExists();
        if (agent == address(0)) revert BadAgent();
        if (cost == 0) revert NoEscrow();
        if (deliveryDeadline <= block.timestamp) revert BadDeadline();
        if (lifetimeEnd < deliveryDeadline) revert BadDeadline();
        if (userPubKey.length != 65 || userPubKey[0] != 0x04) revert BadUserKey();
        if (bytes(evaluatorId).length == 0) revert BadEvaluator();
        jobs[jobId] = Job({
            user: msg.sender,
            agent: agent,
            category: keccak256(bytes(evaluatorId)),
            escrow: cost,
            deliveryDeadline: deliveryDeadline,
            lifetimeEnd: lifetimeEnd,
            delivered: false,
            released: false,
            scored: false
        });
        token.safeTransferFrom(msg.sender, address(this), cost);
        _emitJobPaid(jobId, agent, evaluatorId, params, userPubKey, deliveryDeadline, lifetimeEnd, cost);
    }

    /// JobPaid carries nine fields, which overflows the stack if emitted inline alongside the struct
    /// write above. Isolating it keeps payForJob within the stack limit.
    function _emitJobPaid(
        bytes32 jobId,
        address agent,
        string calldata evaluatorId,
        bytes calldata params,
        bytes calldata userPubKey,
        uint64 deliveryDeadline,
        uint64 lifetimeEnd,
        uint256 cost
    ) private {
        emit JobPaid(jobId, msg.sender, agent, evaluatorId, cost, deliveryDeadline, lifetimeEnd, userPubKey, params);
    }

    /// The agent submits the dual-encrypted (to user + TEE) result. Only its keccak commitment is
    /// stored; the ciphertext is in calldata for the user + TEE to read from the tx. The user can
    /// decrypt and read their private result immediately. Re-delivery is allowed until the escrow is
    /// released — a rejected delivery can be corrected while there is still time.
    function deliver(bytes32 jobId, bytes calldata ciphertext) external {
        Job storage j = jobs[jobId];
        if (j.user == address(0)) revert NoJob();
        if (msg.sender != j.agent) revert NotAgent();
        if (j.released) revert AlreadyReleased();
        if (block.timestamp > j.deliveryDeadline) revert DeadlinePassed();
        j.delivered = true;
        deliveredHash[jobId] = keccak256(ciphertext);
        emit Delivered(jobId, j.agent, keccak256(ciphertext));
    }

    /// The intake engine accepted the delivery: pay the agent the cost minus the platform fee.
    /// Mirrors Quadra `intake::release_payment` — capability-gated there, role-gated here, and
    /// deliberately carrying NO score and NO oracle proof.
    ///
    /// `expectedDeliveryHash` is the commitment the TEE actually validated. Because `deliver` may be
    /// called repeatedly until release, without this the intake engine could pay against a validation
    /// of a ciphertext the agent has since replaced: validate good work, swap in anything, get paid.
    /// Binding the payment to the exact bytes that were judged closes that window.
    function releasePayment(bytes32 jobId, bytes32 expectedDeliveryHash) external nonReentrant {
        if (msg.sender != intake) revert NotIntake();
        Job storage j = jobs[jobId];
        if (j.user == address(0)) revert NoJob();
        if (j.released) revert AlreadyReleased();
        if (!j.delivered) revert NotDelivered();
        if (deliveredHash[jobId] != expectedDeliveryHash) revert StaleDelivery();

        _release(jobId);
    }

    /// The payout itself, shared by the role path and the enclave-attested path.
    ///
    /// Deliberately one implementation rather than two: this is the only code that moves a user's
    /// escrow, and two copies of a money path drift. The reference had exactly that - the FCC path
    /// re-implemented the fee split inline instead of calling the role path's.
    function _release(bytes32 jobId) private {
        Job storage j = jobs[jobId];

        // Effects before interactions.
        uint256 amount = j.escrow;
        j.escrow = 0;
        j.released = true;
        address agent = j.agent;

        // Floor division, so the rounding dust goes to the AGENT, not the treasury — the same
        // direction Quadra `intake::release_payment` rounded.
        uint256 fee = (amount * feeBps) / BPS_DENOM;
        uint256 agentAmount = amount - fee;
        if (fee > 0) token.safeTransfer(treasury, fee);
        token.safeTransfer(agent, agentAmount);

        emit PaymentReleased(jobId, agent, agentAmount, fee);
    }

    /// Nothing valid arrived in time: return the escrow to the user and score the agent 0.
    ///
    /// Note this does NOT require `!delivered`. A delivery that failed the template check is worth
    /// no more than no delivery at all, and the alternative — locking the escrow forever whenever a
    /// malformed result was posted — would strand the user's funds. Callable by the intake engine or
    /// by the user themselves, so a stalled intake can never trap a refund.
    ///
    /// The Passport write is deliberately non-fatal. Quadra's `refund_not_delivered` had no
    /// cross-module dependency at all — it simply emitted `agent_score: 0` — whereas here a Passport
    /// that reverts (recorder not yet wired, contract replaced) would take the refund down with it
    /// and trap the user's escrow. Reputation bookkeeping must never outrank returning someone's
    /// money, so a failure is recorded as an event instead.
    function refundNotDelivered(bytes32 jobId) external nonReentrant {
        Job storage j = jobs[jobId];
        if (j.user == address(0)) revert NoJob();
        if (msg.sender != intake && msg.sender != j.user) revert NotRefunder();
        if (j.released) revert AlreadyReleased();
        if (block.timestamp < j.deliveryDeadline) revert TooEarly();

        // Effects.
        uint256 amount = j.escrow;
        j.escrow = 0;
        j.released = true;
        j.scored = true; // the 0 below is this job's final word on reputation
        address user = j.user;
        address agent = j.agent;
        bytes32 category = j.category;

        // Interactions.
        try passport.record(agent, category, 0, jobId) {}
        catch {
            emit PassportRecordFailed(jobId, agent);
        }
        token.safeTransfer(user, amount);

        emit JobNotDelivered(jobId, agent, user, amount);
    }

    /// The evaluation engine's verdict, at lifetime end. Double verification: (1) recover the EIP-712
    /// signer and require it is the registered TEE, (2) cross-check `groundTruthValue` against the
    /// FTSO anchor-feed Merkle proof, so even the TEE cannot fabricate the resolution value.
    /// `proof` is public oracle data and is NOT part of the signed struct.
    ///
    /// MOVES NO FUNDS. The escrow was settled at release time; this only writes reputation, which is
    /// why a keeper outage can no longer strand anyone's money. That separation is the reason a
    /// scoring failure is survivable at all.
    function scoreJob(
        bytes32 jobId,
        bytes32 receiptHash,
        uint8 score,
        uint256 groundTruthValue,
        bytes calldata signature,
        IFtsoFeedVerifier.FeedDataWithProof calldata proof,
        bytes calldata receipt
    ) external {
        Job storage j = jobs[jobId];
        if (j.user == address(0)) revert NoJob();
        if (j.scored) revert AlreadyScored();
        if (!j.released) revert NotReleased(); // an unpaid job is refunded + scored 0, not scored here
        if (block.timestamp < j.lifetimeEnd) revert TooEarly();
        if (keccak256(receipt) != receiptHash) revert BadReceipt();

        {
            // Registry state BEFORE signature state, matching the guard order everywhere else in
            // this file: the terminal condition is asserted first, so a revoked registry says so
            // instead of being reported as a bad signature.
            address tee = _activeTee();
            address signer = _recoverJobSettlement(jobId, receiptHash, j.agent, score, groundTruthValue, signature);
            if (signer == address(0) || signer != tee) revert BadTeeSignature();
        }
        _checkGroundTruth(jobId, groundTruthValue, proof);

        _finishScore(jobId, score, receiptHash, receipt);
    }

    /// Effects tail of scoreJob. Isolated so scoreJob stays within the stack limit.
    function _finishScore(bytes32 jobId, uint8 score, bytes32 receiptHash, bytes calldata receipt) private {
        Job storage j = jobs[jobId];
        j.scored = true;
        scoredReceiptHash[jobId] = receiptHash;
        passport.record(j.agent, j.category, score, jobId);
        emit ReceiptPublished(jobId, receipt);
        emit JobScored(jobId, j.agent, score, receiptHash);
    }

    function _recoverJobSettlement(
        bytes32 jobId,
        bytes32 receiptHash,
        address agent,
        uint8 score,
        uint256 groundTruthValue,
        bytes calldata signature
    ) private view returns (address) {
        bytes32 structHash = keccak256(
            abi.encode(JOB_SETTLEMENT_TYPEHASH, jobId, receiptHash, agent, score, groundTruthValue)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        return SignatureLib.recover(digest, signature);
    }

    // --- Flare Confidential Compute settlement ---------------------------------------------------
    //
    // These sit ALONGSIDE the EIP-712 paths rather than replacing them, on purpose: FCC is
    // documented as pre-production, so the stack keeps settling through the proven path while the
    // extension is stood up. Both converge on `teeRegistry.activeTeeWallet()`, so switching modes is
    // a registry call, not a redeployment.

    /// What the enclave returns for EVALUATION/VALIDATE.
    struct TeeValidation {
        bytes32 jobId;
        bytes32 deliveryHash;
        bool valid;
        string reason;
    }

    /// What the enclave returns for EVALUATION/SCORE_JOB.
    struct TeeJobScore {
        bytes32 jobId;
        bytes32 receiptHash;
        uint8 score;
        uint256 groundTruthValue;
        bytes receipt;
        IFtsoFeedVerifier.FeedDataWithProof proof;
    }

    /// Release the escrow on an enclave-attested validation. Permissionless: the signature is the
    /// authority, so anyone may relay it and a dead relayer cannot strand the agent's payment.
    function releasePaymentFromTee(
        bytes calldata resultData,
        bytes32 actionId,
        string calldata submissionTag,
        uint8 status,
        bytes calldata signature
    ) external nonReentrant {
        _requireTee(resultData, actionId, submissionTag, status, signature);
        TeeValidation memory v = abi.decode(resultData, (TeeValidation));

        Job storage j = jobs[v.jobId];
        if (j.user == address(0)) revert NoJob();
        if (j.released) revert AlreadyReleased();
        if (!j.delivered) revert NotDelivered();
        if (v.deliveryHash != deliveredHash[v.jobId]) revert StaleDelivery();
        if (!v.valid) revert DeliveryRejected();

        _release(v.jobId);
    }

    /// Record an enclave-attested score. Moves no funds.
    function scoreJobFromTee(
        bytes calldata resultData,
        bytes32 actionId,
        string calldata submissionTag,
        uint8 status,
        bytes calldata signature
    ) external {
        _requireTee(resultData, actionId, submissionTag, status, signature);
        TeeJobScore memory s = abi.decode(resultData, (TeeJobScore));

        Job storage j = jobs[s.jobId];
        if (j.user == address(0)) revert NoJob();
        if (j.scored) revert AlreadyScored();
        if (!j.released) revert NotReleased();
        if (block.timestamp < j.lifetimeEnd) revert TooEarly();
        if (keccak256(s.receipt) != s.receiptHash) revert BadReceipt();
        _checkGroundTruth(s.jobId, s.groundTruthValue, s.proof);

        j.scored = true;
        scoredReceiptHash[s.jobId] = s.receiptHash;
        passport.record(j.agent, j.category, s.score, s.jobId);
        emit ReceiptPublished(s.jobId, s.receipt);
        emit JobScored(s.jobId, j.agent, s.score, s.receiptHash);
    }

    /// Verify the result came from the registered TEE machine, and burn its action id.
    ///
    /// The action id guard is ours, not FCC's. The signed digest covers the chain id but NOT a
    /// verifying contract, so a result stays valid against any deployment on this chain that trusts
    /// the same machine. Consuming the id per deployment closes replay within this one, and the
    /// idempotency flags (`released`, `scored`) close the rest.
    function _requireTee(
        bytes calldata resultData,
        bytes32 actionId,
        string calldata submissionTag,
        uint8 status,
        bytes calldata signature
    ) private {
        address tee = _activeTee();
        address signer = TeeActionResult.recoverSigner(resultData, actionId, submissionTag, status, signature);
        if (signer == address(0) || signer != tee) revert BadTeeSignature();
        if (consumedActionId[actionId]) revert ActionIdConsumed();
        consumedActionId[actionId] = true;
    }

    /// The oracle cross-check, bound to the job's OWN lifetime end.
    ///
    /// `lifetimeEnd` is read from STORAGE, never from the settlement payload — it is what the buyer
    /// fixed when they paid, so neither the enclave nor the relayer chooses which instant the proof
    /// is judged against. Without the round bound a paid job scored at lifetime end could settle on
    /// a genuine reading from years earlier, exactly as a competition could (BUGS.md 39).
    function _checkGroundTruth(
        bytes32 jobId,
        uint256 groundTruthValue,
        IFtsoFeedVerifier.FeedDataWithProof memory proof
    ) private view {
        FtsoLib.checkGroundTruth(
            FtsoLib.GroundTruthWindow({
                verifier: ftsoVerifier,
                firstVotingRoundStartTs: firstVotingRoundStartTs,
                votingEpochDurationSeconds: votingEpochDurationSeconds,
                settlementTimeSecs: jobs[jobId].lifetimeEnd
            }),
            groundTruthValue,
            proof
        );
    }

    /// The registered TEE wallet, refusing a revoked (or never-wired) registry by name.
    ///
    /// Without this a zero `activeTeeWallet` reached the `signer != tee` comparison and produced
    /// `BadTeeSignature` — the same error a genuinely bad signature gives — so "the operator
    /// paused settlement" and "this relayer built a bad payload" were indistinguishable from
    /// outside. One is terminal and one is worth retrying, which is precisely the distinction a
    /// keeper needs to make.
    function _activeTee() private view returns (address tee) {
        tee = teeRegistry.activeTeeWallet();
        if (tee == address(0)) revert TeeRevoked();
    }

    /// Move the platform fee or its recipient.
    ///
    /// The zero-treasury guard is gated on the FEE rather than forbidding a zero address outright,
    /// because `_release` only touches the treasury when the fee is non-zero — so zero fee plus
    /// zero treasury is a legitimate fee-free configuration. With a fee set it is not: the payout
    /// would reach `safeTransfer(address(0), fee)`, which the token rejects, and EVERY release
    /// reverts until the owner notices. The buyer still gets a refund, but only for work the agent
    /// actually did.
    function setFee(uint16 feeBps_, address treasury_) external onlyOwner {
        if (feeBps_ > BPS_DENOM) revert BadFee();
        if (feeBps_ > 0 && treasury_ == address(0)) revert ZeroAddress();
        feeBps = feeBps_;
        treasury = treasury_;
        emit FeeChanged(feeBps_, treasury_);
    }

    /// Point at a new intake engine. Zero is rejected rather than treated as "disable releases":
    /// no caller can ever be `address(0)`, so the slot would silently brick `releasePayment` while
    /// still reading as a configured role. Pausing is a different feature and should look like one.
    function setIntake(address intake_) external onlyOwner {
        if (intake_ == address(0)) revert ZeroAddress();
        intake = intake_;
        emit IntakeChanged(intake_);
    }
}
