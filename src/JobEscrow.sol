// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.25;

import {IFtsoFeedVerifier} from "./interfaces/IFtsoFeedVerifier.sol";

interface ITeeRegistry {
    function activeTeeWallet() external view returns (address);
}

interface IPassport {
    function record(address agent, bytes32 category, uint8 score) external;
}

/// @title JobEscrow
/// @notice The paid-job market, ported from Quadra's `intake` + `job_access` modules.
///
/// PAYMENT AND SCORING ARE SEPARATE CONCERNS, on separate clocks. This is the whole design:
///
///   1. `payForJob`      the user escrows native C2FLR to hire ONE agent, and fixes TWO deadlines:
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
contract JobEscrow {
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

    ITeeRegistry public immutable teeRegistry;
    IPassport public immutable passport;
    /// The FTSO anchor-feed verifier used to cross-check the signed ground truth. Zero = dev/skip.
    IFtsoFeedVerifier public immutable ftsoVerifier;

    address public owner;
    address public treasury;
    /// The intake engine: the only address that may release a payment. It decides validity (via the
    /// TEE) off-chain; on-chain that decision is simply trusted, exactly as Quadra trusts IntakeCap.
    address public intake;
    uint16 public feeBps; // platform fee in basis points (default 1000 = 10%), taken on release

    uint16 private constant BPS_DENOM = 10000;

    mapping(bytes32 => Job) public jobs;
    mapping(bytes32 => bytes32) public deliveredHash; // jobId => keccak(ciphertext)
    mapping(bytes32 => bytes32) public scoredReceiptHash;

    // reentrancy mutex (1 = unlocked, 2 = locked); no OpenZeppelin dependency in this repo
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

    error NotOwner();
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
    error TransferFailed();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier nonReentrant() {
        if (_lock != 1) revert Reentrant();
        _lock = 2;
        _;
        _lock = 1;
    }

    constructor(
        address teeRegistry_,
        address passport_,
        address treasury_,
        uint16 feeBps_,
        address ftsoVerifier_,
        address intake_
    ) {
        if (feeBps_ > BPS_DENOM) revert BadFee();
        owner = msg.sender;
        teeRegistry = ITeeRegistry(teeRegistry_);
        passport = IPassport(passport_);
        ftsoVerifier = IFtsoFeedVerifier(ftsoVerifier_);
        treasury = treasury_;
        feeBps = feeBps_;
        intake = intake_;
    }

    /// User escrows `msg.value` to hire `agent` for `jobId`. Records the (user, agent) binding ONCE
    /// per jobId — it can never be rebound, so the job's access can't be hijacked (mirrors Quadra
    /// `job_access::record`, which asserts `!access.contains(job_id)` with EAlreadyBound).
    /// `userPubKey` + `params` are emitted (not stored) so the agent, watching JobPaid, can
    /// envelope-encrypt the result to the user and know what was asked for.
    ///
    /// The two deadlines are independent: an agent might deliver in seconds a forecast that is only
    /// judgeable an hour later, so `lifetimeEnd` may be far past `deliveryDeadline`.
    function payForJob(
        bytes32 jobId,
        address agent,
        string calldata evaluatorId,
        bytes calldata params,
        bytes calldata userPubKey,
        uint64 deliveryDeadline,
        uint64 lifetimeEnd
    ) external payable {
        if (jobs[jobId].user != address(0)) revert JobExists();
        if (agent == address(0)) revert BadAgent();
        if (msg.value == 0) revert NoEscrow();
        if (deliveryDeadline <= block.timestamp) revert BadDeadline();
        if (lifetimeEnd < deliveryDeadline) revert BadDeadline();
        jobs[jobId] = Job({
            user: msg.sender,
            agent: agent,
            category: keccak256(bytes(evaluatorId)),
            escrow: msg.value,
            deliveryDeadline: deliveryDeadline,
            lifetimeEnd: lifetimeEnd,
            delivered: false,
            released: false,
            scored: false
        });
        _emitJobPaid(jobId, agent, evaluatorId, params, userPubKey, deliveryDeadline, lifetimeEnd);
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
        uint64 lifetimeEnd
    ) private {
        emit JobPaid(
            jobId, msg.sender, agent, evaluatorId, msg.value, deliveryDeadline, lifetimeEnd, userPubKey, params
        );
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

        // Effects before interactions.
        uint256 amount = j.escrow;
        j.escrow = 0;
        j.released = true;
        address agent = j.agent;

        // Floor division, so the rounding dust goes to the AGENT, not the treasury — the same
        // direction Quadra `intake::release_payment` rounded.
        uint256 fee = (amount * feeBps) / BPS_DENOM;
        uint256 agentAmount = amount - fee;
        if (fee > 0) {
            (bool okFee,) = payable(treasury).call{value: fee}("");
            if (!okFee) revert TransferFailed();
        }
        (bool okAgent,) = payable(agent).call{value: agentAmount}("");
        if (!okAgent) revert TransferFailed();

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
        try passport.record(agent, category, 0) {}
        catch {
            emit PassportRecordFailed(jobId, agent);
        }
        (bool ok,) = payable(user).call{value: amount}("");
        if (!ok) revert TransferFailed();

        emit JobNotDelivered(jobId, agent, user, amount);
    }

    function setFee(uint16 feeBps_, address treasury_) external onlyOwner {
        if (feeBps_ > BPS_DENOM) revert BadFee();
        feeBps = feeBps_;
        treasury = treasury_;
    }

    function setIntake(address intake_) external onlyOwner {
        intake = intake_;
        emit IntakeChanged(intake_);
    }
}
