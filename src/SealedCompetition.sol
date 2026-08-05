// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.25;

import {IFtsoFeedVerifier} from "./interfaces/IFtsoFeedVerifier.sol";

interface ITeeRegistry {
    function activeTeeWallet() external view returns (address);
}

interface IPassport {
    function record(address agent, bytes32 category, uint8 score) external;
}

/// @title SealedCompetition
/// @notice The port of Quadra's `competition` module. Agents stake, submit ENCRYPTED predictions
/// (ciphertext lives in calldata; only the TEE can decrypt), and after the resolution time the TEE
/// posts a signed settlement. The contract recovers the signer, checks it is the registered TEE,
/// cross-verifies the ground truth against an FTSO anchor proof, records scores to the Passport and
/// pays out. Sealed inputs in, attested and oracle-verified settlement out.
///
/// Settlement itself lands with the signature layer; this file carries the market mechanics.
///
/// Two resolution modes, both carried over from Quadra:
///  - SCORING (kind 0): each entry is graded in [0,100] and scores ACCUMULATE across recorded jobs.
///  - PERFORMANCE (kind 1): one ROI metric per agent, encoded `metric = PERF_BASE + roi_bps`, which
///    OVERWRITES rather than accumulates so the engine can re-record from the signed end-of-window
///    figure. `threshold = PERF_BASE` therefore means "require ROI >= 0%".
///
/// Because a performance metric is around 1e6, the ranking value is `uint64`, not the `uint8` a
/// pure scoring market would need. That choice is load-bearing: the width is baked into the EIP-712
/// Entry typehash, so widening it later would mean changing this contract, the TEE signer and the
/// verify tool in one atomic release.
contract SealedCompetition {
    struct Competition {
        string evaluatorId;
        bytes32 category; // keccak256(evaluatorId), the Passport key
        uint8 kind; // KIND_SCORING or KIND_PERFORMANCE
        uint256 stake; // what each agent must post to join
        uint256 seedPrize; // the creator's own funding, refundable if the competition is cancelled
        uint256 stakedTotal; // the sum of joiner stakes, tracked apart from the seed
        uint256 prizePool; // native held for this competition == seedPrize + sum(staked)
        uint64 resolveAt;
        uint64 threshold; // entries ranking below this are eliminated from the payout
        bool exists;
        bool settled;
        bool cancelled;
        address creator;
        uint16[] splitPct; // winner split, sums to 100; length = number of winner slots
    }

    /// One agent's ranking value, as signed by the TEE at settlement.
    struct EntryInput {
        address agent;
        uint64 score;
    }

    uint8 public constant KIND_SCORING = 0;
    uint8 public constant KIND_PERFORMANCE = 1;

    /// Zero-ROI baseline for the performance metric: `metric = PERF_BASE + roi_bps`, floored at 0.
    /// 1e6 leaves head-room for the full [-10000, +inf] bps range without underflow at -100% ROI.
    /// The off-chain ROI evaluator MUST use this same encoding.
    uint64 public constant PERF_BASE = 1_000_000;

    /// Winner shares are percentages and must sum to exactly this.
    uint16 private constant PCT_DENOM = 100;

    /// How long after `resolveAt` the TEE has to settle before anyone may cancel and unwind.
    ///
    /// Quadra never needed this: `release_prizes` was permissionless and clock-gated, so liveness
    /// never depended on an off-chain party. Here settlement requires a TEE signature, so without an
    /// escape hatch a dead enclave, a lost key or a rotated wallet would lock every entrant's stake
    /// and the creator's prize forever.
    uint64 public constant CANCEL_WINDOW = 3 days;

    ITeeRegistry public immutable teeRegistry;
    IPassport public immutable passport;
    /// The FTSO anchor-feed verifier used to cross-check the signed ground truth. Zero = dev/skip.
    IFtsoFeedVerifier public immutable ftsoVerifier;

    address public owner;
    /// Who may open a competition. Quadra gated `create_competition` on a `CompetitionCap` object;
    /// Flare has no object capabilities, so the same authority is an address allow-list. The
    /// reference made creation permissionless, which let anyone open a competition under any id and
    /// claim its leftovers.
    mapping(address => bool) public operators;

    mapping(bytes32 => Competition) public competitions;
    mapping(bytes32 => mapping(address => bytes32)) public submissions; // id => agent => ciphertextHash
    mapping(bytes32 => mapping(address => bool)) public joined;
    /// Each agent's own stake, so a cancelled competition can return exactly what each one posted.
    mapping(bytes32 => mapping(address => uint256)) public staked;
    mapping(bytes32 => bytes32) public settledReceiptHash;

    // reentrancy mutex (1 = unlocked, 2 = locked); no OpenZeppelin dependency in this repo
    uint256 private _lock = 1;

    event CompetitionCreated(
        bytes32 indexed competitionId,
        string evaluatorId,
        uint8 kind,
        uint256 stake,
        uint256 seedPrize,
        uint64 resolveAt,
        uint64 threshold
    );
    event Joined(bytes32 indexed competitionId, address indexed agent, uint256 stake);
    event Submitted(bytes32 indexed competitionId, address indexed agent, bytes32 ciphertextHash);
    event Cancelled(bytes32 indexed competitionId, uint256 seedReturned);
    event StakeWithdrawn(bytes32 indexed competitionId, address indexed agent, uint256 amount);
    event OperatorSet(address indexed operator, bool allowed);

    error NotOwner();
    error NotOperator();
    error AlreadyExists();
    error NoCompetition();
    error NotOpen();
    error BadStake();
    error BadSplit();
    error BadKind();
    error BadResolveAt();
    error AlreadyJoined();
    error NotJoined();
    error TooEarly();
    error AlreadySettled();
    error NotCancelled();
    error NothingStaked();
    error Reentrant();
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

    constructor(address teeRegistry_, address passport_, address ftsoVerifier_) {
        owner = msg.sender;
        operators[msg.sender] = true;
        teeRegistry = ITeeRegistry(teeRegistry_);
        passport = IPassport(passport_);
        ftsoVerifier = IFtsoFeedVerifier(ftsoVerifier_);
    }

    function setOperator(address operator, bool allowed) external onlyOwner {
        operators[operator] = allowed;
        emit OperatorSet(operator, allowed);
    }

    /// Open a competition. `splitPct` is the winner split (e.g. [100] winner-take-all, or
    /// [50,30,20] top-3); it must be non-empty and sum to 100. `threshold` eliminates entries
    /// ranking below it from the payout.
    ///
    /// `exists` is an explicit flag rather than a `resolveAt != 0` sentinel. With the sentinel, a
    /// competition created with `resolveAt = 0` absorbed its funding and then read as nonexistent
    /// everywhere, so it could be created again by anyone while its money stayed locked.
    function create(
        bytes32 competitionId,
        string calldata evaluatorId,
        uint8 kind,
        uint256 stake,
        uint64 resolveAt,
        uint64 threshold,
        uint16[] calldata splitPct
    ) external payable {
        if (!operators[msg.sender]) revert NotOperator();
        if (competitions[competitionId].exists) revert AlreadyExists();
        if (kind != KIND_SCORING && kind != KIND_PERFORMANCE) revert BadKind();
        if (!_validSplit(splitPct)) revert BadSplit();
        // A competition born already resolvable can never be joined and never settled, so its
        // funding would be stranded: join reverts NotOpen, and the money only leaves through
        // settlement or cancellation.
        if (resolveAt <= block.timestamp) revert BadResolveAt();

        Competition storage c = competitions[competitionId];
        c.evaluatorId = evaluatorId;
        c.category = keccak256(bytes(evaluatorId));
        c.kind = kind;
        c.stake = stake;
        c.seedPrize = msg.value;
        c.prizePool = msg.value;
        c.resolveAt = resolveAt;
        c.threshold = threshold;
        c.exists = true;
        c.creator = msg.sender;
        c.splitPct = splitPct; // calldata -> storage copy

        emit CompetitionCreated(competitionId, evaluatorId, kind, stake, msg.value, resolveAt, threshold);
    }

    function join(bytes32 competitionId) external payable {
        Competition storage c = competitions[competitionId];
        if (!c.exists) revert NoCompetition();
        if (block.timestamp >= c.resolveAt) revert NotOpen();
        if (msg.value != c.stake) revert BadStake();
        if (joined[competitionId][msg.sender]) revert AlreadyJoined();

        joined[competitionId][msg.sender] = true;
        staked[competitionId][msg.sender] = msg.value;
        c.stakedTotal += msg.value;
        c.prizePool += msg.value;

        emit Joined(competitionId, msg.sender, msg.value);
    }

    /// The prediction stays PRIVATE: only its keccak commitment is stored; the ciphertext is in
    /// calldata for the TEE to read from the tx, decryptable only by the TEE's ECIES key.
    /// Overwritable while the competition is open, so a revised forecast replaces the old one.
    function submitSealed(bytes32 competitionId, bytes calldata ciphertext) external {
        Competition storage c = competitions[competitionId];
        if (!c.exists) revert NoCompetition();
        if (block.timestamp >= c.resolveAt) revert NotOpen();
        if (!joined[competitionId][msg.sender]) revert NotJoined();
        submissions[competitionId][msg.sender] = keccak256(ciphertext);
        emit Submitted(competitionId, msg.sender, keccak256(ciphertext));
    }

    /// The TEE never settled: unwind the competition so nobody's money is trapped.
    ///
    /// Permissionless on purpose. The whole point is to survive the settlement path being
    /// unavailable, so requiring a privileged caller would reintroduce the dependency it exists to
    /// remove. The creator's seed is returned here; each agent reclaims their own stake through
    /// `withdrawStake`, which avoids looping over an unbounded participant set.
    function cancel(bytes32 competitionId) external nonReentrant {
        Competition storage c = competitions[competitionId];
        if (!c.exists) revert NoCompetition();
        if (c.settled) revert AlreadySettled();
        if (block.timestamp < uint256(c.resolveAt) + CANCEL_WINDOW) revert TooEarly();

        c.cancelled = true;
        uint256 seed = c.seedPrize;
        c.seedPrize = 0;
        c.prizePool -= seed;

        if (seed > 0) {
            (bool ok,) = payable(c.creator).call{value: seed}("");
            if (!ok) revert TransferFailed();
        }
        emit Cancelled(competitionId, seed);
    }

    /// Reclaim your own stake from a cancelled competition. Agent-initiated, so one hostile or
    /// broken payee cannot block anyone else's refund.
    function withdrawStake(bytes32 competitionId) external nonReentrant {
        Competition storage c = competitions[competitionId];
        if (!c.exists) revert NoCompetition();
        if (!c.cancelled) revert NotCancelled();

        uint256 amount = staked[competitionId][msg.sender];
        if (amount == 0) revert NothingStaked();

        staked[competitionId][msg.sender] = 0;
        c.stakedTotal -= amount;
        c.prizePool -= amount;

        (bool ok,) = payable(msg.sender).call{value: amount}("");
        if (!ok) revert TransferFailed();
        emit StakeWithdrawn(competitionId, msg.sender, amount);
    }

    /// Non-empty and summing to exactly 100 (Quadra `valid_split`, PCT_DENOM = 100).
    function _validSplit(uint16[] calldata splitPct) internal pure returns (bool) {
        uint256 n = splitPct.length;
        if (n == 0) return false;
        uint256 sum = 0;
        for (uint256 i = 0; i < n; i++) {
            sum += splitPct[i];
        }
        return sum == PCT_DENOM;
    }

    /// The auto-generated `competitions` getter omits the dynamic array, so expose it separately.
    function getSplit(bytes32 competitionId) external view returns (uint16[] memory) {
        return competitions[competitionId].splitPct;
    }
}
