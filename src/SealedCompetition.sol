// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.25;

import {IFtsoFeedVerifier} from "./interfaces/IFtsoFeedVerifier.sol";
import {FtsoLib} from "./FtsoLib.sol";

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
    /// Agents already folded into this competition's settlement. Set as each entry is processed, so
    /// a repeated agent in `entries[]` cannot take two winner slots or two Passport records.
    mapping(bytes32 => mapping(address => bool)) public recorded;
    /// Prizes credited but not yet withdrawn. Settlement never pushes value to a winner; it credits
    /// here and the winner pulls. One winner whose `receive()` reverts would otherwise revert the
    /// whole settlement transaction, permanently freezing a funded competition.
    mapping(address => uint256) public owed;

    // --- EIP-712 ---------------------------------------------------------------------------------
    // These three strings are the ABI of trust. The TEE signer, this contract and the verify tool
    // must agree on them byte for byte, so they are frozen here and changed only as a coordinated
    // release across every repo that reproduces them.
    //
    // `score` is uint64, not the uint8 a scoring-only market would use, because a PERFORMANCE
    // competition ranks on `PERF_BASE + roi_bps` (around 1e6).
    bytes32 private constant ENTRY_TYPEHASH = keccak256("Entry(address agent,uint64 score)");
    bytes32 private constant SETTLEMENT_TYPEHASH = keccak256(
        "Settlement(bytes32 competitionId,bytes32 receiptHash,uint256 groundTruthValue,Entry[] entries)Entry(address agent,uint64 score)"
    );
    bytes32 private immutable DOMAIN_SEPARATOR;

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
    event PrizeAwarded(bytes32 indexed competitionId, address indexed agent, uint256 rank, uint256 amount);
    event Settled(bytes32 indexed competitionId, bytes32 receiptHash, uint256 winners, uint256 totalPaid);
    /// The full canonical receipt body (the verify tool fetches this; keccak(receipt) == receiptHash).
    event ReceiptPublished(bytes32 indexed competitionId, bytes receipt);
    event PrizeClaimed(address indexed agent, uint256 amount);
    event RemainingWithdrawn(bytes32 indexed competitionId, address indexed to, uint256 amount);

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
    error AlreadyCancelled();
    error NotSettled();
    error NotCreator();
    error BadTeeSignature();
    error BadReceipt();
    error EntryNotJoined();
    error DuplicateEntry();
    error NothingOwed();

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
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("SealedCompetition"),
                keccak256("1"),
                block.chainid,
                address(this)
            )
        );
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

    /// Settlement: only the registered TEE can post it. Double verification: (1) recover the EIP-712
    /// signer and require it is the registered TEE, (2) cross-check `groundTruthValue` against the
    /// FTSO anchor-feed Merkle proof, so even the TEE cannot fabricate the resolution value.
    /// `proof` is public oracle data and is NOT part of the signed struct.
    ///
    /// Every entry must have actually joined. The reference wrote `joined` and `submissions` and then
    /// never read either, so the TEE's entry list was trusted wholesale: it could name addresses that
    /// never staked and never submitted, and those addresses were both paid and written into the
    /// Passport. Quadra got this for free, because its payout set was built from `participants`,
    /// which only joining could populate.
    function settle(
        bytes32 competitionId,
        bytes32 receiptHash,
        uint256 groundTruthValue,
        EntryInput[] calldata entries,
        bytes calldata signature,
        IFtsoFeedVerifier.FeedDataWithProof calldata proof,
        bytes calldata receipt
    ) external nonReentrant {
        Competition storage c = competitions[competitionId];
        if (!c.exists) revert NoCompetition();
        if (c.settled) revert AlreadySettled();
        if (c.cancelled) revert AlreadyCancelled();
        if (block.timestamp < c.resolveAt) revert TooEarly();
        if (keccak256(receipt) != receiptHash) revert BadReceipt();

        {
            address signer = _recoverSettlement(competitionId, receiptHash, groundTruthValue, entries, signature);
            if (signer == address(0) || signer != teeRegistry.activeTeeWallet()) revert BadTeeSignature();
        }
        FtsoLib.checkGroundTruth(ftsoVerifier, groundTruthValue, proof);

        c.settled = true;
        settledReceiptHash[competitionId] = receiptHash;
        _recordEntries(competitionId, c.kind, c.category, entries);
        (uint256 totalPaid, uint256 winners) = _payWinners(competitionId, entries);

        emit ReceiptPublished(competitionId, receipt);
        emit Settled(competitionId, receiptHash, winners, totalPaid);
    }

    /// Validate the entry set and fold it into the Passport.
    ///
    /// Only SCORING competitions write reputation. A PERFORMANCE metric is around 1e6, and the
    /// Passport's Bayesian `overall()` is defined over [0,100] — folding a raw ROI figure into that
    /// track would make the leaderboard meaningless. Performance competitions therefore rank and pay
    /// but do not yet build reputation; a normalization has to be agreed before they can.
    function _recordEntries(bytes32 competitionId, uint8 kind, bytes32 category, EntryInput[] calldata entries)
        private
    {
        for (uint256 i = 0; i < entries.length; i++) {
            address agent = entries[i].agent;
            if (!joined[competitionId][agent]) revert EntryNotJoined();
            if (recorded[competitionId][agent]) revert DuplicateEntry();
            recorded[competitionId][agent] = true;

            if (kind == KIND_SCORING) {
                // Passport bounds this at 100 itself; the cast is safe because anything above the
                // ceiling reverts there rather than truncating here.
                uint64 s = entries[i].score;
                passport.record(agent, category, s > type(uint8).max ? type(uint8).max : uint8(s));
            }
        }
    }

    /// Rank and credit the winners, following Quadra `release_prizes` exactly:
    ///  - an entry qualifies when `score >= threshold` (inclusive),
    ///  - slots are filled in descending score order,
    ///  - TIES GO TO THE ENTRY SEEN FIRST (Move compared with strict `>` over an insertion-ordered
    ///    vector, so the incumbent kept the slot),
    ///  - each share is `floor(prize * pct / 100)` off a snapshot taken BEFORE any payout, so shares
    ///    do not compound,
    ///  - dust and the shares of unfilled slots are forfeited to the leftover pool rather than
    ///    redistributed; the creator reclaims them with `withdrawRemaining`.
    function _payWinners(bytes32 competitionId, EntryInput[] calldata entries)
        private
        returns (uint256 totalPaid, uint256 winners)
    {
        Competition storage c = competitions[competitionId];
        uint256 prize = c.prizePool;
        c.prizePool = 0; // effects before any credit

        uint256 slots = c.splitPct.length;
        uint256 n = entries.length;
        bool[] memory taken = new bool[](n);

        for (uint256 rank = 0; rank < slots; rank++) {
            uint256 best = type(uint256).max;
            for (uint256 i = 0; i < n; i++) {
                if (taken[i]) continue;
                if (entries[i].score < c.threshold) continue;
                // strict `>` keeps the earlier entry on a tie
                if (best == type(uint256).max || entries[i].score > entries[best].score) best = i;
            }
            if (best == type(uint256).max) break; // no qualifying entry left; remaining slots lapse

            taken[best] = true;
            uint256 amount = (prize * c.splitPct[rank]) / PCT_DENOM;
            if (amount > 0) {
                owed[entries[best].agent] += amount;
                totalPaid += amount;
            }
            winners += 1;
            emit PrizeAwarded(competitionId, entries[best].agent, rank, amount);
        }

        c.prizePool = prize - totalPaid; // dust + lapsed slots stay claimable by the creator
    }

    /// Withdraw prizes credited by settlement. Winner-initiated, so a payee that cannot receive
    /// value fails only its own withdrawal.
    function claimPrize() external nonReentrant {
        uint256 amount = owed[msg.sender];
        if (amount == 0) revert NothingOwed();
        owed[msg.sender] = 0;
        (bool ok,) = payable(msg.sender).call{value: amount}("");
        if (!ok) revert TransferFailed();
        emit PrizeClaimed(msg.sender, amount);
    }

    /// The creator reclaims what settlement did not pay out: rounding dust plus the shares of any
    /// winner slots that had no qualifying entry.
    function withdrawRemaining(bytes32 competitionId) external nonReentrant {
        Competition storage c = competitions[competitionId];
        if (!c.exists) revert NoCompetition();
        if (!c.settled) revert NotSettled();
        if (msg.sender != c.creator) revert NotCreator();

        uint256 amount = c.prizePool;
        if (amount == 0) revert NothingOwed();
        c.prizePool = 0;

        (bool ok,) = payable(c.creator).call{value: amount}("");
        if (!ok) revert TransferFailed();
        emit RemainingWithdrawn(competitionId, c.creator, amount);
    }

    function _recoverSettlement(
        bytes32 competitionId,
        bytes32 receiptHash,
        uint256 groundTruthValue,
        EntryInput[] calldata entries,
        bytes calldata signature
    ) private view returns (address) {
        bytes32[] memory entryHashes = new bytes32[](entries.length);
        for (uint256 i = 0; i < entries.length; i++) {
            entryHashes[i] = keccak256(abi.encode(ENTRY_TYPEHASH, entries[i].agent, entries[i].score));
        }
        bytes32 structHash = keccak256(
            abi.encode(
                SETTLEMENT_TYPEHASH,
                competitionId,
                receiptHash,
                groundTruthValue,
                keccak256(abi.encodePacked(entryHashes))
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        return _recover(digest, signature);
    }

    function _recover(bytes32 digest, bytes calldata sig) private pure returns (address) {
        if (sig.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        if (v < 27) v += 27;
        return ecrecover(digest, v, r, s);
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
