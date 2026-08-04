// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.25;

/// @title IFtsoFeedVerifier
/// @notice Minimal local mirror of Flare's `FtsoV2Interface` feed-proof verification, so the
/// settlement contracts can independently confirm the ground-truth price the TEE signed against a
/// finalized FTSO anchor feed + Merkle proof — the "double verification" (TEE signature AND oracle
/// proof) at the heart of GOAL 8.1. Defined locally to avoid pulling the whole flare-periphery
/// package; the struct layout MUST match the on-chain FtsoV2 so the `FeedDataWithProof` the TEE
/// fetches from the DA layer (`/api/v0/ftso/anchor-feeds-with-proof`) ABI-encodes identically.
///
/// On Coston2 the real verifier is FtsoV2. Resolve its address at runtime through
/// `ContractRegistry.getFtsoV2()` and inject it at deploy time — never hardcode it. Flare's own
/// published docs carry at least one stale address for a sibling contract.
interface IFtsoFeedVerifier {
    /// One finalized anchor feed reading. `value` is the price in `decimals` fixed point
    /// (price = value / 10**decimals); `id` is the 21-byte feed id (e.g. BTC/USD).
    ///
    /// NOTE on `turnoutBPS`: Flare's own `FtsoV2Interface` and the live DA layer JSON spell this
    /// field `turnoutBIPS`. ABI encoding is positional, so on-chain verification is unaffected and
    /// this local spelling is harmless here — but any off-chain fetcher that keys its JSON parsing
    /// off THIS name reads 0 and silently produces a proof that fails to verify. Off-chain code
    /// must read `turnoutBIPS` (with `turnoutBPS` as a fallback).
    struct FeedData {
        uint32 votingRoundId;
        bytes21 id;
        int32 value;
        uint16 turnoutBPS;
        int8 decimals;
    }

    /// A `FeedData` plus its Merkle proof against the finalized voting-round root.
    struct FeedDataWithProof {
        bytes32[] proof;
        FeedData body;
    }

    /// Verifies the Merkle proof of a finalized FTSO anchor feed. Returns true iff valid.
    function verifyFeedData(FeedDataWithProof calldata _feedData) external view returns (bool);
}
