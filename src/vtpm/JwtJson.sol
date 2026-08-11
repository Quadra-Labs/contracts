// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.25;

/// @title JwtJson
/// @notice Minimal JSON field extraction for a Confidential Space attestation payload.
///
/// Adapted from `flare-foundation/flare-vtpm-attestation`'s `ParserUtils` (MIT), re-pragma'd to
/// this repo's solc and extended with the `eat_nonce` handling `TeeRegistry.register` needs. It is
/// NOT a JSON parser and does not try to be one: it finds a literal key pattern and reads to a
/// delimiter.
///
/// THAT IS SAFE HERE ONLY BECAUSE OF WHERE IT SITS, and the reason is worth stating because it
/// stops being true the moment this is reused. The bytes being scanned are a Google-signed JWT
/// payload whose signature has ALREADY been verified by the caller. So the document is not
/// attacker-authored — but two of its fields ARE attacker-influenced, because a workload chooses
/// them: `eat_nonce`, and the container's `env`/`env_override` maps, which echo arbitrary
/// environment variable names and values into the payload.
///
/// That is a real injection surface. A workload that sets an environment variable literally named
/// `image_digest":"sha256:...` would, under a naive first-match scan, be able to make the parser
/// read an image digest of its choosing. Two things defend against it:
///
///   1. `submods.container.image_digest` is read with the LAST match, not the first. The `env` and
///      `env_override` maps are nested INSIDE `submods.container`, appearing after `image_digest`
///      in every observed token, so a forged occurrence there loses to the genuine one. `indexOfLast`
///      exists for exactly this and is not a stylistic choice.
///   2. `eat_nonce` is required to be valid hex of at most 32 bytes. An injected string cannot be
///      both a legal hex nonce and a JSON-breaking payload.
///
/// A caller that ever passes UNVERIFIED bytes to this library has removed the only thing making it
/// sound.
library JwtJson {
    error KeyNotFound(string key);
    error BadHexValue(string key);

    uint256 private constant NOT_FOUND = type(uint256).max;

    /// The first index of `needle` in `haystack`, or NOT_FOUND.
    function indexOf(bytes memory haystack, bytes memory needle) internal pure returns (uint256) {
        if (needle.length == 0 || haystack.length < needle.length) return NOT_FOUND;
        uint256 limit = haystack.length - needle.length;
        for (uint256 i = 0; i <= limit; ++i) {
            bool found = true;
            for (uint256 j = 0; j < needle.length; ++j) {
                if (haystack[i + j] != needle[j]) {
                    found = false;
                    break;
                }
            }
            if (found) return i;
        }
        return NOT_FOUND;
    }

    /// The LAST index of `needle` in `haystack`, or NOT_FOUND. See the header for why this exists.
    function indexOfLast(bytes memory haystack, bytes memory needle) internal pure returns (uint256) {
        if (needle.length == 0 || haystack.length < needle.length) return NOT_FOUND;
        uint256 i = haystack.length - needle.length + 1;
        while (i > 0) {
            --i;
            bool found = true;
            for (uint256 j = 0; j < needle.length; ++j) {
                if (haystack[i + j] != needle[j]) {
                    found = false;
                    break;
                }
            }
            if (found) return i;
        }
        return NOT_FOUND;
    }

    function contains(bytes memory haystack, bytes memory needle) internal pure returns (bool) {
        return indexOf(haystack, needle) != NOT_FOUND;
    }

    function _slice(bytes memory data, uint256 start, uint256 end) private pure returns (bytes memory out) {
        out = new bytes(end - start);
        for (uint256 i = 0; i < out.length; ++i) {
            out[i] = data[start + i];
        }
    }

    /// The value of a `"key":"value"` pair, read to the closing quote. Reverts if absent.
    function stringValue(bytes memory payload, string memory key, bool last)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory pattern = abi.encodePacked('"', bytes(key), '":"');
        uint256 at = last ? indexOfLast(payload, pattern) : indexOf(payload, pattern);
        if (at == NOT_FOUND) revert KeyNotFound(key);
        uint256 start = at + pattern.length;

        for (uint256 i = start; i < payload.length; ++i) {
            // No escape handling: every claim this contract reads (iss, hwmodel, swname,
            // image_digest, sub, eat_nonce) is drawn from a fixed alphabet with no quotes or
            // backslashes, and each is compared against an expected value afterwards. A field
            // carrying an escape simply fails that comparison.
            if (payload[i] == '"') return _slice(payload, start, i);
        }
        revert KeyNotFound(key);
    }

    /// The value of a `"key":<number>` pair. Stops at the first non-digit. Reverts if absent.
    function uintValue(bytes memory payload, string memory key) internal pure returns (uint256 value) {
        bytes memory pattern = abi.encodePacked('"', bytes(key), '":');
        uint256 at = indexOf(payload, pattern);
        if (at == NOT_FOUND) revert KeyNotFound(key);
        uint256 start = at + pattern.length;

        bool any = false;
        for (uint256 i = start; i < payload.length; ++i) {
            uint8 c = uint8(payload[i]);
            if (c < 48 || c > 57) break;
            value = value * 10 + (c - 48);
            any = true;
        }
        if (!any) revert KeyNotFound(key);
    }

    /// The value of a `"key":true|false` pair. Anything that is not exactly `true` reads as false.
    function boolValue(bytes memory payload, string memory key) internal pure returns (bool) {
        bytes memory pattern = abi.encodePacked('"', bytes(key), '":true');
        return contains(payload, pattern);
    }

    /// True when `prefix` is a prefix of `value`.
    function hasPrefix(bytes memory value, bytes memory prefix) internal pure returns (bool) {
        if (prefix.length == 0) return true;
        if (value.length < prefix.length) return false;
        for (uint256 i = 0; i < prefix.length; ++i) {
            if (value[i] != prefix[i]) return false;
        }
        return true;
    }

    /// One hex digit as a nibble. Reverts on anything else.
    function _nibble(bytes1 c, string memory key) private pure returns (uint8) {
        uint8 b = uint8(c);
        if (b >= 48 && b <= 57) return b - 48; // 0-9
        if (b >= 97 && b <= 102) return b - 87; // a-f
        if (b >= 65 && b <= 70) return b - 55; // A-F
        revert BadHexValue(key);
    }

    /// A `0x`-prefixed hex string as a right-aligned bytes32.
    ///
    /// RIGHT-ALIGNED, and lenient about length up to 32 bytes, because Confidential Space accepts
    /// any nonce of 10 to 74 bytes and real tokens carry short ones. The value is only ever
    /// COMPARED against `keccak256(abi.encodePacked(wallet, pubkey))`, so a short nonce simply
    /// yields a bytes32 with leading zeros that no keccak output will ever equal. Left-aligning
    /// instead would silently reject a legitimately short nonce.
    function hexToBytes32(bytes memory value, string memory key) internal pure returns (bytes32) {
        uint256 start = 0;
        if (value.length >= 2 && value[0] == "0" && (value[1] == "x" || value[1] == "X")) start = 2;

        uint256 digits = value.length - start;
        if (digits == 0 || digits > 64) revert BadHexValue(key);

        uint256 acc = 0;
        for (uint256 i = start; i < value.length; ++i) {
            acc = (acc << 4) | _nibble(value[i], key);
        }
        return bytes32(acc);
    }

    /// The `eat_nonce` claim, as bytes32.
    ///
    /// Handles BOTH shapes Google emits: a bare string when one nonce was requested, and an array
    /// when several were. The launcher API takes `nonces` as a list, so which shape comes back
    /// depends on how many were asked for — and a verifier that handled only one of them would
    /// work in testing and fail the first time someone passed two.
    function eatNonce(bytes memory payload) internal pure returns (bytes32) {
        bytes memory arrayPattern = '"eat_nonce":["';
        uint256 at = indexOf(payload, arrayPattern);
        if (at != NOT_FOUND) {
            uint256 start = at + arrayPattern.length;
            for (uint256 i = start; i < payload.length; ++i) {
                if (payload[i] == '"') {
                    return hexToBytes32(_slice(payload, start, i), "eat_nonce");
                }
            }
            revert KeyNotFound("eat_nonce");
        }
        return hexToBytes32(stringValue(payload, "eat_nonce", false), "eat_nonce");
    }
}
