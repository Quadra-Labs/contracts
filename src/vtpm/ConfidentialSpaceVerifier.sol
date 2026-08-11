// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.25;

import {Base64} from "openzeppelin-contracts/contracts/utils/Base64.sol";
import {RSA} from "openzeppelin-contracts/contracts/utils/cryptography/RSA.sol";

import {Ownable2Step} from "../Ownable2Step.sol";
import {IVtpmAttestation} from "../interfaces/IVtpmAttestation.sol";
import {JwtJson} from "./JwtJson.sol";

/// @title ConfidentialSpaceVerifier
/// @notice Verifies a Google Confidential Space attestation JWT on chain, and returns the two
/// claims `TeeRegistry.register` binds on: the container image digest and the `eat_nonce`.
///
/// THIS IS THE CONTRACT THAT MAKES "TEE" A VERIFIED STATEMENT RATHER THAN A CLAIM. Without it the
/// only way to bind a settlement signer is `setActiveTee`, an owner transaction asserting that a
/// key belongs to an enclave — which is a trusted operator wearing the word "TEE". With it, the
/// chain itself checks that the key was generated inside a genuine AMD SEV-SNP VM, running an
/// image whose digest matches the one registered, with secure boot on, and that the token was
/// minted for that exact key.
///
/// The design is a deliberate simplification of `flare-foundation/flare-vtpm-attestation`, whose
/// signature path (OpenZeppelin `Base64.encodeURL` + `RSA.pkcs1Sha256`) this reuses verbatim
/// because it is the correct and audited way to do RS256 in Solidity. What is dropped: the UUPS
/// proxy pair, the initializer plumbing, the per-sender quote registry and the pluggable token-type
/// verifiers. Those serve a general-purpose attestation service. This is one function called by one
/// contract, and every one of them would be an upgrade path or a storage slot to reason about.
/// What is ADDED is the `eat_nonce` extraction, which upstream never surfaces and which is the
/// whole reason a token cannot be replayed to bind a different key.
///
/// TRUST ASSUMPTIONS, stated plainly because the submission has to:
///
///   1. The JWKS is OWNER-SET. Google publishes its signing keys at a well-known URL and rotates
///      them; `scripts/syncJwks.ts` mirrors them into this contract. So the root of trust is the
///      owner faithfully mirroring Google, not Google directly. This is the residual trust Flare
///      Confidential Compute removes by replacing it with data-provider consensus, and it is why
///      `TeeRegistry` keeps `registerFccTee` as a third path.
///   2. The image digest pin is only as strong as the build's reproducibility. A digest nobody can
///      independently rebuild attests that SOME image ran, not that the published source did.
///   3. Anyone who can run the same public image in their own Confidential Space project can mint
///      a valid token for their own enclave key. That is not a confidentiality break — their
///      enclave runs the same code and its operator still cannot read the key — but it is a
///      liveness and griefing surface. `requiredSubPrefix` closes it by pinning the GCP project.
contract ConfidentialSpaceVerifier is Ownable2Step, IVtpmAttestation {
    using JwtJson for bytes;

    struct RsaKey {
        bytes exponent;
        bytes modulus;
    }

    /// Google's signing keys, by `kid`. Mirrored from the published JWKS.
    mapping(bytes32 kidHash => RsaKey) private _keys;

    /// `iss` every Confidential Space token carries.
    string public constant ISSUER = "https://confidentialcomputing.googleapis.com";
    /// The only hardware model this accepts. AMD SEV-SNP.
    string public constant HW_MODEL = "GCP_AMD_SEV";
    /// The only software stack this accepts.
    string public constant SW_NAME = "CONFIDENTIAL_SPACE";

    /// Optional `sub` prefix, pinning which GCP project may register. Empty disables the check.
    ///
    /// `sub` is the instance's self link:
    /// `https://www.googleapis.com/compute/v1/projects/<project>/zones/<zone>/instances/<name>`
    /// so a prefix through `<project>` restricts registration to VMs in that project. See trust
    /// assumption 3: without it, anyone running the same public image can bind their own key.
    string public requiredSubPrefix;

    /// Clock skew allowed on `iat`, for a token minted moments before the block that carries it.
    uint256 public constant IAT_SKEW = 5 minutes;

    /// Hard bounds on the JWT parts this will scan.
    ///
    /// `JwtJson.indexOf` / `indexOfLast` are naive substring scans and this contract runs seven of
    /// them over the payload, so the gas cost is O(payload x claims). A real Confidential Space
    /// payload is around 4 KB and verifying one costs ~2.35M gas — comfortably inside Coston2's
    /// block limit, and a ONE-OFF cost per enclave registration rather than a per-settlement one,
    /// which is why the scans are left as they are.
    ///
    /// What was unbounded is the INPUT. `register` is permissionless by design (the token is the
    /// credential, not `msg.sender`), so without a cap any caller can hand this an arbitrarily
    /// long `payload` and make it scan megabytes. That is self-limiting — they burn their own gas
    /// — but it is a needless way to spend a block, and a bound is one comparison.
    ///
    /// 8 KB is double the observed payload, so Google can grow the token materially before this
    /// needs revisiting. If it ever does, raise this AND hunt the claims in one pass instead of
    /// seven; raising it alone moves the gas cost linearly.
    uint256 public constant MAX_PAYLOAD_BYTES = 8192;
    /// The header carries only `alg`, `kid` and `typ`. 1 KB is already generous.
    uint256 public constant MAX_HEADER_BYTES = 1024;

    event KeyAdded(bytes32 indexed kidHash, bytes kid);
    event KeyRemoved(bytes32 indexed kidHash, bytes kid);
    event SubPrefixChanged(string prefix);

    error UnknownKey(bytes kid);
    error BadSignature();
    error TokenExpired(uint256 exp, uint256 nowTs);
    error TokenNotYetValid(uint256 iat, uint256 nowTs);
    error BadIssuer(bytes got);
    error BadHardware(bytes got);
    error BadSoftware(bytes got);
    error SecureBootOff();
    error BadSubject(bytes got);
    error NotAnOidcToken();
    /// A JWT part is longer than this contract will scan. See MAX_PAYLOAD_BYTES.
    error PartTooLong(uint256 got, uint256 max);

    // --- JWKS administration ---------------------------------------------------------------------

    /// Mirror one Google signing key. `exponent` and `modulus` are the raw big-endian bytes of the
    /// JWK's base64url `e` and `n`.
    ///
    /// Re-setting an existing `kid` is allowed and is the normal path: Google republishes a key
    /// unchanged for most of its life, and a sync that had to delete first would leave a window
    /// where no token verifies.
    function setKey(bytes calldata kid, bytes calldata exponent, bytes calldata modulus) external onlyOwner {
        // OZ's pkcs1Sha256 enforces a 2048-bit minimum itself and returns false below it, which
        // would surface here as an unexplained BadSignature at registration time instead of as a
        // rejected key at configuration time.
        require(modulus.length >= 0x100, "modulus under 2048 bits");
        require(exponent.length > 0, "empty exponent");
        bytes32 kidHash = keccak256(kid);
        _keys[kidHash] = RsaKey({exponent: exponent, modulus: modulus});
        emit KeyAdded(kidHash, kid);
    }

    function removeKey(bytes calldata kid) external onlyOwner {
        bytes32 kidHash = keccak256(kid);
        if (_keys[kidHash].modulus.length == 0) revert UnknownKey(kid);
        delete _keys[kidHash];
        emit KeyRemoved(kidHash, kid);
    }

    function hasKey(bytes calldata kid) external view returns (bool) {
        return _keys[keccak256(kid)].modulus.length != 0;
    }

    /// Pin the GCP project allowed to register, or pass "" to allow any. See trust assumption 3.
    function setRequiredSubPrefix(string calldata prefix) external onlyOwner {
        requiredSubPrefix = prefix;
        emit SubPrefixChanged(prefix);
    }

    // --- verification ----------------------------------------------------------------------------

    /// Verify a Confidential Space attestation JWT and return the two claims the registry binds on.
    ///
    /// `header`, `payload` and `signature` are the base64url-DECODED JWT parts, matching what
    /// `evaluation-engine/src/attestation.ts::splitJwt` produces. The signing input is rebuilt by
    /// re-encoding, because a JWT signature covers the ASCII `b64url(header).b64url(payload)`
    /// string rather than the decoded bytes. Decoding and re-encoding round-trips exactly:
    /// base64url is canonical and unpadded here, which is what `Base64.encodeURL` emits.
    ///
    /// Implemented as `view` even though `IVtpmAttestation` declares it non-view. The interface
    /// leaves room for a verifier that records what it saw; this one deliberately does not, so
    /// there is no per-registration storage growth and no state a future bug could corrupt.
    /// Solidity permits the narrowing, and `TeeRegistry` needs no change either way.
    function verifyAttestation(bytes calldata header, bytes calldata payload, bytes calldata signature)
        external
        view
        returns (string memory imageDigest, bytes32 eatNonce)
    {
        // BEFORE the signature check, which is the expensive half: rejecting an oversized part
        // after paying for an RSA verification and a Base64 re-encode would defeat the point.
        if (payload.length > MAX_PAYLOAD_BYTES) revert PartTooLong(payload.length, MAX_PAYLOAD_BYTES);
        if (header.length > MAX_HEADER_BYTES) revert PartTooLong(header.length, MAX_HEADER_BYTES);

        _verifySignature(header, payload, signature);
        _validateClaims(payload);

        // LAST match: `submods.container.env` echoes workload-chosen variable names into the
        // payload after this key, so a first-match scan would let a workload name a variable
        // `image_digest":"sha256:...` and choose its own attested identity. See JwtJson's header.
        imageDigest = string(payload.stringValue("image_digest", true));
        eatNonce = JwtJson.eatNonce(payload);
    }

    function _verifySignature(bytes calldata header, bytes calldata payload, bytes calldata signature)
        private
        view
    {
        // An `x5c` header is the PKI token type, which carries its own certificate chain and needs
        // a completely different validation path. Rejecting it explicitly beats failing later with
        // an unrelated complaint about a missing `kid`.
        if (JwtJson.contains(header, bytes('"x5c"'))) revert NotAnOidcToken();

        bytes memory kid = JwtJson.stringValue(header, "kid", false);
        RsaKey storage key = _keys[keccak256(kid)];
        if (key.modulus.length == 0) revert UnknownKey(kid);

        bytes memory signingInput =
            abi.encodePacked(Base64.encodeURL(header), ".", Base64.encodeURL(payload));

        if (!RSA.pkcs1Sha256(sha256(signingInput), signature, key.exponent, key.modulus)) {
            revert BadSignature();
        }
    }

    function _validateClaims(bytes calldata payload) private view {
        uint256 exp = payload.uintValue("exp");
        if (exp < block.timestamp) revert TokenExpired(exp, block.timestamp);

        uint256 iat = payload.uintValue("iat");
        if (iat > block.timestamp + IAT_SKEW) revert TokenNotYetValid(iat, block.timestamp);

        bytes memory iss = payload.stringValue("iss", false);
        if (keccak256(iss) != keccak256(bytes(ISSUER))) revert BadIssuer(iss);

        bytes memory hwmodel = payload.stringValue("hwmodel", false);
        if (keccak256(hwmodel) != keccak256(bytes(HW_MODEL))) revert BadHardware(hwmodel);

        bytes memory swname = payload.stringValue("swname", false);
        if (keccak256(swname) != keccak256(bytes(SW_NAME))) revert BadSoftware(swname);

        // Secure boot proves the guest booted a Google-signed UEFI chain. A token without it can
        // still be genuine and still be a machine whose boot path was tampered with.
        if (!payload.boolValue("secboot")) revert SecureBootOff();

        bytes memory prefix = bytes(requiredSubPrefix);
        if (prefix.length != 0) {
            bytes memory sub = payload.stringValue("sub", false);
            if (!JwtJson.hasPrefix(sub, prefix)) revert BadSubject(sub);
        }
    }
}
