// SPDX-License-Identifier: MIT
pragma solidity >=0.7.6 <0.9;

/// @title ITeeMachineRegistry
/// @notice Flare Confidential Compute's registry of TEE machines.
///
/// Minimal local copy, matching flare-foundation/fce-extension-scaffold. Replace with the package
/// import once flare-smart-contracts-v2 publishes.
///
/// Membership here IS the attestation: a machine only appears against an extension after its code
/// hash was whitelisted (`allow-tee-version`) and its Confidential Space attestation was accepted by
/// Flare's data-provider consensus. That is the whole point of migrating onto FCC - the alternative
/// is re-implementing attestation verification in our own contract against owner-set JWKS keys.
interface ITeeMachineRegistry {
    /// Up to `_count` machines currently serving `_extensionId`. Empty if none are available.
    function getRandomTeeIds(uint256 _extensionId, uint256 _count) external view returns (address[] memory);
}
