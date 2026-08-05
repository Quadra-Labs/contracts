// SPDX-License-Identifier: MIT
pragma solidity >=0.7.6 <0.9;

/// @title ITeeExtensionRegistry
/// @notice Flare Confidential Compute's instruction router.
///
/// Minimal local copy, matching flare-foundation/fce-extension-scaffold. Replace with the package
/// import once flare-smart-contracts-v2 publishes:
///   import { ITeeExtensionRegistry } from
///     "flare-smart-contracts-v2/contracts/userInterfaces/tee/ITeeExtensionRegistry.sol";
///
/// This is a protocol interface, not ours to redesign - the field order below is the wire contract
/// with Flare's infrastructure.
interface ITeeExtensionRegistry {
    struct TeeInstructionParams {
        bytes32 opType;
        bytes32 opCommand;
        bytes message;
        address[] cosigners;
        uint64 cosignersThreshold;
        address claimBackAddress;
    }

    /// Route an instruction to the given TEE machines. Payable: FCC charges per instruction, so
    /// scoring is not free-per-item for whoever requests it.
    function sendInstructions(address[] calldata _teeIds, TeeInstructionParams calldata _instructionParams)
        external
        payable
        returns (bytes32 _instructionId);

    /// One past the highest allocated public extension id.
    function nextPublicExtensionId() external view returns (uint256);

    /// The on-chain contract registered as the instruction sender for an extension.
    function getTeeExtensionInstructionsSender(uint256 _extensionId) external view returns (address);
}
