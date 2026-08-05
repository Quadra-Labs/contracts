// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.25;

/// @title IFlareContractRegistry
/// @notice Flare's on-chain name service. Deployed at the SAME address on every Flare-family
/// network (Flare, Songbird, Coston, Coston2), which is what makes it safe to hardcode when nothing
/// else is: the address is network-independent, the answers are not.
///
/// This exists so deployment never hardcodes a protocol contract address. Flare's own published
/// docs already carry at least one stale one - the Coston2 `FdcVerification` address in the
/// reference project's notes resolves to a different contract than the registry reports - and a
/// wrong oracle address does not fail loudly. It produces settlements that look verified and are
/// not.
interface IFlareContractRegistry {
    /// Resolve a protocol contract by name, e.g. "FtsoV2", "FlareSystemsManager", "FdcVerification".
    /// Returns the zero address for an unknown name.
    function getContractAddressByName(string calldata _name) external view returns (address);
}
