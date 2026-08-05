// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.25;

/// @title Ownable2Step
/// @notice Minimal two-step ownership, shared by every contract in this repo. No OpenZeppelin
/// dependency: the whole point of `lib/` here is one pinned submodule, and this is forty lines.
///
/// This is the replacement for Quadra's capability objects. On Sui, authority was a `Cap` - an
/// unforgeable object held in a wallet, handed over with `transfer::public_transfer`. On the EVM it
/// becomes an address in a storage slot, and that is a genuine downgrade worth naming: a capability
/// cannot be phished, cannot be re-pointed by whoever currently holds the slot, and cannot be lost
/// to a compromised key without the new holder being visible on chain.
///
/// Two-step transfer recovers the part of that which is recoverable. A single-step
/// `transferOwnership` sends authority to an address that may not exist, may not be controlled, or
/// may be a typo - and the mistake is unrecoverable because the old owner has already lost the
/// right to correct it. Requiring the recipient to call `acceptOwnership` proves the key is live
/// before anything moves.
abstract contract Ownable2Step {
    address public owner;
    /// Nominated but not yet in control. Authority does not move until this address accepts.
    address public pendingOwner;

    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    error NotOwner();
    error NotPendingOwner();
    error ZeroAddress();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor() {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    /// Nominate a new owner. Nothing changes until they accept, so a wrong address is harmless and
    /// can simply be overwritten by nominating again.
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    /// Claim ownership. Only the nominated address can call this, which is what proves the key is
    /// live before authority moves.
    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert NotPendingOwner();
        address previous = owner;
        owner = pendingOwner;
        pendingOwner = address(0);
        emit OwnershipTransferred(previous, owner);
    }
}
