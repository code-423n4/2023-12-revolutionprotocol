// SPDX-License-Identifier: MIT
pragma solidity 0.8.22;

import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { IRevolutionProtocolRewards } from "./interfaces/IRevolutionProtocolRewards.sol";

// LICENSE
// RevolutionProtocolRewards.sol is a modified version of Zora's ProtocolRewards.sol:
// https://github.com/ourzora/zora-protocol/blob/38e9e788c258426037d9bc8a1e8821bf3ce8acf6/packages/protocol-rewards/src/ProtocolRewards.sol
//
// ProtocolRewards.sol source code Copyright Zora licensed under the MIT license.

/// @title ProtocolRewards
/// @notice Manager of deposits & withdrawals for protocol rewards
contract RevolutionProtocolRewards is IRevolutionProtocolRewards, EIP712 {
    /// @notice The EIP-712 typehash for gasless withdraws
    bytes32 public constant WITHDRAW_TYPEHASH = keccak256("Withdraw(address from,address to,uint256 amount,uint256 nonce,uint256 deadline)");

    /// @notice An account's balance
    mapping(address => uint256) public balanceOf;

    /// @notice An account's nonce for gasless withdraws
    mapping(address => uint256) public nonces;

    constructor() payable EIP712("RevolutionProtocolRewards", "1") {}

    /// @notice The total amount of ETH held in the contract
    function totalRewardsSupply() external view returns (uint256) {
        return address(this).balance;
    }

    /// @notice Generic function to deposit ETH for a recipient, with an optional comment
    /// @param to Address to deposit to
    /// @param to Reason system reason for deposit (used for indexing)
    /// @param comment Optional comment as reason for deposit
    function deposit(address to, bytes4 reason, string calldata comment) external payable {
        if (to == address(0)) revert ADDRESS_ZERO();

        balanceOf[to] += msg.value;

        emit Deposit(msg.sender, to, reason, msg.value, comment);
    }

    /// @notice Generic function to deposit ETH for multiple recipients, with an optional comment
    /// @param recipients recipients to send the amount to, array aligns with amounts
    /// @param amounts amounts to send to each recipient, array aligns with recipients
    /// @param reasons optional bytes4 hash for indexing
    /// @param comment Optional comment to include with purchase
    function depositBatch(address[] calldata recipients, uint256[] calldata amounts, bytes4[] calldata reasons, string calldata comment) external payable {
        uint256 numRecipients = recipients.length;

        if (numRecipients != amounts.length || numRecipients != reasons.length) revert ARRAY_LENGTH_MISMATCH();

        uint256 expectedTotalValue;

        for (uint256 i; i < numRecipients; ) {
            expectedTotalValue += amounts[i];

            unchecked {
                ++i;
            }
        }

        if (msg.value != expectedTotalValue) revert INVALID_DEPOSIT();

        address currentRecipient;
        uint256 currentAmount;

        for (uint256 i; i < numRecipients; ) {
            currentRecipient = recipients[i];
            currentAmount = amounts[i];

            if (currentRecipient == address(0)) revert ADDRESS_ZERO();

            balanceOf[currentRecipient] += currentAmount;

            emit Deposit(msg.sender, currentRecipient, reasons[i], currentAmount, comment);

            unchecked {
                ++i;
            }
        }
    }

    /// @notice Used by Revolution token contracts to deposit protocol rewards
    /// @param builderReferral Builder referral
    /// @param builderReferralReward Builder referral reward
    /// @param purchaseReferral Purchase referral user
    /// @param purchaseReferralReward Purchase referral amount
    /// @param deployer Deployer
    /// @param deployerReward Deployer reward amount
    /// @param revolution Revolution recipient
    /// @param revolutionReward Revolution amount
    function depositRewards(
        address builderReferral,
        uint256 builderReferralReward,
        address purchaseReferral,
        uint256 purchaseReferralReward,
        address deployer,
        uint256 deployerReward,
        address revolution,
        uint256 revolutionReward
    ) external payable {
        if (msg.value != (builderReferralReward + purchaseReferralReward + deployerReward + revolutionReward)) revert INVALID_DEPOSIT();

        unchecked {
            if (builderReferral != address(0)) balanceOf[builderReferral] += builderReferralReward;

            if (purchaseReferral != address(0)) balanceOf[purchaseReferral] += purchaseReferralReward;

            if (deployer != address(0)) balanceOf[deployer] += deployerReward;

            if (revolution != address(0)) balanceOf[revolution] += revolutionReward;
        }

        emit RewardsDeposit(
            builderReferral,
            purchaseReferral,
            deployer,
            revolution,
            msg.sender,
            builderReferralReward,
            purchaseReferralReward,
            deployerReward,
            revolutionReward
        );
    }

    /// @notice Withdraw protocol rewards
    /// @param to Withdraws from msg.sender to this address
    /// @param amount Amount to withdraw (0 for total balance)
    function withdraw(address to, uint256 amount) external {
        if (to == address(0)) revert ADDRESS_ZERO();

        address owner = msg.sender;

        if (amount > balanceOf[owner]) revert INVALID_WITHDRAW();

        if (amount == 0) amount = balanceOf[owner];

        balanceOf[owner] -= amount;

        emit Withdraw(owner, to, amount);

        (bool success, ) = to.call{ value: amount }("");

        if (!success) revert TRANSFER_FAILED();
    }

    /// @notice Withdraw rewards on behalf of an address
    /// @param to The address to withdraw for
    /// @param amount The amount to withdraw (0 for total balance)
    function withdrawFor(address to, uint256 amount) external {
        if (to == address(0)) revert ADDRESS_ZERO();

        if (amount > balanceOf[to]) revert INVALID_WITHDRAW();

        if (amount == 0) amount = balanceOf[to];

        balanceOf[to] -= amount;

        emit Withdraw(to, to, amount);

        (bool success, ) = to.call{ value: amount }("");

        if (!success) revert TRANSFER_FAILED();
    }

    /// @notice Execute a withdraw of protocol rewards via signature
    /// @param from Withdraw from this address
    /// @param to Withdraw to this address
    /// @param amount Amount to withdraw (0 for total balance)
    /// @param deadline Deadline for the signature to be valid
    /// @param v V component of signature
    /// @param r R component of signature
    /// @param s S component of signature
    function withdrawWithSig(address from, address to, uint256 amount, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
        if (block.timestamp > deadline) revert SIGNATURE_DEADLINE_EXPIRED();

        bytes32 withdrawHash;

        unchecked {
            withdrawHash = keccak256(abi.encode(WITHDRAW_TYPEHASH, from, to, amount, nonces[from]++, deadline));
        }

        bytes32 digest = _hashTypedDataV4(withdrawHash);

        address recoveredAddress = ecrecover(digest, v, r, s);

        // Ensure signature is valid
        if (recoveredAddress == address(0) || recoveredAddress != from) revert INVALID_SIGNATURE();

        // Ensure to address is not 0
        if (to == address(0)) revert ADDRESS_ZERO();

        // Ensure amount is not greater than balance
        if (amount > balanceOf[from]) revert INVALID_WITHDRAW();

        // Set amount to balance if 0
        if (amount == 0) amount = balanceOf[from];

        balanceOf[from] -= amount;

        emit Withdraw(from, to, amount);

        (bool success, ) = to.call{ value: amount }("");

        if (!success) {
            revert TRANSFER_FAILED();
        }
    }
}
