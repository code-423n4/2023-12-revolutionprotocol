// SPDX-License-Identifier: MIT
pragma solidity 0.8.22;

import { IRevolutionProtocolRewards } from "../interfaces/IRevolutionProtocolRewards.sol";

struct RewardsSettings {
    uint256 builderReferralReward;
    uint256 purchaseReferralReward;
    uint256 deployerReward;
    uint256 revolutionReward;
}

/// @notice Common logic for Revolution TokenEmitter contracts for protocol reward splits & deposits
abstract contract RewardSplits {
    error INVALID_ETH_AMOUNT();

    // 2.5% total
    uint256 internal constant DEPLOYER_REWARD_BPS = 25;
    uint256 internal constant REVOLUTION_REWARD_BPS = 75;
    uint256 internal constant BUILDER_REWARD_BPS = 100;
    uint256 internal constant PURCHASE_REFERRAL_BPS = 50;

    uint256 public constant minPurchaseAmount = 0.0000001 ether;
    uint256 public constant maxPurchaseAmount = 50_000 ether;

    address internal immutable revolutionRewardRecipient;
    IRevolutionProtocolRewards internal immutable protocolRewards;

    constructor(address _protocolRewards, address _revolutionRewardRecipient) payable {
        if (_protocolRewards == address(0) || _revolutionRewardRecipient == address(0)) {
            revert("Invalid Address Zero");
        }

        protocolRewards = IRevolutionProtocolRewards(_protocolRewards);
        revolutionRewardRecipient = _revolutionRewardRecipient;
    }

    /*
     * @notice Sometimes has rounding errors vs. compute purchase rewards, use externally.
     * @param _paymentAmountWei The amount of ETH being paid for the purchase
     */
    function computeTotalReward(uint256 paymentAmountWei) public view returns (uint256) {
        if (paymentAmountWei <= minPurchaseAmount || paymentAmountWei >= maxPurchaseAmount) {
            revert INVALID_ETH_AMOUNT();
        }

        return
            (paymentAmountWei * BUILDER_REWARD_BPS) /
            10_000 +
            (paymentAmountWei * PURCHASE_REFERRAL_BPS) /
            10_000 +
            (paymentAmountWei * DEPLOYER_REWARD_BPS) /
            10_000 +
            (paymentAmountWei * REVOLUTION_REWARD_BPS) /
            10_000;
    }

    function computePurchaseRewards(uint256 paymentAmountWei) public view returns (RewardsSettings memory, uint256) {
        return (
            RewardsSettings({
                builderReferralReward: (paymentAmountWei * BUILDER_REWARD_BPS) / 10_000,
                purchaseReferralReward: (paymentAmountWei * PURCHASE_REFERRAL_BPS) / 10_000,
                deployerReward: (paymentAmountWei * DEPLOYER_REWARD_BPS) / 10_000,
                revolutionReward: (paymentAmountWei * REVOLUTION_REWARD_BPS) / 10_000
            }),
            computeTotalReward(paymentAmountWei)
        );
    }

    function _depositPurchaseRewards(uint256 paymentAmountWei, address builderReferral, address purchaseReferral, address deployer) internal returns (uint256) {
        (RewardsSettings memory settings, uint256 totalReward) = computePurchaseRewards(paymentAmountWei);

        if (builderReferral == address(0)) builderReferral = revolutionRewardRecipient;

        if (deployer == address(0)) deployer = revolutionRewardRecipient;

        if (purchaseReferral == address(0)) purchaseReferral = revolutionRewardRecipient;

        protocolRewards.depositRewards{ value: totalReward }(
            builderReferral,
            settings.builderReferralReward,
            purchaseReferral,
            settings.purchaseReferralReward,
            deployer,
            settings.deployerReward,
            revolutionRewardRecipient,
            settings.revolutionReward
        );

        return totalReward;
    }
}
