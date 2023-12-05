// SPDX-License-Identifier: MIT
pragma solidity 0.8.22;

import "../ProtocolRewardsTest.sol";
import { RewardsSettings } from "../../src/abstract/RewardSplits.sol";
import { NontransferableERC20Votes } from "../utils/TokenEmitterLibrary.sol";

contract TokenEmitterRewardsTest is ProtocolRewardsTest {
    MockTokenEmitter internal mockTokenEmitter;
    NontransferableERC20Votes internal govToken;

    function setUp() public override {
        super.setUp();

        govToken = new NontransferableERC20Votes(address(this), "Revolution Governance", "GOV");

        mockTokenEmitter = new MockTokenEmitter(address(this), govToken, treasury, address(protocolRewards), revolution);

        govToken.transferOwnership(address(mockTokenEmitter));

        vm.label(address(mockTokenEmitter), "MOCK_TOKENEMITTER");
    }

    function testDeposit(uint256 msgValue) public {
        bool shouldExpectRevert = msgValue <= mockTokenEmitter.minPurchaseAmount() || msgValue >= mockTokenEmitter.maxPurchaseAmount();

        vm.deal(collector, msgValue);

        // array of len 1 addresses
        address[] memory addresses = new address[](1);
        addresses[0] = collector;
        uint[] memory bps = new uint[](1);
        bps[0] = 10_000;

        vm.prank(collector);
        // // BPS too small to issue rewards
        if (shouldExpectRevert) {
            //expect INVALID_ETH_AMOUNT()
            vm.expectRevert();
        }
        mockTokenEmitter.buyToken{ value: msgValue }(addresses, bps, builderReferral, purchaseReferral, deployer);

        if (shouldExpectRevert) {
            vm.expectRevert();
        }
        (RewardsSettings memory settings, uint256 totalReward) = mockTokenEmitter.computePurchaseRewards(msgValue);

        if (!shouldExpectRevert) {
            assertApproxEqAbs(protocolRewards.totalRewardsSupply(), totalReward, 5);
            assertApproxEqAbs(protocolRewards.balanceOf(builderReferral), settings.builderReferralReward, 5);
            assertApproxEqAbs(protocolRewards.balanceOf(purchaseReferral), settings.purchaseReferralReward, 5);
            assertApproxEqAbs(protocolRewards.balanceOf(deployer), settings.deployerReward, 5);
            assertApproxEqAbs(protocolRewards.balanceOf(revolution), settings.revolutionReward, 5);
        }
    }

    function testNullReferralRecipient(uint256 msgValue) public {
        bool shouldExpectRevert = msgValue <= mockTokenEmitter.minPurchaseAmount() || msgValue >= mockTokenEmitter.maxPurchaseAmount();

        NontransferableERC20Votes govToken2 = new NontransferableERC20Votes(address(this), "Revolution Governance", "GOV");

        mockTokenEmitter = new MockTokenEmitter(address(this), govToken2, treasury, address(protocolRewards), revolution);

        govToken2.transferOwnership(address(mockTokenEmitter));

        // array of len 1 addresses
        address[] memory addresses = new address[](1);
        addresses[0] = collector;
        uint[] memory bps = new uint[](1);
        bps[0] = 10_000;

        vm.deal(collector, msgValue);

        vm.prank(collector);
        if (shouldExpectRevert) {
            //expect INVALID_ETH_AMOUNT()
            vm.expectRevert();
        }
        mockTokenEmitter.buyToken{ value: msgValue }(addresses, bps, builderReferral, address(0), deployer);

        if (shouldExpectRevert) {
            //expect INVALID_ETH_AMOUNT()
            vm.expectRevert();
        }
        (RewardsSettings memory settings, uint256 totalReward) = mockTokenEmitter.computePurchaseRewards(msgValue);

        if (!shouldExpectRevert) {
            assertApproxEqAbs(protocolRewards.totalRewardsSupply(), totalReward, 5);
            assertApproxEqAbs(protocolRewards.balanceOf(builderReferral), settings.builderReferralReward, 5);
            assertApproxEqAbs(protocolRewards.balanceOf(deployer), settings.deployerReward, 5);
            assertApproxEqAbs(protocolRewards.balanceOf(revolution), settings.purchaseReferralReward + settings.revolutionReward, 5);
        }
    }

    function testRevertInvalidEth(uint16 msgValue) public {
        vm.assume(msgValue < mockTokenEmitter.minPurchaseAmount() || msgValue > mockTokenEmitter.maxPurchaseAmount());

        vm.expectRevert(abi.encodeWithSignature("INVALID_ETH_AMOUNT()"));
        mockTokenEmitter.computePurchaseRewards(msgValue);
    }
}
