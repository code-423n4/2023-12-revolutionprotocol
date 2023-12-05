// SPDX-License-Identifier: MIT
pragma solidity 0.8.22;

import "forge-std/Test.sol";

import "../src/RevolutionProtocolRewards.sol";
import "./utils/MockTokenEmitter.sol";

contract ProtocolRewardsTest is Test {
    uint256 internal constant ETH_SUPPLY = 120_200_000 ether;

    RevolutionProtocolRewards internal protocolRewards;

    address internal collector;
    address internal builderReferral;
    address internal purchaseReferral;
    address internal deployer;
    address internal revolution;
    address internal treasury;

    function setUp() public virtual {
        protocolRewards = new RevolutionProtocolRewards();

        vm.label(address(protocolRewards), "protocolRewards");

        collector = makeAddr("collector");
        builderReferral = makeAddr("builderReferral");
        purchaseReferral = makeAddr("purchaseReferral");
        deployer = makeAddr("firstMinter");
        revolution = makeAddr("revolution");
        treasury = makeAddr("treasury");
    }
}
