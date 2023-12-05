// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import { VerbsAuctionHouseTest } from "./AuctionHouse.t.sol";
import { PausableUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

contract VerbsAuctionHouseMintTest is VerbsAuctionHouseTest {
    function testMintFailureDueToEmptyNFTList() public {
        // Pre-conditions setup to ensure the CultureIndex is empty
        vm.expectEmit(true, true, true, true);
        emit PausableUpgradeable.Paused(address(this));
        auctionHouse.unpause();

        // Expect that the auction is paused due to error
        assertEq(auctionHouse.paused(), true, "Auction house should be paused");
    }

    function testBehaviorOnMintFailureDuringAuctionCreation() public {
        //check auction paused emitted
        vm.expectEmit(true, true, true, true);
        emit PausableUpgradeable.Paused(address(this));

        auctionHouse.unpause();

        (uint256 verbId, uint256 amount, uint256 auctionStartTime, uint256 auctionEndTime, address payable bidder, bool settled) = auctionHouse.auction();

        // Check that auction is not created
        assertEq(verbId, 0);
        assertEq(amount, 0);
        assertEq(auctionStartTime, 0);
        assertEq(auctionEndTime, 0);
        assertEq(bidder, address(0));
        assertEq(settled, false);
    }
}
