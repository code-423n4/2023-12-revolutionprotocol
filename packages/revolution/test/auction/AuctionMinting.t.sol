// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import { AuctionHouseTest } from "./AuctionHouse.t.sol";
import { PausableUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

contract AuctionHouseMintTest is AuctionHouseTest {
    function testMintFailureDueToEmptyNFTList() public {
        // Pre-conditions setup to ensure the CultureIndex is empty
        vm.expectEmit(true, true, true, true);
        emit PausableUpgradeable.Paused(address(dao));
        auction.unpause();

        // Expect that the auction is paused due to error
        assertEq(auction.paused(), true, "Auction house should be paused");
    }

    function testBehaviorOnMintFailureDuringAuctionCreation() public {
        //check auction paused emitted
        vm.expectEmit(true, true, true, true);
        emit PausableUpgradeable.Paused(address(dao));

        auction.unpause();

        (
            uint256 verbId,
            uint256 amount,
            uint256 auctionStartTime,
            uint256 auctionEndTime,
            address payable bidder,
            bool settled
        ) = auction.auction();

        // Check that auction is not created
        assertEq(verbId, 0);
        assertEq(amount, 0);
        assertEq(auctionStartTime, 0);
        assertEq(auctionEndTime, 0);
        assertEq(bidder, address(0));
        assertEq(settled, false);
    }
}
