// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import { VerbsAuctionHouseTest } from "./AuctionHouse.t.sol";
import { IVerbsAuctionHouse } from "../../src/interfaces/IVerbsAuctionHouse.sol";
import { wadMul, wadDiv } from "../../src/libs/SignedWadMath.sol";

contract VerbsAuctionHouseBasicTest is VerbsAuctionHouseTest {
    function testEventEmission(uint256 newCreatorRateBps, uint256 newEntropyRateBps) public {
        vm.assume(newCreatorRateBps > auctionHouse.minCreatorRateBps());
        vm.assume(newCreatorRateBps <= 10_000);
        vm.assume(newEntropyRateBps <= 10_000);

        // Expect events when changing creatorRateBps
        vm.expectEmit(true, true, true, true);
        emit IVerbsAuctionHouse.CreatorRateBpsUpdated(newCreatorRateBps);
        auctionHouse.setCreatorRateBps(newCreatorRateBps);

        // Expect events when changing entropyRateBps
        vm.expectEmit(true, true, true, true);
        emit IVerbsAuctionHouse.EntropyRateBpsUpdated(newEntropyRateBps);
        auctionHouse.setEntropyRateBps(newEntropyRateBps);
    }

    function testSetEntropyRateBps(uint256 newEntropyRateBps) public {
        vm.assume(newEntropyRateBps <= 10_000);

        // Expect an event emission
        vm.expectEmit(true, true, true, true);
        emit IVerbsAuctionHouse.EntropyRateBpsUpdated(newEntropyRateBps);

        // Update the rate
        auctionHouse.setEntropyRateBps(newEntropyRateBps);

        // Assert new rate
        assertEq(auctionHouse.entropyRateBps(), newEntropyRateBps);
    }

    function testSetEntropyRateBpsRestrictToOwner() public {
        uint256 newEntropyRateBps = 5000;

        // Attempt to change entropyRateBps as a non-owner
        vm.startPrank(address(2));
        vm.expectRevert();
        auctionHouse.setEntropyRateBps(newEntropyRateBps);
        vm.stopPrank();
    }

    function testSetEntropyRateBpsInvalidValues(uint256 invalidEntropyRateBps) public {
        vm.assume(invalidEntropyRateBps > 10_000);

        // Attempt to set an invalid entropy rate
        vm.expectRevert("Entropy rate must be less than or equal to 10_000");
        auctionHouse.setEntropyRateBps(invalidEntropyRateBps);

        // Assert that the rate was not updated
        assertEq(auctionHouse.entropyRateBps(), 5000);

        int256 invalidEntropyRateBps2 = -1; // Greater than 10,000

        // Attempt to set an invalid entropy rate
        vm.expectRevert();
        auctionHouse.setEntropyRateBps(uint256(invalidEntropyRateBps2));

        // Assert that the rate was not updated
        assertEq(auctionHouse.entropyRateBps(), 5000);
    }

    function testSetMinCreatorRateBps(uint256 newMinCreatorRateBps, uint256 creatorRateBps) public {
        if (creatorRateBps > 10_000) {
            vm.expectRevert("Creator rate must be less than or equal to 10_000");
        } else if (creatorRateBps < auctionHouse.minCreatorRateBps()) {
            vm.expectRevert("Creator rate must be greater than or equal to minCreatorRateBps");
        } else {
            // Expect an event emission
            vm.expectEmit(true, true, true, true);
            emit IVerbsAuctionHouse.CreatorRateBpsUpdated(creatorRateBps);
        }
        auctionHouse.setCreatorRateBps(creatorRateBps);

        //if newMinCreatorRate is greater than creatorRateBps, then expect error
        if (newMinCreatorRateBps > auctionHouse.creatorRateBps()) {
            vm.expectRevert("Min creator rate must be less than or equal to creator rate");
        } else if (newMinCreatorRateBps <= auctionHouse.minCreatorRateBps()) {
            vm.expectRevert("Min creator rate must be greater than previous minCreatorRateBps");
        } else {
            // Expect an event emission
            vm.expectEmit(true, true, true, true);
            emit IVerbsAuctionHouse.MinCreatorRateBpsUpdated(newMinCreatorRateBps);
        }
        // Update the minimum rate
        auctionHouse.setMinCreatorRateBps(newMinCreatorRateBps);

        // Assert new minimum rate
        if (newMinCreatorRateBps <= auctionHouse.creatorRateBps() && newMinCreatorRateBps >= auctionHouse.minCreatorRateBps()) {
            assertEq(auctionHouse.minCreatorRateBps(), newMinCreatorRateBps);
        }
    }

    function testSetMinCreatorRateBpsRestrictToOwner(uint256 newMinCreatorRateBps) public {
        vm.assume(newMinCreatorRateBps < auctionHouse.creatorRateBps());

        // Attempt to change minCreatorRateBps as a non-owner
        vm.startPrank(address(2));
        vm.expectRevert();
        auctionHouse.setMinCreatorRateBps(newMinCreatorRateBps);
        vm.stopPrank();
    }

    function testSetMinCreatorRateBpsInvalidValues(int256 invalidMinCreatorRateBps) public {
        vm.assume(uint256(invalidMinCreatorRateBps) < auctionHouse.creatorRateBps());

        // Attempt to set an invalid minimum creator rate
        if (uint256(invalidMinCreatorRateBps) <= auctionHouse.minCreatorRateBps()) {
            vm.expectRevert("Min creator rate must be greater than previous minCreatorRateBps");
        } else if (uint256(invalidMinCreatorRateBps) > 10_000) {
            vm.expectRevert("Min creator rate must be less than or equal to 10_000");
        }
        auctionHouse.setMinCreatorRateBps(uint256(invalidMinCreatorRateBps));
    }

    function testMinCreatorRateLoweringRestriction(uint256 lowerMinCreatorRateBps) public {
        vm.assume(lowerMinCreatorRateBps < auctionHouse.minCreatorRateBps());

        // Attempt to set a lower minimum creator rate than the current one
        vm.expectRevert("Min creator rate must be greater than previous minCreatorRateBps");
        auctionHouse.setMinCreatorRateBps(lowerMinCreatorRateBps);
    }

    function testValueUpdates(uint256 newCreatorRateBps, uint256 newEntropyRateBps) public {
        vm.assume(newCreatorRateBps > auctionHouse.minCreatorRateBps());
        vm.assume(newCreatorRateBps <= 10_000);
        vm.assume(newEntropyRateBps <= 10_000);

        // Change creatorRateBps as the owner
        auctionHouse.setCreatorRateBps(newCreatorRateBps);
        assertEq(auctionHouse.creatorRateBps(), newCreatorRateBps, "creatorRateBps should be updated");

        // Change entropyRateBps as the owner
        auctionHouse.setEntropyRateBps(newEntropyRateBps);
        assertEq(auctionHouse.entropyRateBps(), newEntropyRateBps, "entropyRateBps should be updated");
    }

    function testOwnerOnlyAccess() public {
        uint256 newCreatorRateBps = 2500;
        uint256 newEntropyRateBps = 6000;

        // Attempt to change creatorRateBps as a non-owner
        vm.startPrank(address(2));
        vm.expectRevert();
        auctionHouse.setCreatorRateBps(newCreatorRateBps);
        vm.stopPrank();

        // Attempt to change entropyRateBps as a non-owner
        vm.startPrank(address(2));
        vm.expectRevert();
        auctionHouse.setEntropyRateBps(newEntropyRateBps);
        vm.stopPrank();
    }

    // Fallback function to allow contract to receive Ether
    receive() external payable {}

    function testInitializationParameters() public {
        assertEq(auctionHouse.WETH(), address(mockWETH), "WETH address should be set correctly");
        assertEq(auctionHouse.timeBuffer(), 15 minutes, "Time buffer should be set correctly");
        assertEq(auctionHouse.reservePrice(), 1 ether, "Reserve price should be set correctly");
        assertEq(auctionHouse.minBidIncrementPercentage(), 5, "Min bid increment percentage should be set correctly");
        assertEq(auctionHouse.duration(), 24 hours, "Auction duration should be set correctly");
    }

    function testAuctionCreation() public {
        createDefaultArtPiece();

        auctionHouse.unpause();
        uint256 startTime = block.timestamp;

        (uint256 verbId, uint256 amount, uint256 auctionStartTime, uint256 auctionEndTime, address payable bidder, bool settled) = auctionHouse.auction();
        assertEq(auctionStartTime, startTime, "Auction start time should be set correctly");
        assertEq(auctionEndTime, startTime + auctionHouse.duration(), "Auction end time should be set correctly");
        assertEq(verbId, 0, "Auction should be for the zeroth verb");
        assertEq(amount, 0, "Auction amount should be 0");
        assertEq(bidder, address(0), "Auction bidder should be 0");
        assertEq(settled, false, "Auction should not be settled");
    }

    function testBiddingProcess(uint256 bidAmount) public {
        vm.assume(bidAmount > auctionHouse.reservePrice());
        vm.assume(bidAmount < 10_000_000 ether);

        createDefaultArtPiece();

        auctionHouse.unpause();
        vm.deal(address(1), bidAmount + 2 ether);

        vm.startPrank(address(1));
        auctionHouse.createBid{ value: bidAmount }(0); // Assuming the first auction's verbId is 0
        (uint256 verbId, uint256 amount, , uint256 endTime, address payable bidder, ) = auctionHouse.auction();

        assertEq(amount, bidAmount, "Bid amount should be set correctly");
        assertEq(bidder, address(1), "Bidder address should be set correctly");
        vm.stopPrank();

        vm.warp(endTime + 1);
        createDefaultArtPiece();
        // Ether going to owner of the auction
        uint256 auctioneerPayment = uint256(wadDiv(wadMul(int256(bidAmount), 10_000 - int256(auctionHouse.creatorRateBps())), 10_000));

        //Total amount of ether going to creator
        uint256 creatorPayment = bidAmount - auctioneerPayment;

        //Ether reserved to pay the creator directly
        uint256 creatorDirectPayment = uint256(wadDiv(wadMul(int256(creatorPayment), int256(auctionHouse.entropyRateBps())), 10_000));

        //Ether reserved to buy creator governance
        uint256 creatorGovernancePayment = creatorPayment - creatorDirectPayment;

        bool shouldExpectRevert = creatorGovernancePayment <= tokenEmitter.minPurchaseAmount() || creatorGovernancePayment >= tokenEmitter.maxPurchaseAmount();

        // // BPS too small to issue rewards
        if (shouldExpectRevert) {
            //expect INVALID_ETH_AMOUNT()
            vm.expectRevert();
        }
        auctionHouse.settleCurrentAndCreateNewAuction(); // This will settle the current auction and create a new one

        if (shouldExpectRevert) {
            (, , , , , bool settled) = auctionHouse.auction();
            assertEq(settled, false, "Auction should not be settled because new one created");
        } else {
            assertEq(verbs.ownerOf(verbId), address(1), "Verb should be transferred to the auction house");
        }
    }

    function testSettlingAuctions() public {
        createDefaultArtPiece();
        auctionHouse.unpause();

        (uint256 verbId, , , uint256 endTime, , ) = auctionHouse.auction();
        assertEq(verbs.ownerOf(verbId), address(auctionHouse), "Verb should be transferred to the auction house");

        vm.warp(endTime + 1);
        uint256 pieceId = createDefaultArtPiece();

        //vote for pieceId
        vm.startPrank(address(auctionHouse));
        vm.roll(block.number + 1);
        cultureIndex.vote(pieceId);

        auctionHouse.settleCurrentAndCreateNewAuction(); // This will settle the current auction and create a new one

        (, , , , , bool settled) = auctionHouse.auction();

        assertEq(settled, false, "Auction should not be settled because new one created");
    }

    function testAdministrativeFunctions(uint256 newTimeBuffer, uint256 newReservePrice, uint8 newMinBidIncrementPercentage) public {
        auctionHouse.setTimeBuffer(newTimeBuffer);
        assertEq(auctionHouse.timeBuffer(), newTimeBuffer, "Time buffer should be updated correctly");

        auctionHouse.setReservePrice(newReservePrice);
        assertEq(auctionHouse.reservePrice(), newReservePrice, "Reserve price should be updated correctly");

        auctionHouse.setMinBidIncrementPercentage(newMinBidIncrementPercentage);
        assertEq(auctionHouse.minBidIncrementPercentage(), newMinBidIncrementPercentage, "Min bid increment percentage should be updated correctly");
    }

    function testAccessControl() public {
        vm.startPrank(address(1));
        vm.expectRevert();
        auctionHouse.pause();
        vm.stopPrank();

        vm.startPrank(address(1));
        vm.expectRevert();
        auctionHouse.unpause();
        vm.stopPrank();
    }
}

contract ContractWithoutReceiveOrFallback {
    // This contract intentionally does not have receive() or fallback()
    // functions to test the behavior of sending Ether to such a contract.
}
