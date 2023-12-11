// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import { AuctionHouseTest } from "./AuctionHouse.t.sol";
import { IAuctionHouse } from "../../src/interfaces/IAuctionHouse.sol";
import { wadMul, wadDiv } from "../../src/libs/SignedWadMath.sol";

contract AuctionHouseBasicTest is AuctionHouseTest {
    function testEventEmission(uint256 newCreatorRateBps, uint256 newEntropyRateBps) public {
        vm.assume(newCreatorRateBps > auction.minCreatorRateBps());
        vm.assume(newCreatorRateBps <= 10_000);
        vm.assume(newEntropyRateBps <= 10_000);

        // Expect events when changing creatorRateBps
        vm.expectEmit(true, true, true, true);
        emit IAuctionHouse.CreatorRateBpsUpdated(newCreatorRateBps);
        auction.setCreatorRateBps(newCreatorRateBps);

        // Expect events when changing entropyRateBps
        vm.expectEmit(true, true, true, true);
        emit IAuctionHouse.EntropyRateBpsUpdated(newEntropyRateBps);
        auction.setEntropyRateBps(newEntropyRateBps);
    }

    function testBidEventEmission() public {
        //setup bid
        uint256 bidAmount = 100 ether;
        uint256 verbId = createDefaultArtPiece();

        auction.unpause();
        vm.deal(address(1), bidAmount + 2 ether);
        vm.stopPrank();
        vm.prank(address(1));
        // Expect an event emission
        vm.expectEmit(true, true, true, true);
        emit IAuctionHouse.AuctionBid(verbId, address(21), address(1), bidAmount, false);
        auction.createBid{ value: bidAmount }(0, address(21)); // Assuming the first auction's verbId is 0
    }

    function testSetEntropyRateBps(uint256 newEntropyRateBps) public {
        vm.assume(newEntropyRateBps <= 10_000);

        // Expect an event emission
        vm.expectEmit(true, true, true, true);
        emit IAuctionHouse.EntropyRateBpsUpdated(newEntropyRateBps);

        // Update the rate
        auction.setEntropyRateBps(newEntropyRateBps);

        // Assert new rate
        assertEq(auction.entropyRateBps(), newEntropyRateBps);
    }

    function testSetEntropyRateBpsRestrictToOwner() public {
        uint256 newEntropyRateBps = 5000;

        // Attempt to change entropyRateBps as a non-owner
        vm.stopPrank();
        vm.startPrank(address(2));
        vm.expectRevert();
        auction.setEntropyRateBps(newEntropyRateBps);
        vm.stopPrank();
    }

    function testSetEntropyRateBpsInvalidValues(uint256 invalidEntropyRateBps) public {
        vm.assume(invalidEntropyRateBps > 10_000);

        uint256 oldEntropyRateBps = auction.entropyRateBps();

        // Attempt to set an invalid entropy rate
        vm.expectRevert("Entropy rate must be less than or equal to 10_000");
        auction.setEntropyRateBps(invalidEntropyRateBps);

        // Assert that the rate was not updated
        assertEq(auction.entropyRateBps(), oldEntropyRateBps);

        int256 invalidEntropyRateBps2 = -1; // Greater than 10,000

        // Attempt to set an invalid entropy rate
        vm.expectRevert();
        auction.setEntropyRateBps(uint256(invalidEntropyRateBps2));

        // Assert that the rate was not updated
        assertEq(auction.entropyRateBps(), oldEntropyRateBps);
    }

    function testSetMinCreatorRateBps(uint256 newMinCreatorRateBps, uint256 creatorRateBps) public {
        if (creatorRateBps > 10_000) {
            vm.expectRevert("Creator rate must be less than or equal to 10_000");
        } else if (creatorRateBps < auction.minCreatorRateBps()) {
            vm.expectRevert("Creator rate must be greater than or equal to minCreatorRateBps");
        } else {
            // Expect an event emission
            vm.expectEmit(true, true, true, true);
            emit IAuctionHouse.CreatorRateBpsUpdated(creatorRateBps);
        }
        auction.setCreatorRateBps(creatorRateBps);

        //if newMinCreatorRate is greater than creatorRateBps, then expect error
        if (newMinCreatorRateBps > auction.creatorRateBps()) {
            vm.expectRevert("Min creator rate must be less than or equal to creator rate");
        } else if (newMinCreatorRateBps <= auction.minCreatorRateBps()) {
            vm.expectRevert("Min creator rate must be greater than previous minCreatorRateBps");
        } else {
            // Expect an event emission
            vm.expectEmit(true, true, true, true);
            emit IAuctionHouse.MinCreatorRateBpsUpdated(newMinCreatorRateBps);
        }
        // Update the minimum rate
        auction.setMinCreatorRateBps(newMinCreatorRateBps);

        // Assert new minimum rate
        if (newMinCreatorRateBps <= auction.creatorRateBps() && newMinCreatorRateBps >= auction.minCreatorRateBps()) {
            assertEq(auction.minCreatorRateBps(), newMinCreatorRateBps);
        }
    }

    function testSetMinCreatorRateBpsRestrictToOwner(uint256 newMinCreatorRateBps) public {
        vm.assume(newMinCreatorRateBps < auction.creatorRateBps());

        // Attempt to change minCreatorRateBps as a non-owner
        vm.startPrank(address(2));
        vm.expectRevert();
        auction.setMinCreatorRateBps(newMinCreatorRateBps);
        vm.stopPrank();
    }

    function testSetMinCreatorRateBpsInvalidValues(int256 invalidMinCreatorRateBps) public {
        vm.assume(uint256(invalidMinCreatorRateBps) < auction.creatorRateBps());

        // Attempt to set an invalid minimum creator rate
        if (uint256(invalidMinCreatorRateBps) <= auction.minCreatorRateBps()) {
            vm.expectRevert("Min creator rate must be greater than previous minCreatorRateBps");
        } else if (uint256(invalidMinCreatorRateBps) > 10_000) {
            vm.expectRevert("Min creator rate must be less than or equal to 10_000");
        }
        auction.setMinCreatorRateBps(uint256(invalidMinCreatorRateBps));
    }

    function testMinCreatorRateLoweringRestriction(uint256 lowerMinCreatorRateBps) public {
        vm.assume(lowerMinCreatorRateBps < auction.minCreatorRateBps());

        // Attempt to set a lower minimum creator rate than the current one
        vm.expectRevert("Min creator rate must be greater than previous minCreatorRateBps");
        auction.setMinCreatorRateBps(lowerMinCreatorRateBps);
    }

    function testValueUpdates(uint256 newCreatorRateBps, uint256 newEntropyRateBps) public {
        vm.assume(newCreatorRateBps > auction.minCreatorRateBps());
        vm.assume(newCreatorRateBps <= 10_000);
        vm.assume(newEntropyRateBps <= 10_000);

        // Change creatorRateBps as the owner
        auction.setCreatorRateBps(newCreatorRateBps);
        assertEq(auction.creatorRateBps(), newCreatorRateBps, "creatorRateBps should be updated");

        // Change entropyRateBps as the owner
        auction.setEntropyRateBps(newEntropyRateBps);
        assertEq(auction.entropyRateBps(), newEntropyRateBps, "entropyRateBps should be updated");
    }

    function testOwnerOnlyAccess() public {
        uint256 newCreatorRateBps = 2500;
        uint256 newEntropyRateBps = 6000;

        // Attempt to change creatorRateBps as a non-owner
        vm.stopPrank();
        vm.startPrank(address(2));
        vm.expectRevert();
        auction.setCreatorRateBps(newCreatorRateBps);
        vm.stopPrank();

        // Attempt to change entropyRateBps as a non-owner
        vm.startPrank(address(2));
        vm.expectRevert();
        auction.setEntropyRateBps(newEntropyRateBps);
        vm.stopPrank();
    }

    // Fallback function to allow contract to receive Ether
    receive() external payable {}

    function testInitializationParameters() public {
        emit log_string("testing");
        emit log_address(weth);
        emit log_address(auction.WETH());

        assertEq(auction.WETH(), address(weth), "WETH address should be set correctly");
        assertEq(auction.timeBuffer(), 15 minutes, "Time buffer should be set correctly");
        assertEq(auction.reservePrice(), 1 ether, "Reserve price should be set correctly");
        assertEq(auction.minBidIncrementPercentage(), 5, "Min bid increment percentage should be set correctly");
        assertEq(auction.duration(), 24 hours, "Auction duration should be set correctly");
    }

    function testBidForAnotherAccount() public {
        //setup bid
        uint256 bidAmount = 100 ether;
        uint256 verbId = createDefaultArtPiece();

        auction.unpause();
        vm.deal(address(1), bidAmount + 2 ether);

        vm.stopPrank();

        // try to bid with bidder address(0) first and expect revert
        vm.expectRevert("Bidder cannot be zero address");
        vm.startPrank(address(1));
        auction.createBid{ value: bidAmount }(0, address(0)); // Assuming the first auction's verbId is 0

        // Expect an event emission
        vm.expectEmit(true, true, true, true);
        emit IAuctionHouse.AuctionBid(verbId, address(21), address(1), bidAmount, false);
        auction.createBid{ value: bidAmount }(0, address(21)); // Assuming the first auction's verbId is 0

        // Expect auction bidder to be 21
        (, , , , address payable bidder, ) = auction.auction();
        assertEq(bidder, address(21), "Bidder address should be set correctly");

        // Expect auction amount to be bidAmount
        (, uint256 amount, , , , ) = auction.auction();
        assertEq(amount, bidAmount, "Bid amount should be set correctly");

        // Expect auction settled to be false
        (, , , , , bool settled) = auction.auction();
        assertEq(settled, false, "Auction should not be settled");

        // Expect auction verbId to be 0
        (uint256 verbId2, , , , , ) = auction.auction();
        assertEq(verbId2, 0, "Auction should be for the zeroth verb");

        // Expect auction startTime to be set correctly
        (, , uint256 startTime, , , ) = auction.auction();
        assertEq(startTime, block.timestamp, "Auction start time should be set correctly");

        // Expect auction endTime to be set correctly
        (, , , uint256 endTime, , ) = auction.auction();
        assertEq(endTime, block.timestamp + auction.duration(), "Auction end time should be set correctly");

        // vm warp and then settle auction
        vm.warp(endTime + 1);
        auction.settleCurrentAndCreateNewAuction(); // This will settle the current auction and create a new one

        // Expect 21 to be the owner of the verb
        assertEq(erc721Token.ownerOf(verbId), address(21), "Verb should be transferred to bidder param");
    }

    function testAuctionCreation() public {
        createDefaultArtPiece();

        auction.unpause();
        uint256 startTime = block.timestamp;

        (
            uint256 verbId,
            uint256 amount,
            uint256 auctionStartTime,
            uint256 auctionEndTime,
            address payable bidder,
            bool settled
        ) = auction.auction();
        assertEq(auctionStartTime, startTime, "Auction start time should be set correctly");
        assertEq(auctionEndTime, startTime + auction.duration(), "Auction end time should be set correctly");
        assertEq(verbId, 0, "Auction should be for the zeroth verb");
        assertEq(amount, 0, "Auction amount should be 0");
        assertEq(bidder, address(0), "Auction bidder should be 0");
        assertEq(settled, false, "Auction should not be settled");
    }

    function testBiddingProcess(uint256 bidAmount) public {
        vm.assume(bidAmount > auction.reservePrice());
        vm.assume(bidAmount < 10_000_000 ether);

        createDefaultArtPiece();

        auction.unpause();
        vm.deal(address(1), bidAmount + 2 ether);

        vm.startPrank(address(1));
        auction.createBid{ value: bidAmount }(0, address(1)); // Assuming the first auction's verbId is 0
        (uint256 verbId, uint256 amount, , uint256 endTime, address payable bidder, ) = auction.auction();

        assertEq(amount, bidAmount, "Bid amount should be set correctly");
        assertEq(bidder, address(1), "Bidder address should be set correctly");
        vm.stopPrank();

        vm.warp(endTime + 1);
        createDefaultArtPiece();
        // Ether going to owner of the auction
        uint256 auctioneerPayment = uint256(
            wadDiv(wadMul(int256(bidAmount), 10_000 - int256(auction.creatorRateBps())), 10_000)
        );

        //Total amount of ether going to creator
        uint256 creatorPayment = bidAmount - auctioneerPayment;

        //Ether reserved to pay the creator directly
        uint256 creatorDirectPayment = uint256(
            wadDiv(wadMul(int256(creatorPayment), int256(auction.entropyRateBps())), 10_000)
        );

        //Ether reserved to buy creator governance
        uint256 creatorGovernancePayment = creatorPayment - creatorDirectPayment;

        bool shouldExpectRevert = creatorGovernancePayment <= erc20TokenEmitter.minPurchaseAmount() ||
            creatorGovernancePayment >= erc20TokenEmitter.maxPurchaseAmount();

        // // BPS too small to issue rewards
        if (shouldExpectRevert) {
            //expect INVALID_ETH_AMOUNT()
            vm.expectRevert();
        }
        auction.settleCurrentAndCreateNewAuction(); // This will settle the current auction and create a new one

        if (shouldExpectRevert) {
            (, , , , , bool settled) = auction.auction();
            assertEq(settled, false, "Auction should not be settled because new one created");
        } else {
            assertEq(erc721Token.ownerOf(verbId), address(1), "Verb should be transferred to the auction house");
        }
    }

    // function testSettlingAuctions() public {
    //     createDefaultArtPiece();
    //     auction.unpause();

    //     (uint256 verbId, , , uint256 endTime, , ) = auction.auction();
    //     assertEq(
    //         erc721Token.ownerOf(verbId),
    //         address(auction),
    //         "Verb should be transferred to the auction house"
    //     );

    //     vm.warp(endTime + 1);
    //     uint256 pieceId = createDefaultArtPiece();

    //     //vote for pieceId
    //     vm.startPrank(address(auction));
    //     vm.roll(block.number + 1);
    //     cultureIndex.vote(pieceId);

    //     auction.settleCurrentAndCreateNewAuction(); // This will settle the current auction and create a new one

    //     (, , , , , bool settled) = auction.auction();

    //     assertEq(settled, false, "Auction should not be settled because new one created");
    // }

    // function testAdministrativeFunctions(
    //     uint256 newTimeBuffer,
    //     uint256 newReservePrice,
    //     uint8 newMinBidIncrementPercentage
    // ) public {
    //     auction.setTimeBuffer(newTimeBuffer);
    //     assertEq(auction.timeBuffer(), newTimeBuffer, "Time buffer should be updated correctly");

    //     auction.setReservePrice(newReservePrice);
    //     assertEq(auction.reservePrice(), newReservePrice, "Reserve price should be updated correctly");

    //     auction.setMinBidIncrementPercentage(newMinBidIncrementPercentage);
    //     assertEq(
    //         auction.minBidIncrementPercentage(),
    //         newMinBidIncrementPercentage,
    //         "Min bid increment percentage should be updated correctly"
    //     );
    // }

    // function testAccessControl() public {
    //     vm.startPrank(address(1));
    //     vm.expectRevert();
    //     auction.pause();
    //     vm.stopPrank();

    //     vm.startPrank(address(1));
    //     vm.expectRevert();
    //     auction.unpause();
    //     vm.stopPrank();
    // }
}

contract ContractWithoutReceiveOrFallback {
    // This contract intentionally does not have receive() or fallback()
    // functions to test the behavior of sending Ether to such a contract.
}
