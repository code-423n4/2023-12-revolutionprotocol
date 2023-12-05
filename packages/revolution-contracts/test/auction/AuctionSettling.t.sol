// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import { VerbsAuctionHouseTest } from "./AuctionHouse.t.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { ICultureIndex } from "../../src/interfaces/ICultureIndex.sol";
import { IVerbsToken } from "../../src/interfaces/IVerbsToken.sol";

contract VerbsAuctionHouseSettleTest is VerbsAuctionHouseTest {
    // Fallback function to allow contract to receive Ether
    receive() external payable {}

    function testSettlingAuctionWithWinningBid(uint8 nDays) public {
        createDefaultArtPiece();
        auctionHouse.unpause();

        uint256 balanceBefore = address(this).balance;

        uint256 bidAmount = auctionHouse.reservePrice();
        vm.deal(address(11), bidAmount);
        vm.startPrank(address(11));
        auctionHouse.createBid{ value: bidAmount }(0); // Assuming first auction's verbId is 0
        vm.stopPrank();

        vm.warp(block.timestamp + auctionHouse.duration() + nDays); // Fast forward time to end the auction

        createDefaultArtPiece();
        auctionHouse.settleCurrentAndCreateNewAuction();
        vm.roll(block.number + 1);

        uint256 balanceAfter = address(this).balance;

        assertEq(verbs.ownerOf(0), address(11), "Verb should be transferred to the highest bidder");
        // cultureIndex currentVotes of highest bidder should be 10
        assertEq(cultureIndex.getCurrentVotes(address(11)), cultureIndex.erc721VotingTokenWeight() * 1e18, "Highest bidder should have 10 votes");

        uint256 creatorRate = auctionHouse.creatorRateBps();
        uint256 entropyRate = auctionHouse.entropyRateBps();

        //calculate fee
        uint256 amountToOwner = (bidAmount * (10_000 - (creatorRate * entropyRate) / 10_000)) / 10_000;

        //amount spent on governance
        uint256 etherToSpendOnGovernanceTotal = (bidAmount * creatorRate) / 10_000 - (bidAmount * (entropyRate * creatorRate)) / 10_000 / 10_000;
        uint256 feeAmount = tokenEmitter.computeTotalReward(etherToSpendOnGovernanceTotal);

        assertEq(balanceAfter - balanceBefore, amountToOwner - feeAmount, "Bid amount minus entropy should be transferred to the auction house owner");
    }

    function testSettlingAuctionWithNoBids(uint8 nDays) public {
        uint256 verbId = createDefaultArtPiece();
        auctionHouse.unpause();

        vm.warp(block.timestamp + auctionHouse.duration() + nDays); // Fast forward time to end the auction

        // Assuming verbs.burn is called for auctions with no bids
        vm.expectEmit(true, true, true, true);
        emit IVerbsToken.VerbBurned(verbId);

        auctionHouse.settleCurrentAndCreateNewAuction();
    }

    function testSettlingAuctionPrematurely() public {
        createDefaultArtPiece();
        auctionHouse.unpause();

        vm.expectRevert();
        auctionHouse.settleAuction(); // Attempt to settle before the auction ends
    }

    function testTransferFailureAndFallbackToWETH(uint256 amount) public {
        vm.assume(amount > tokenEmitter.minPurchaseAmount());
        vm.assume(amount > auctionHouse.reservePrice());
        vm.assume(amount < tokenEmitter.maxPurchaseAmount());

        createDefaultArtPiece();
        auctionHouse.unpause();

        address recipient = address(new ContractThatRejectsEther());

        auctionHouse.transferOwnership(recipient);

        vm.deal(address(auctionHouse), amount);
        auctionHouse.createBid{ value: amount }(0); // Assuming first auction's verbId is 0

        // Initially, recipient should have 0 ether and 0 WETH
        assertEq(recipient.balance, 0);
        assertEq(IERC20(address(mockWETH)).balanceOf(recipient), 0);

        //go in future
        vm.warp(block.timestamp + auctionHouse.duration() + 1); // Fast forward time to end the auction

        auctionHouse.settleCurrentAndCreateNewAuction();

        // Check if the recipient received WETH instead of Ether
        uint256 creatorRate = auctionHouse.creatorRateBps();
        assertEq(IERC20(address(mockWETH)).balanceOf(recipient), (amount * (10_000 - creatorRate)) / 10_000);
        assertEq(recipient.balance, 0); // Ether balance should still be 0
        //make sure voting weight on culture index is 721 vote weight for winning bidder
        assertEq(cultureIndex.getCurrentVotes(address(this)), cultureIndex.erc721VotingTokenWeight() * 1e18, "Highest bidder should have 10 votes");
    }

    function testTransferToEOA() public {
        createDefaultArtPiece();
        auctionHouse.unpause();

        address recipient = address(0x123); // Some EOA address
        uint256 amount = 1 ether;

        auctionHouse.transferOwnership(recipient);

        vm.deal(address(auctionHouse), amount);
        auctionHouse.createBid{ value: amount }(0); // Assuming first auction's verbId is 0

        // Initially, recipient should have 0 ether
        assertEq(recipient.balance, 0);

        //go in future
        vm.warp(block.timestamp + auctionHouse.duration() + 1); // Fast forward time to end the auction

        auctionHouse.settleCurrentAndCreateNewAuction();

        // Check if the recipient received Ether
        uint256 creatorRate = auctionHouse.creatorRateBps();
        assertEq(recipient.balance, (amount * (10_000 - creatorRate)) / 10_000);
        //make sure voting weight on culture index is 721 vote weight for winning bidder
        assertEq(cultureIndex.getCurrentVotes(address(this)), cultureIndex.erc721VotingTokenWeight() * 1e18, "Highest bidder should have 10 votes");
    }

    function testTransferToContractWithoutReceiveOrFallback(uint256 amount) public {
        vm.assume(amount > tokenEmitter.minPurchaseAmount());
        vm.assume(amount > auctionHouse.reservePrice());
        vm.assume(amount < tokenEmitter.maxPurchaseAmount());

        createDefaultArtPiece();
        auctionHouse.unpause();

        address recipient = address(new ContractWithoutReceiveOrFallback());

        auctionHouse.transferOwnership(recipient);

        vm.deal(address(auctionHouse), amount);
        auctionHouse.createBid{ value: amount }(0); // Assuming first auction's verbId is 0

        // Initially, recipient should have 0 ether and 0 WETH
        assertEq(recipient.balance, 0);
        assertEq(IERC20(address(mockWETH)).balanceOf(recipient), 0);

        //go in future
        vm.warp(block.timestamp + auctionHouse.duration() + 1); // Fast forward time to end the auction

        auctionHouse.settleCurrentAndCreateNewAuction();

        // Check if the recipient received WETH instead of Ether
        uint256 creatorRate = auctionHouse.creatorRateBps();

        assertEq(IERC20(address(mockWETH)).balanceOf(recipient), (amount * (10_000 - creatorRate)) / 10_000);
        assertEq(recipient.balance, 0); // Ether balance should still be 0
        //make sure voting weight on culture index is 721 vote weight for winning bidder
        assertEq(cultureIndex.getCurrentVotes(address(this)), cultureIndex.erc721VotingTokenWeight() * 1e18, "Highest bidder should have 10 votes");
    }

    function testSettlingAuctionWithMultipleCreators(uint8 nCreators) public {
        vm.assume(nCreators > 2);
        vm.assume(nCreators < 100);

        uint256 creatorRate = (auctionHouse.creatorRateBps());
        uint256 entropyRate = (auctionHouse.entropyRateBps());

        address[] memory creatorAddresses = new address[](nCreators);
        uint256[] memory creatorBps = new uint256[](nCreators);
        uint256 totalBps = 0;

        // Assume n creators with equal share
        for (uint256 i = 0; i < nCreators; i++) {
            creatorAddresses[i] = address(uint160(i + 1)); // Example creator addresses
            if (i == nCreators - 1) {
                creatorBps[i] = 10_000 - totalBps;
            } else {
                creatorBps[i] = (10_000) / (nCreators - 1);
            }

            totalBps += creatorBps[i];
        }

        uint256 verbId = createArtPieceMultiCreator(
            "Multi Creator Art",
            "An art piece with multiple creators",
            ICultureIndex.MediaType.IMAGE,
            "ipfs://multi-creator-art",
            "",
            "",
            creatorAddresses,
            creatorBps
        );

        auctionHouse.unpause();

        uint256 bidAmount = auctionHouse.reservePrice();
        vm.deal(address(21_000), bidAmount + 1 ether);
        vm.startPrank(address(21_000));
        auctionHouse.createBid{ value: bidAmount }(verbId);
        vm.stopPrank();

        vm.warp(block.timestamp + auctionHouse.duration() + 1); // Fast forward time to end the auction

        // Track balances before auction settlement
        uint256[] memory balancesBefore = new uint256[](creatorAddresses.length);
        uint256[] memory mockWETHBalancesBefore = new uint256[](creatorAddresses.length);
        uint256[] memory governanceTokenBalancesBefore = new uint256[](creatorAddresses.length);
        for (uint256 i = 0; i < creatorAddresses.length; i++) {
            balancesBefore[i] = address(creatorAddresses[i]).balance;
            governanceTokenBalancesBefore[i] = governanceToken.balanceOf(creatorAddresses[i]);
            mockWETHBalancesBefore[i] = mockWETH.balanceOf(creatorAddresses[i]);
        }

        // Track expected governance token payout
        uint256 etherToSpendOnGovernanceTotal = uint256((bidAmount * creatorRate) / 10_000 - (bidAmount * (entropyRate * creatorRate)) / 10_000 / 10_000);

        uint256 expectedGovernanceTokenPayout = uint256(
            tokenEmitter.getTokenQuoteForEther(etherToSpendOnGovernanceTotal - tokenEmitter.computeTotalReward(etherToSpendOnGovernanceTotal))
        );

        auctionHouse.settleCurrentAndCreateNewAuction();

        //assert auctionHouse balance is 0
        assertEq(address(auctionHouse).balance, 0);

        // Verify each creator's payout
        for (uint256 i = 0; i < creatorAddresses.length; i++) {
            uint256 expectedEtherShare = uint256(((bidAmount) * creatorBps[i] * creatorRate) / 10_000 / 10_000);

            //either the creator gets ETH or WETH
            assertEq(
                address(creatorAddresses[i]).balance - balancesBefore[i] > 0
                    ? address(creatorAddresses[i]).balance - balancesBefore[i]
                    : mockWETH.balanceOf(creatorAddresses[i]) - mockWETHBalancesBefore[i],
                (expectedEtherShare * entropyRate) / 10_000,
                "Incorrect ETH payout for creator"
            );

            assertApproxEqAbs(
                governanceToken.balanceOf(creatorAddresses[i]) - governanceTokenBalancesBefore[i],
                uint256((expectedGovernanceTokenPayout * creatorBps[i]) / 10_000),
                // "Incorrect governance token payout for creator",
                1
            );
        }

        // Verify ownership of the verb
        assertEq(verbs.ownerOf(verbId), address(21_000), "Verb should be transferred to the highest bidder");
        // Verify voting weight on culture index is 721 vote weight for winning bidder
        assertEq(cultureIndex.getCurrentVotes(address(21_000)), cultureIndex.erc721VotingTokenWeight() * 1e18, "Highest bidder should have 10 votes");
    }

    function testSettlingAuctionWithWinningBidAndCreatorPayout(uint256 bidAmount) public {
        vm.assume(bidAmount > tokenEmitter.minPurchaseAmount());
        vm.assume(bidAmount > auctionHouse.reservePrice());
        vm.assume(bidAmount < tokenEmitter.maxPurchaseAmount());

        uint256 verbId = createArtPiece("Art Piece", "A new art piece", ICultureIndex.MediaType.IMAGE, "ipfs://image", "", "", address(0x1), 10_000);

        uint256 creatorRate = auctionHouse.creatorRateBps();
        uint256 entropyRate = auctionHouse.entropyRateBps();

        auctionHouse.unpause();

        vm.deal(address(21_000), bidAmount);
        vm.startPrank(address(21_000));
        auctionHouse.createBid{ value: bidAmount }(verbId);
        vm.stopPrank();

        // Ether going to owner of the auction
        uint256 auctioneerPayment = (bidAmount * (10_000 - creatorRate)) / 10_000;

        //Total amount of ether going to creator
        uint256 creatorPayment = bidAmount - auctioneerPayment;

        //Ether reserved to pay the creator directly
        uint256 creatorDirectPayment = (creatorPayment * entropyRate) / 10_000;

        //Ether reserved to buy creator governance
        uint256 creatorGovernancePayment = creatorPayment - creatorDirectPayment;

        //Get expected protocol fee amount
        uint256 feeAmount = tokenEmitter.computeTotalReward(creatorGovernancePayment);

        vm.warp(block.timestamp + auctionHouse.duration() + 1); // Fast forward time to end the auction

        uint256 expectedGovernanceTokens = uint256(tokenEmitter.getTokenQuoteForEther(creatorGovernancePayment - feeAmount));

        emit log_string("creatorGovernancePayment");
        emit log_uint(creatorGovernancePayment);

        emit log_string("gov minus fee");
        emit log_uint(creatorGovernancePayment - feeAmount);

        emit log_string("expectedGovernanceTokens");
        emit log_uint(expectedGovernanceTokens);

        // Track ETH balances
        uint256 balanceBeforeCreator = address(0x1).balance;
        uint256 balanceBeforeTreasury = address(this).balance;

        auctionHouse.settleCurrentAndCreateNewAuction();

        // Checking if the creator received their share
        assertEq(address(0x1).balance - balanceBeforeCreator, creatorDirectPayment, "Creator did not receive the correct amount of ETH");

        // Checking if the contract received the correct amount
        uint256 expectedContractShare = bidAmount - creatorDirectPayment - feeAmount;
        assertApproxEqAbs(
            address(this).balance - balanceBeforeTreasury,
            expectedContractShare,
            // "Contract did not receive the correct amount of ETH"
            10
        );

        // Checking ownership of the verb
        assertEq(verbs.ownerOf(verbId), address(21_000), "Verb should be transferred to the highest bidder");
        // Checking voting weight on culture index is 721 vote weight for winning bidder
        assertEq(cultureIndex.getCurrentVotes(address(21_000)), cultureIndex.erc721VotingTokenWeight() * 1e18, "Highest bidder should have 10 votes");

        assertEq(governanceToken.balanceOf(address(0x1)), expectedGovernanceTokens, "Creator did not receive the correct amount of governance tokens");
    }
}

contract ContractWithoutReceiveOrFallback {
    // This contract intentionally does not have receive() or fallback()
    // functions to test the behavior of sending Ether to such a contract.
}

contract ContractThatRejectsEther {
    // This contract has a receive() function that reverts any Ether transfers.
    receive() external payable {
        revert("Rejecting Ether transfer");
    }

    // Alternatively, you could use a fallback function that reverts.
    // fallback() external payable {
    //     revert("Rejecting Ether transfer");
    // }
}
