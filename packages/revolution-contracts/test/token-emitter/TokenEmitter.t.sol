// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import { Test } from "forge-std/Test.sol";
import { unsafeWadDiv } from "../../src/libs/SignedWadMath.sol";
import { TokenEmitter } from "../../src/TokenEmitter.sol";
import { NontransferableERC20Votes } from "../../src/NontransferableERC20Votes.sol";
import { RevolutionProtocolRewards } from "@collectivexyz/protocol-rewards/src/RevolutionProtocolRewards.sol";
import { wadDiv } from "../../src/libs/SignedWadMath.sol";

contract TokenEmitterTest is Test {
    TokenEmitter public emitter;

    event Log(string, uint);

    // 1,000 tokens per day is the target emission
    uint256 tokensPerTimeUnit = 1_000;

    uint256 expectedVolume = tokensPerTimeUnit * 1e18;

    function setUp() public {
        vm.startPrank(address(0));
        RevolutionProtocolRewards protocolRewards = new RevolutionProtocolRewards();

        address treasury = address(21);
        vm.deal(address(0), 100000 ether);
        vm.stopPrank();

        //20% - how much the price decays per unit of time with no sales
        int256 priceDecayPercent = 1e18 / 10;

        NontransferableERC20Votes governanceToken = new NontransferableERC20Votes(address(this), "Revolution Governance", "GOV");

        int256 oneFullTokenTargetPrice = 1 ether;

        //this setup assumes an ideal of 1e21 or 1_000 ETH (1_000 * 1e18) coming into the system per day, token prices will increaase if more ETH comes in
        emitter = new TokenEmitter(
            address(this),
            governanceToken,
            address(protocolRewards),
            address(this),
            treasury,
            oneFullTokenTargetPrice,
            priceDecayPercent,
            //scale by 1e18 the tokens per time unit
            int256(1e18 * tokensPerTimeUnit)
        );

        address emitterAddress = address(emitter);

        governanceToken.transferOwnership(emitterAddress);
    }

    function testTransferTokenContractOwnership() public {
        // makes a token emitter with one nontransferableerc20
        // makes a second with the same one
        // ensures that the second cannot mint and calling buyGovernance fails
        // transfers ownership to the second
        // ensures that the second can mint and calling buyGovernance succeeds

        address treasury = address(0x36);

        // // 0.1 per governance, 10% price decay per day, 100 governance sale target per day
        NontransferableERC20Votes governanceToken = new NontransferableERC20Votes(address(this), "Revolution Governance", "GOV");
        RevolutionProtocolRewards protocolRewards = new RevolutionProtocolRewards();

        TokenEmitter emitter1 = new TokenEmitter(address(this), governanceToken, address(protocolRewards), address(this), treasury, 1e14, 1e17, 1e22);

        TokenEmitter emitter2 = new TokenEmitter(address(this), governanceToken, address(protocolRewards), address(this), treasury, 1e14, 1e17, 1e22);

        governanceToken.transferOwnership(address(emitter1));

        vm.deal(address(this), 100000 ether);

        address[] memory recipients = new address[](1);
        recipients[0] = address(1);

        uint256[] memory bps = new uint256[](1);
        bps[0] = 10_000;

        emitter1.buyToken{ value: 1e18 }(recipients, bps, address(0), address(0), address(0));

        vm.prank(address(emitter1));

        governanceToken.transferOwnership(address(emitter2));

        vm.prank(address(0));
        emitter2.buyToken{ value: 1e18 }(recipients, bps, address(0), address(0), address(0));
    }

    function testBuyTokenWithDifferentRates(uint256 creatorRate, uint256 entropyRate) public {
        // Assume valid rates
        vm.assume(creatorRate <= 10000 && entropyRate <= 10000);

        // Set creator and entropy rates
        emitter.setCreatorRateBps(creatorRate);
        emitter.setEntropyRateBps(entropyRate);
        assertEq(emitter.creatorRateBps(), creatorRate, "Creator rate not set correctly");
        assertEq(emitter.entropyRateBps(), entropyRate, "Entropy rate not set correctly");

        // Setup for buying token
        address[] memory recipients = new address[](1);
        recipients[0] = address(1); // recipient address

        uint256[] memory bps = new uint256[](1);
        bps[0] = 10000; // 100% of the tokens to the recipient

        uint256 valueToSend = 1 ether;
        emitter.setCreatorsAddress(address(80));
        address creatorsAddress = emitter.creatorsAddress();
        uint256 creatorsInitialEthBalance = address(creatorsAddress).balance;

        uint256 feeAmount = emitter.computeTotalReward(valueToSend);

        // Calculate expected ETH sent to creator
        uint256 totalPaymentForCreator = ((valueToSend - feeAmount) * creatorRate) / 10000;
        uint256 expectedCreatorEth = (totalPaymentForCreator * entropyRate) / 10000;

        if(creatorRate == 0) vm.expectRevert("Ether amount must be greater than 0");
        uint256 expectedCreatorTokens = uint(emitter.getTokenQuoteForEther(totalPaymentForCreator - expectedCreatorEth));

        // Perform token purchase
        uint256 tokensSold = emitter.buyToken{ value: valueToSend }(recipients, bps, address(0), address(0), address(0));

        // Verify tokens distributed to creator
        uint256 creatorTokenBalance = emitter.balanceOf(creatorsAddress);
        assertEq(creatorTokenBalance, expectedCreatorTokens, "Creator did not receive correct amount of tokens");

        // Verify ETH sent to creator
        uint256 creatorsNewEthBalance = address(creatorsAddress).balance;
        assertEq(creatorsNewEthBalance - creatorsInitialEthBalance, expectedCreatorEth, "Incorrect ETH amount sent to creator");

        // Verify tokens distributed to recipient
        uint256 recipientTokenBalance = emitter.balanceOf(address(1));
        assertEq(recipientTokenBalance, tokensSold, "Recipient did not receive correct amount of tokens");
    }

    function testBuyingLaterIsBetter() public {
        vm.startPrank(address(0));

        int256 initAmount = emitter.getTokenQuoteForEther(1e18);

        int256 firstPrice = emitter.buyTokenQuote(1e19);

        // solhint-disable-next-line not-rely-on-time
        vm.warp(block.timestamp + (10 days));

        int256 secondPrice = emitter.buyTokenQuote(1e19);

        emit log_int(firstPrice);
        emit log_int(secondPrice);

        int256 laterAmount = emitter.getTokenQuoteForEther(1e18);

        assertGt(laterAmount, initAmount, "Later amount should be greater than initial amount");

        assertLt(secondPrice, firstPrice, "Second price should be less than first price");
    }

    function testBuyToken() public {
        vm.startPrank(address(0));

        address[] memory recipients = new address[](1);
        recipients[0] = address(1);

        uint256[] memory bps = new uint256[](1);
        bps[0] = 10_000;

        emitter.buyToken{ value: 1e18 }(recipients, bps, address(0), address(0), address(0));
        emit Log("Balance: ", emitter.balanceOf(address(1)));
    }

    function testBuyTokenPriceIncreases() public {
        vm.startPrank(address(0));

        address[] memory firstRecipients = new address[](1);
        firstRecipients[0] = address(1);

        address[] memory secondRecipients = new address[](1);
        secondRecipients[0] = address(2);

        uint256[] memory bps = new uint256[](1);
        bps[0] = 10_000;

        emitter.buyToken{ value: 1e18 }(firstRecipients, bps, address(0), address(0), address(0));

        emitter.buyToken{ value: 1e18 }(secondRecipients, bps, address(0), address(0), address(0));

        // should get more expensive
        assertGt(emitter.balanceOf(address(1)), emitter.balanceOf(address(2)));
    }

    // test multiple payouts
    function testPercentagePayouts(uint firstBps) public {
        vm.assume(firstBps < 10000);
        vm.assume(firstBps > 0);
        vm.startPrank(address(0));

        address[] memory recipients = new address[](2);
        recipients[0] = address(1);
        recipients[1] = address(2);

        uint256[] memory bps = new uint256[](2);
        bps[0] = firstBps;
        bps[1] = 10_000 - firstBps;

        // estimate tokens to be emitted
        int256 expectedAmount = emitter.getTokenQuoteForEther(1e18 - emitter.computeTotalReward(1e18));

        emitter.buyToken{ value: 1e18 }(recipients, bps, address(0), address(0), address(0));
        //assert address balances are correct
        //multiply bps by expectedAmount and assert
        assertEq(emitter.balanceOf(address(1)), (firstBps * uint256(expectedAmount)) / 10_000, "First recipient should have correct balance");
        assertEq(emitter.balanceOf(address(2)), ((10_000 - firstBps) * uint256(expectedAmount)) / 10_000, "Second recipient should have correct balance");

        //assert treasury balance is correct
        assertEq(address(emitter.treasury()).balance, 1e18 - emitter.computeTotalReward(1e18), "Treasury should have payment - totalReward in balance");
    }

    // Test to ensure the total basis points add up to 100%
    function testTotalBasisPoints() public {
        vm.startPrank(address(0));

        address[] memory recipients = new address[](2);
        recipients[0] = address(1);
        recipients[1] = address(2);

        // Test case with correct total of 10,000 basis points (100%)
        uint256[] memory correctBps = new uint256[](2);
        correctBps[0] = 5000; // 50%
        correctBps[1] = 5000; // 50%

        int expectedAmount = emitter.getTokenQuoteForEther(1e18 - emitter.computeTotalReward(1e18));
        assertGt(expectedAmount, 0, "Token purchase should have a positive amount");

        // Attempting a valid token purchase
        uint emittedWad = emitter.buyToken{ value: 1e18 }(recipients, correctBps, address(0), address(0), address(0));
        int totalSupplyAfterValidPurchase = int(emitter.totalSupply());
        assertEq(totalSupplyAfterValidPurchase, expectedAmount, "Supply should match the expected amount");
        //emitted should match expected
        assertEq(int(emittedWad), expectedAmount, "Emitted amount should match expected amount");
        //emitted should match supply
        assertEq(int(emittedWad), totalSupplyAfterValidPurchase, "Emitted amount should match total supply");

        //expect treasury to have payment - totalReward in balance
        assertEq(address(emitter.treasury()).balance, 1e18 - emitter.computeTotalReward(1e18), "Treasury should have payment - totalReward in balance");

        // Test case with incorrect total of basis points
        uint256[] memory incorrectBps = new uint256[](2);
        incorrectBps[0] = 4000; // 40%
        incorrectBps[1] = 4000; // 40%

        // Expecting the transaction to revert due to incorrect total basis points
        vm.expectRevert("bps must add up to 10_000");
        emitter.buyToken{ value: 1e18 }(recipients, incorrectBps, address(0), address(0), address(0));

        vm.stopPrank();
    }

    function testSetCreatorsAddress() public {
        // Setting Creators Address by Owner
        address newCreatorsAddress = address(0x123);
        emitter.setCreatorsAddress(newCreatorsAddress);
        assertEq(emitter.creatorsAddress(), newCreatorsAddress, "Owner should be able to set creators address");

        // Attempting to set Creators Address by Non-Owner
        address nonOwner = address(0x4156);
        vm.startPrank(nonOwner);
        try emitter.setCreatorsAddress(nonOwner) {
            fail("Non-owner should not be able to set creators address");
        } catch {}
        vm.stopPrank();
    }

    // // // TODO: test scamming creator fails with percentage low
    // function testFailLowPercentage() public {
    //     vm.startPrank(address(0));

    //     address[] memory recipients = new address[](2);
    //     recipients[0] = address(1);
    //     recipients[1] = address(2);

    //     uint256[] memory bps = new uint256[](2);
    //     bps[0] = 9_500;
    //     bps[1] = 500;

    //     emitter.buyToken{value: 1e18}(recipients, bps);
    // }

    function testBuyingTwiceAmountIsNotMoreThanTwiceEmittedTokens() public {
        vm.startPrank(address(0));

        address[] memory recipients = new address[](1);
        recipients[0] = address(1);

        uint256[] memory bps = new uint256[](1);
        bps[0] = 10_000;

        emitter.buyToken{ value: 1e18 }(recipients, bps, address(0), address(0), address(0));
        uint256 firstAmount = emitter.balanceOf(address(1));

        emitter.buyToken{ value: 1e18 }(recipients, bps, address(0), address(0), address(0));
        uint256 secondAmountDifference = emitter.balanceOf(address(1)) - firstAmount;

        assert(secondAmountDifference <= 2 * emitter.totalSupply());
    }

    function testBuyTokenReentrancy() public {
        // Deploy the malicious treasury contract
        MaliciousTreasury maliciousTreasury = new MaliciousTreasury(address(emitter));

        // Initialize TokenEmitter with the address of the malicious treasury
        NontransferableERC20Votes governanceToken = new NontransferableERC20Votes(address(this), "Revolution Governance", "GOV");
        uint256 toScale = 1e18 * 1e18;
        uint256 tokensPerTimeUnit_ = 10_000;
        RevolutionProtocolRewards protocolRewards = new RevolutionProtocolRewards();

        TokenEmitter emitter2 = new TokenEmitter(
            address(this),
            governanceToken,
            address(protocolRewards),
            address(this),
            address(maliciousTreasury),
            1e14,
            1e17,
            int256(tokensPerTimeUnit_ * toScale)
        );
        governanceToken.transferOwnership(address(emitter2));

        vm.deal(address(this), 100000 ether);

        //buy tokens and see if malicious treasury can reenter
        address[] memory recipients = new address[](1);
        recipients[0] = address(1);
        uint256[] memory bps = new uint256[](1);
        bps[0] = 10_000;
        vm.expectRevert();
        emitter2.buyToken{ value: 1e18 }(recipients, bps, address(0), address(0), address(0));

        emit log_uint(emitter2.totalSupply());
        emit log_uint(emitter2.balanceOf(address(maliciousTreasury)));
    }

    function testGetTokenAmountForMultiPurchaseGeneral(uint256 payment) public {
        vm.assume(payment > emitter.minPurchaseAmount());
        vm.assume(payment < emitter.maxPurchaseAmount());
        vm.startPrank(address(0));

        uint256 SOME_MAX_EXPECTED_VALUE = uint256(wadDiv(int256(payment), 1 ether)) * 1e18 * tokensPerTimeUnit;

        int256 slightlyMore = emitter.getTokenQuoteForEther((payment * 101) / 100);

        // Call the function with the typical payment amount
        int256 tokenAmount = emitter.getTokenQuoteForEther(payment);

        emit log_int(tokenAmount);

        // Assert that the token amount is reasonable (not zero or unexpectedly high)
        assertGt(tokenAmount, 0, "Token amount should be greater than zero");
        assertLt(tokenAmount, int256(SOME_MAX_EXPECTED_VALUE), "Token amount should be less than some max expected value");
        assertLt(tokenAmount, slightlyMore, "Token amount should be less than slightly more");

        //buy 10 ether of tokens
        address[] memory recipients = new address[](1);
        recipients[0] = address(1);
        uint256[] memory bps = new uint256[](1);
        bps[0] = 10_000;

        //ensure that enough volume was bought for the day, so purchase expectedVolume amount first
        emitter.buyToken{ value: expectedVolume }(recipients, bps, address(0), address(0), address(0));

        emitter.buyToken{ value: payment }(recipients, bps, address(0), address(0), address(0));

        int256 newTokenAmount = emitter.getTokenQuoteForEther(payment);

        // Assert that the new token amount is less than the previous tokenAmount
        assertLt(newTokenAmount, tokenAmount, "Token amount should be less than previous token amount");

        vm.stopPrank();
    }

    function testGetTokenAmountForMultiPurchaseEdgeCases() public {
        vm.startPrank(address(0));

        // Edge Case 1: Very Small Payment
        uint256 smallPayment = 0.00001 ether;
        int256 smallPaymentTokenAmount = emitter.getTokenQuoteForEther(smallPayment);
        assertGt(smallPaymentTokenAmount, 0, "Token amount for small payment should be greater than zero");
        emit log_int(smallPaymentTokenAmount);

        // A days worth of payment amount
        int256 dailyPaymentTokenAmount = emitter.getTokenQuoteForEther(expectedVolume);
        assertLt(uint256(dailyPaymentTokenAmount), tokensPerTimeUnit * 1e18, "Token amount for daily payment should be less than tokens per day");
        emit log_string("Daily Payment Token Amount: ");
        emit log_int(dailyPaymentTokenAmount);

        // Edge Case 2: Very Large Payment
        // An unusually large payment amount
        int256 largePaymentTokenAmount = emitter.getTokenQuoteForEther(expectedVolume * 100);
        //spending 100x the expected amount per day should get you < 25x the tokens
        uint256 SOME_REALISTIC_UPPER_BOUND = 25 * tokensPerTimeUnit * 1e18;
        assertLt(uint256(largePaymentTokenAmount), SOME_REALISTIC_UPPER_BOUND, "Token amount for large payment should be less than some realistic upper bound");
        emit log_string("Large Payment Token Amount: ");
        emit log_int(largePaymentTokenAmount);

        uint256 largestPayment = expectedVolume * 1_000; // An unusually large payment amount
        int256 largestPaymentTokenAmount = emitter.getTokenQuoteForEther(largestPayment);
        //spending 1000x the daily amount should get you less than 50x the tokens
        assertLt(uint256(largestPaymentTokenAmount), 50 * tokensPerTimeUnit * 1e18, "Token amount for largest payment should be less than some realistic upper bound");

        emit log_string("Largest Payment Token Amount: ");
        emit log_int(largestPaymentTokenAmount);

        vm.stopPrank();
    }

    function testGetTokenPrice() public {
        vm.startPrank(address(0));

        vm.deal(address(0), 100000 ether);
        vm.stopPrank();

        int256 priceAfterManyPurchases = emitter.buyTokenQuote(1e18);
        emit log_int(priceAfterManyPurchases);

        // Simulate the passage of time
        uint256 daysElapsed = 221;
        vm.warp(block.timestamp + daysElapsed * 1 days);

        int256 priceAfterManyDays = emitter.buyTokenQuote(1e18);

        emit log_int(priceAfterManyDays);

        // Assert that the price is greater than zero
        assertGt(priceAfterManyDays, 0, "Price should never hit zero");
    }
}

contract MaliciousTreasury {
    TokenEmitter emitter;
    bool public reentryAttempted;

    constructor(address _emitter) {
        emitter = TokenEmitter(_emitter);
        reentryAttempted = false;
    }

    // Fallback function to enable re-entrance to TokenEmitter
    function call() external payable {
        reentryAttempted = true;
        address[] memory recipients = new address[](1);
        recipients[0] = address(this);
        uint256[] memory bps = new uint256[](1);
        bps[0] = 10_000;

        // Attempt to re-enter TokenEmitter
        emitter.buyToken{ value: msg.value }(recipients, bps, address(0), address(0), address(0));
    }
}
