// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import { Test } from "forge-std/Test.sol";
import { unsafeWadDiv } from "../../src/libs/SignedWadMath.sol";
import { ERC20TokenEmitter } from "../../src/ERC20TokenEmitter.sol";
import { IERC20TokenEmitter } from "../../src/interfaces/IERC20TokenEmitter.sol";
import { NontransferableERC20Votes } from "../../src/NontransferableERC20Votes.sol";
import { RevolutionProtocolRewards } from "@collectivexyz/protocol-rewards/src/RevolutionProtocolRewards.sol";
import { wadDiv } from "../../src/libs/SignedWadMath.sol";
import { IRevolutionBuilder } from "../../src/interfaces/IRevolutionBuilder.sol";
import { RevolutionBuilderTest } from "../RevolutionBuilder.t.sol";
import { INontransferableERC20Votes } from "../../src/interfaces/INontransferableERC20Votes.sol";
import { ERC1967Proxy } from "../../src/libs/proxy/ERC1967Proxy.sol";

contract ERC20TokenEmitterTest is RevolutionBuilderTest {
    event Log(string, uint);

    // 1,000 tokens per day is the target emission
    uint256 tokensPerTimeUnit = 1_000;

    uint256 expectedVolume = tokensPerTimeUnit * 1e18;

    string public tokenNamePrefix = "Vrb";

    function setUp() public override {
        super.setUp();
        super.setMockParams();

        super.setERC721TokenParams("Mock", "MOCK", "https://example.com/token/", tokenNamePrefix);

        int256 oneFullTokenTargetPrice = 1 ether;

        int256 priceDecayPercent = 1e18 / 10;

        super.setERC20TokenEmitterParams(
            oneFullTokenTargetPrice,
            priceDecayPercent,
            int256(1e18 * tokensPerTimeUnit),
            creatorsAddress
        );

        super.deployMock();

        vm.deal(address(0), 100000 ether);

        // vm.startPrank(address(0));
        // RevolutionProtocolRewards protocolRewards = new RevolutionProtocolRewards();

        // vm.deal(address(0), 100000 ether);
        // vm.stopPrank();

        // //20% - how much the price decays per unit of time with no sales

        // erc20Token.initialize({
        //     _erc20TokenParams: IRevolutionBuilder.ERC20TokenParams({name: "Revolution Governance", symbol: "GOV"}),
        //     _initialOwner: address(this)
        // });

        // //this setup assumes an ideal of 1e21 or 1_000 ETH (1_000 * 1e18) coming into the system per day, token prices will increaase if more ETH comes in
        // emitter = new ERC20TokenEmitter(
        //     address(this),
        //     governanceToken,
        //     address(protocolRewards),
        //     address(this),
        //     erc20TokenEmitter.treasury(),
        //     oneFullTokenTargetPrice,
        //     priceDecayPercent,
        //     //scale by 1e18 the tokens per time unit
        //     int256(1e18 * tokensPerTimeUnit)
        // );

        //erc20TokenEmitter.setCreatorsAddress(erc20TokenEmitter.creatorsAddress());

        // address emitterAddress = address(emitter);

        // erc20Token.transferOwnership(emitterAddress);
    }

    function testCannotBuyAsTreasury() public {
        vm.startPrank(erc20TokenEmitter.treasury());

        vm.deal(erc20TokenEmitter.treasury(), 100000 ether);

        address[] memory recipients = new address[](1);
        recipients[0] = address(1);

        uint256[] memory bps = new uint256[](1);
        bps[0] = 10_000;

        vm.expectRevert("Funds recipient cannot buy tokens");
        erc20TokenEmitter.buyToken{ value: 1e18 }(
            recipients,
            bps,
            IERC20TokenEmitter.ProtocolRewardAddresses({
                builder: address(0),
                purchaseReferral: address(0),
                deployer: address(0)
            })
        );
    }

    function testCannotBuyAsCreators() public {
        vm.startPrank(erc20TokenEmitter.creatorsAddress());

        vm.deal(erc20TokenEmitter.creatorsAddress(), 100000 ether);

        address[] memory recipients = new address[](1);
        recipients[0] = address(1);

        uint256[] memory bps = new uint256[](1);
        bps[0] = 10_000;

        vm.expectRevert("Funds recipient cannot buy tokens");
        erc20TokenEmitter.buyToken{ value: 1e18 }(
            recipients,
            bps,
            IERC20TokenEmitter.ProtocolRewardAddresses({
                builder: address(0),
                purchaseReferral: address(0),
                deployer: address(0)
            })
        );
    }

    function testTransferTokenContractOwnership() public {
        // makes a token emitter with one nontransferableerc20
        // makes a second with the same one
        // ensures that the second cannot mint and calling buyGovernance fails
        // transfers ownership to the second
        // ensures that the second can mint and calling buyGovernance succeeds

        address treasury = address(0x36);
        RevolutionProtocolRewards protocolRewards = new RevolutionProtocolRewards();

        address governanceToken = address(new ERC1967Proxy(erc20TokenImpl, ""));

        address emitter1 = address(new ERC1967Proxy(erc20TokenEmitterImpl, ""));

        vm.startPrank(address(manager));
        IERC20TokenEmitter(emitter1).initialize({
            initialOwner: address(this),
            erc20Token: address(governanceToken),
            treasury: treasury,
            vrgdac: address(erc20TokenEmitter.vrgdac()),
            creatorsAddress: creatorsAddress
        });

        INontransferableERC20Votes(governanceToken).initialize({
            initialOwner: address(emitter1),
            erc20TokenParams: IRevolutionBuilder.ERC20TokenParams({ name: "Revolution Governance", symbol: "GOV" })
        });

        vm.deal(address(this), 100000 ether);

        address[] memory recipients = new address[](1);
        recipients[0] = address(1);

        uint256[] memory bps = new uint256[](1);
        bps[0] = 10_000;

        vm.startPrank(address(this));
        IERC20TokenEmitter(emitter1).buyToken{ value: 1e18 }(
            recipients,
            bps,
            IERC20TokenEmitter.ProtocolRewardAddresses({
                builder: address(0),
                purchaseReferral: address(0),
                deployer: address(0)
            })
        );

        address emitter2 = address(new ERC1967Proxy(erc20TokenEmitterImpl, ""));

        vm.startPrank(address(manager));
        IERC20TokenEmitter(emitter2).initialize({
            initialOwner: address(this),
            erc20Token: address(governanceToken),
            treasury: treasury,
            vrgdac: address(erc20TokenEmitter.vrgdac()),
            creatorsAddress: creatorsAddress
        });

        vm.startPrank(address(emitter1));
        NontransferableERC20Votes(governanceToken).transferOwnership(address(emitter2));

        vm.startPrank(address(emitter2));
        //accept ownership transfer
        NontransferableERC20Votes(governanceToken).acceptOwnership();

        vm.startPrank(address(48));
        vm.deal(address(48), 100000 ether);
        IERC20TokenEmitter(emitter2).buyToken{ value: 1e18 }(
            recipients,
            bps,
            IERC20TokenEmitter.ProtocolRewardAddresses({
                builder: address(0),
                purchaseReferral: address(0),
                deployer: address(0)
            })
        );
    }

    function testBuyTokenWithDifferentRates(uint256 creatorRate, uint256 entropyRate) public {
        // Assume valid rates
        vm.assume(creatorRate <= 10000 && entropyRate <= 10000);

        vm.startPrank(address(dao));
        // Set creator and entropy rates
        erc20TokenEmitter.setCreatorRateBps(creatorRate);
        erc20TokenEmitter.setEntropyRateBps(entropyRate);
        assertEq(erc20TokenEmitter.creatorRateBps(), creatorRate, "Creator rate not set correctly");
        assertEq(erc20TokenEmitter.entropyRateBps(), entropyRate, "Entropy rate not set correctly");

        // Setup for buying token
        address[] memory recipients = new address[](1);
        recipients[0] = address(1); // recipient address

        uint256[] memory bps = new uint256[](1);
        bps[0] = 10000; // 100% of the tokens to the recipient

        uint256 valueToSend = 1 ether;
        erc20TokenEmitter.setCreatorsAddress(address(80));
        address creatorsAddress = erc20TokenEmitter.creatorsAddress();
        uint256 creatorsInitialEthBalance = address(erc20TokenEmitter.creatorsAddress()).balance;

        uint256 feeAmount = erc20TokenEmitter.computeTotalReward(valueToSend);

        // Calculate expected ETH sent to creator
        uint256 totalPaymentForCreator = ((valueToSend - feeAmount) * creatorRate) / 10000;
        uint256 expectedCreatorEth = (totalPaymentForCreator * entropyRate) / 10000;

        if (creatorRate == 0 || entropyRate == 10_000) vm.expectRevert("Ether amount must be greater than 0");
        uint256 expectedCreatorTokens = uint(
            erc20TokenEmitter.getTokenQuoteForEther(totalPaymentForCreator - expectedCreatorEth)
        );

        // Perform token purchase
        vm.startPrank(address(this));
        uint256 tokensSold = erc20TokenEmitter.buyToken{ value: valueToSend }(
            recipients,
            bps,
            IERC20TokenEmitter.ProtocolRewardAddresses({
                builder: address(0),
                purchaseReferral: address(0),
                deployer: address(0)
            })
        );

        // Verify tokens distributed to creator
        uint256 creatorTokenBalance = erc20TokenEmitter.balanceOf(erc20TokenEmitter.creatorsAddress());
        assertEq(creatorTokenBalance, expectedCreatorTokens, "Creator did not receive correct amount of tokens");

        // Verify ETH sent to creator
        uint256 creatorsNewEthBalance = address(erc20TokenEmitter.creatorsAddress()).balance;
        assertEq(
            creatorsNewEthBalance - creatorsInitialEthBalance,
            expectedCreatorEth,
            "Incorrect ETH amount sent to creator"
        );

        // Verify tokens distributed to recipient
        uint256 recipientTokenBalance = erc20TokenEmitter.balanceOf(address(1));
        assertEq(recipientTokenBalance, tokensSold, "Recipient did not receive correct amount of tokens");
    }

    function testBuyingLaterIsBetter() public {
        vm.startPrank(address(0));

        int256 initAmount = erc20TokenEmitter.getTokenQuoteForEther(1e18);

        int256 firstPrice = erc20TokenEmitter.buyTokenQuote(1e19);

        // solhint-disable-next-line not-rely-on-time
        vm.warp(block.timestamp + (10 days));

        int256 secondPrice = erc20TokenEmitter.buyTokenQuote(1e19);

        emit log_int(firstPrice);
        emit log_int(secondPrice);

        int256 laterAmount = erc20TokenEmitter.getTokenQuoteForEther(1e18);

        assertGt(laterAmount, initAmount, "Later amount should be greater than initial amount");

        assertLt(secondPrice, firstPrice, "Second price should be less than first price");
    }

    function testBuyToken() public {
        vm.startPrank(address(0));

        address[] memory recipients = new address[](1);
        recipients[0] = address(1);

        uint256[] memory bps = new uint256[](1);
        bps[0] = 10_000;

        vm.deal(address(0), 100000 ether);

        emit log_address(address(0));

        erc20TokenEmitter.buyToken{ value: 1e18 }(
            recipients,
            bps,
            IERC20TokenEmitter.ProtocolRewardAddresses({
                builder: address(0),
                purchaseReferral: address(0),
                deployer: address(0)
            })
        );
        emit Log("Balance: ", erc20TokenEmitter.balanceOf(address(1)));
    }

    function testBuyTokenPriceIncreases() public {
        vm.startPrank(address(0));

        address[] memory firstRecipients = new address[](1);
        firstRecipients[0] = address(1);

        address[] memory secondRecipients = new address[](1);
        secondRecipients[0] = address(2);

        uint256[] memory bps = new uint256[](1);
        bps[0] = 10_000;

        erc20TokenEmitter.buyToken{ value: 1e18 }(
            firstRecipients,
            bps,
            IERC20TokenEmitter.ProtocolRewardAddresses({
                builder: address(0),
                purchaseReferral: address(0),
                deployer: address(0)
            })
        );

        erc20TokenEmitter.buyToken{ value: 1e18 }(
            secondRecipients,
            bps,
            IERC20TokenEmitter.ProtocolRewardAddresses({
                builder: address(0),
                purchaseReferral: address(0),
                deployer: address(0)
            })
        );

        // should get more expensive
        assertGt(erc20TokenEmitter.balanceOf(address(1)), erc20TokenEmitter.balanceOf(address(2)));
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
        int256 expectedAmount = erc20TokenEmitter.getTokenQuoteForEther(
            1e18 - erc20TokenEmitter.computeTotalReward(1e18)
        );

        erc20TokenEmitter.buyToken{ value: 1e18 }(
            recipients,
            bps,
            IERC20TokenEmitter.ProtocolRewardAddresses({
                builder: address(0),
                purchaseReferral: address(0),
                deployer: address(0)
            })
        );
        //assert address balances are correct
        //multiply bps by expectedAmount and assert
        assertEq(
            erc20TokenEmitter.balanceOf(address(1)),
            (firstBps * uint256(expectedAmount)) / 10_000,
            "First recipient should have correct balance"
        );
        assertEq(
            erc20TokenEmitter.balanceOf(address(2)),
            ((10_000 - firstBps) * uint256(expectedAmount)) / 10_000,
            "Second recipient should have correct balance"
        );

        //assert treasury balance is correct
        assertEq(
            address(erc20TokenEmitter.treasury()).balance,
            1e18 - erc20TokenEmitter.computeTotalReward(1e18),
            "Treasury should have payment - totalReward in balance"
        );
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

        int expectedAmount = erc20TokenEmitter.getTokenQuoteForEther(1e18 - erc20TokenEmitter.computeTotalReward(1e18));
        assertGt(expectedAmount, 0, "Token purchase should have a positive amount");

        // Attempting a valid token purchase
        uint emittedWad = erc20TokenEmitter.buyToken{ value: 1e18 }(
            recipients,
            correctBps,
            IERC20TokenEmitter.ProtocolRewardAddresses({
                builder: address(0),
                purchaseReferral: address(0),
                deployer: address(0)
            })
        );
        int totalSupplyAfterValidPurchase = int(erc20TokenEmitter.totalSupply());
        assertEq(totalSupplyAfterValidPurchase, expectedAmount, "Supply should match the expected amount");
        //emitted should match expected
        assertEq(int(emittedWad), expectedAmount, "Emitted amount should match expected amount");
        //emitted should match supply
        assertEq(int(emittedWad), totalSupplyAfterValidPurchase, "Emitted amount should match total supply");

        //expect treasury to have payment - totalReward in balance
        assertEq(
            address(erc20TokenEmitter.treasury()).balance,
            1e18 - erc20TokenEmitter.computeTotalReward(1e18),
            "Treasury should have payment - totalReward in balance"
        );

        // Test case with incorrect total of basis points
        uint256[] memory incorrectBps = new uint256[](2);
        incorrectBps[0] = 4000; // 40%
        incorrectBps[1] = 4000; // 40%

        // Expecting the transaction to revert due to incorrect total basis points
        vm.expectRevert("bps must add up to 10_000");
        erc20TokenEmitter.buyToken{ value: 1e18 }(
            recipients,
            incorrectBps,
            IERC20TokenEmitter.ProtocolRewardAddresses({
                builder: address(0),
                purchaseReferral: address(0),
                deployer: address(0)
            })
        );

        vm.stopPrank();
    }

    function testSetCreatorsAddress() public {
        // Setting Creators Address by Owner
        address newCreatorsAddress = address(0x123);
        vm.prank(address(dao));
        erc20TokenEmitter.setCreatorsAddress(newCreatorsAddress);
        assertEq(
            erc20TokenEmitter.creatorsAddress(),
            newCreatorsAddress,
            "Owner should be able to set creators address"
        );

        // Attempting to set Creators Address by Non-Owner
        address nonOwner = address(0x4156);
        vm.startPrank(nonOwner);
        try erc20TokenEmitter.setCreatorsAddress(nonOwner) {
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

    //    erc20TokenEmitter.buyToken{value: 1e18}(recipients, bps);
    // }

    function testBuyingTwiceAmountIsNotMoreThanTwiceEmittedTokens() public {
        vm.startPrank(address(0));

        address[] memory recipients = new address[](1);
        recipients[0] = address(1);

        uint256[] memory bps = new uint256[](1);
        bps[0] = 10_000;

        erc20TokenEmitter.buyToken{ value: 1e18 }(
            recipients,
            bps,
            IERC20TokenEmitter.ProtocolRewardAddresses({
                builder: address(0),
                purchaseReferral: address(0),
                deployer: address(0)
            })
        );
        uint256 firstAmount = erc20TokenEmitter.balanceOf(address(1));

        erc20TokenEmitter.buyToken{ value: 1e18 }(
            recipients,
            bps,
            IERC20TokenEmitter.ProtocolRewardAddresses({
                builder: address(0),
                purchaseReferral: address(0),
                deployer: address(0)
            })
        );
        uint256 secondAmountDifference = erc20TokenEmitter.balanceOf(address(1)) - firstAmount;

        assert(secondAmountDifference <= 2 * erc20TokenEmitter.totalSupply());
    }

    function testBuyTokenReentrancy() public {
        // Deploy the malicious treasury contract
        MaliciousTreasury maliciousTreasury = new MaliciousTreasury(address(erc20TokenEmitter));

        address governanceToken = address(new ERC1967Proxy(erc20TokenImpl, ""));

        address emitter2 = address(new ERC1967Proxy(erc20TokenEmitterImpl, ""));

        vm.startPrank(address(manager));
        IERC20TokenEmitter(emitter2).initialize({
            initialOwner: address(this),
            erc20Token: address(governanceToken),
            treasury: address(maliciousTreasury),
            vrgdac: address(erc20TokenEmitter.vrgdac()),
            creatorsAddress: creatorsAddress
        });

        INontransferableERC20Votes(governanceToken).initialize({
            initialOwner: address(emitter2),
            erc20TokenParams: IRevolutionBuilder.ERC20TokenParams({ name: "Revolution Governance", symbol: "GOV" })
        });

        vm.deal(address(this), 100000 ether);

        //buy tokens and see if malicious treasury can reenter
        address[] memory recipients = new address[](1);
        recipients[0] = address(1);
        uint256[] memory bps = new uint256[](1);
        bps[0] = 10_000;
        vm.expectRevert();
        IERC20TokenEmitter(emitter2).buyToken{ value: 1e18 }(
            recipients,
            bps,
            IERC20TokenEmitter.ProtocolRewardAddresses({
                builder: address(0),
                purchaseReferral: address(0),
                deployer: address(0)
            })
        );
    }

    function testGetTokenAmountForMultiPurchaseGeneral(uint256 payment) public {
        vm.assume(payment > erc20TokenEmitter.minPurchaseAmount());
        vm.assume(payment < erc20TokenEmitter.maxPurchaseAmount());
        vm.startPrank(address(0));

        uint256 SOME_MAX_EXPECTED_VALUE = uint256(wadDiv(int256(payment), 1 ether)) * 1e18 * tokensPerTimeUnit;

        int256 slightlyMore = erc20TokenEmitter.getTokenQuoteForEther((payment * 101) / 100);

        // Call the function with the typical payment amount
        int256 tokenAmount = erc20TokenEmitter.getTokenQuoteForEther(payment);

        emit log_int(tokenAmount);

        // Assert that the token amount is reasonable (not zero or unexpectedly high)
        assertGt(tokenAmount, 0, "Token amount should be greater than zero");
        assertLt(
            tokenAmount,
            int256(SOME_MAX_EXPECTED_VALUE),
            "Token amount should be less than some max expected value"
        );
        assertLt(tokenAmount, slightlyMore, "Token amount should be less than slightly more");

        //buy 10 ether of tokens
        address[] memory recipients = new address[](1);
        recipients[0] = address(1);
        uint256[] memory bps = new uint256[](1);
        bps[0] = 10_000;

        //ensure that enough volume was bought for the day, so purchase expectedVolume amount first
        erc20TokenEmitter.buyToken{ value: expectedVolume }(
            recipients,
            bps,
            IERC20TokenEmitter.ProtocolRewardAddresses({
                builder: address(0),
                purchaseReferral: address(0),
                deployer: address(0)
            })
        );

        erc20TokenEmitter.buyToken{ value: payment }(
            recipients,
            bps,
            IERC20TokenEmitter.ProtocolRewardAddresses({
                builder: address(0),
                purchaseReferral: address(0),
                deployer: address(0)
            })
        );

        int256 newTokenAmount = erc20TokenEmitter.getTokenQuoteForEther(payment);

        // Assert that the new token amount is less than the previous tokenAmount
        assertLt(newTokenAmount, tokenAmount, "Token amount should be less than previous token amount");

        vm.stopPrank();
    }

    function testGetTokenAmountForMultiPurchaseEdgeCases() public {
        vm.startPrank(address(0));

        // Edge Case 1: Very Small Payment
        uint256 smallPayment = 0.00001 ether;
        int256 smallPaymentTokenAmount = erc20TokenEmitter.getTokenQuoteForEther(smallPayment);
        assertGt(smallPaymentTokenAmount, 0, "Token amount for small payment should be greater than zero");
        emit log_int(smallPaymentTokenAmount);

        // A days worth of payment amount
        int256 dailyPaymentTokenAmount = erc20TokenEmitter.getTokenQuoteForEther(expectedVolume);
        assertLt(
            uint256(dailyPaymentTokenAmount),
            tokensPerTimeUnit * 1e18,
            "Token amount for daily payment should be less than tokens per day"
        );
        emit log_string("Daily Payment Token Amount: ");
        emit log_int(dailyPaymentTokenAmount);

        // Edge Case 2: Very Large Payment
        // An unusually large payment amount
        int256 largePaymentTokenAmount = erc20TokenEmitter.getTokenQuoteForEther(expectedVolume * 100);
        //spending 100x the expected amount per day should get you < 25x the tokens
        uint256 SOME_REALISTIC_UPPER_BOUND = 25 * tokensPerTimeUnit * 1e18;
        assertLt(
            uint256(largePaymentTokenAmount),
            SOME_REALISTIC_UPPER_BOUND,
            "Token amount for large payment should be less than some realistic upper bound"
        );
        emit log_string("Large Payment Token Amount: ");
        emit log_int(largePaymentTokenAmount);

        uint256 largestPayment = expectedVolume * 1_000; // An unusually large payment amount
        int256 largestPaymentTokenAmount = erc20TokenEmitter.getTokenQuoteForEther(largestPayment);
        //spending 1000x the daily amount should get you less than 50x the tokens
        assertLt(
            uint256(largestPaymentTokenAmount),
            50 * tokensPerTimeUnit * 1e18,
            "Token amount for largest payment should be less than some realistic upper bound"
        );

        emit log_string("Largest Payment Token Amount: ");
        emit log_int(largestPaymentTokenAmount);

        vm.stopPrank();
    }

    function testGetTokenPrice() public {
        vm.startPrank(address(0));

        vm.deal(address(0), 100000 ether);
        vm.stopPrank();

        int256 priceAfterManyPurchases = erc20TokenEmitter.buyTokenQuote(1e18);
        emit log_int(priceAfterManyPurchases);

        // Simulate the passage of time
        uint256 daysElapsed = 221;
        vm.warp(block.timestamp + daysElapsed * 1 days);

        int256 priceAfterManyDays = erc20TokenEmitter.buyTokenQuote(1e18);

        emit log_int(priceAfterManyDays);

        // Assert that the price is greater than zero
        assertGt(priceAfterManyDays, 0, "Price should never hit zero");
    }
}

contract MaliciousTreasury {
    ERC20TokenEmitter erc20TokenEmitter;
    bool public reentryAttempted;

    constructor(address _emitter) {
        erc20TokenEmitter = ERC20TokenEmitter(_emitter);
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
        erc20TokenEmitter.buyToken{ value: msg.value }(
            recipients,
            bps,
            IERC20TokenEmitter.ProtocolRewardAddresses({
                builder: address(0),
                purchaseReferral: address(0),
                deployer: address(0)
            })
        );
    }
}
