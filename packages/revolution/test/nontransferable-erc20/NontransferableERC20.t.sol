// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import { Test } from "forge-std/Test.sol";
import { NontransferableERC20Votes } from "../../src/NontransferableERC20Votes.sol";
import { RevolutionBuilderTest } from "../RevolutionBuilder.t.sol";

contract NontransferableERC20TestSuite is RevolutionBuilderTest {
    event Log(string, uint);

    // NontransferableERC20Votes token;

    function setUp() public override {
        super.setUp();
        super.setMockParams();

        super.setERC20TokenParams("Revolution Governance", "GOV");

        super.setCultureIndexParams("Vrbs", "Our community Vrbs. Must be 32x32.", 10, 200, 0);

        super.deployMock();

        // token = new NontransferableERC20Votes(address(erc20TokenEmitter), "Revolution Governance", "GOV");
    }

    function testTransferRestrictions() public {
        // Setup: Mint some tokens to an account
        address account1 = address(0x1);
        uint256 mintAmount = 1000 * 1e18;
        vm.startPrank(address(erc20TokenEmitter));
        erc20Token.mint(account1, mintAmount);
        assertEq(erc20Token.balanceOf(account1), mintAmount, "Minting failed");

        // Attempt to transfer tokens from account1 to account2
        address account2 = address(0x2);
        uint256 transferAmount = 500 * 1e18;
        vm.startPrank(account1);
        vm.expectRevert(abi.encodeWithSignature("TRANSFER_NOT_ALLOWED()"));
        erc20Token.transfer(account2, transferAmount);
        vm.stopPrank();

        // Verify that the balances remain unchanged
        assertEq(erc20Token.balanceOf(account1), mintAmount, "Balance of account1 should not change");
        assertEq(erc20Token.balanceOf(account2), 0, "Balance of account2 should remain zero");
    }

    function testApprovalRestrictions() public {
        // Setup: Use two accounts
        address owner = address(erc20TokenEmitter);
        address spender = address(0x2);

        // Attempt to approve spender by the owner
        uint256 approvalAmount = 500 * 1e18;
        vm.startPrank(owner);
        vm.expectRevert(abi.encodeWithSignature("TRANSFER_NOT_ALLOWED()"));
        erc20Token.approve(spender, approvalAmount);
        vm.stopPrank();

        // Verify that the allowance remains zero
        assertEq(erc20Token.allowance(owner, spender), 0, "Allowance should remain zero");
    }

    function testMintingBehavior() public {
        address account = address(0x3);
        uint256 mintAmount = 500 * 1e18;

        // Attempt minting by a non-owner
        address nonOwner = address(0x4);
        vm.startPrank(nonOwner);
        vm.expectRevert();
        erc20Token.mint(account, mintAmount);
        vm.stopPrank();

        // Verify that the balance remains unchanged
        assertEq(erc20Token.balanceOf(account), 0, "Non-owner should not be able to mint");

        // Minting by the owner
        vm.startPrank(address(erc20TokenEmitter));
        erc20Token.mint(account, mintAmount);
        vm.stopPrank();

        // Verify balance and total supply
        assertEq(erc20Token.balanceOf(account), mintAmount, "Minting failed to update balance");
        assertEq(erc20Token.totalSupply(), mintAmount, "Total supply not updated correctly");
    }

    function testVotingAndDelegation() public {
        address delegate = address(0x6);
        uint256 mintAmount = 1000 * 1e18;

        // Mint tokens to the owner
        vm.startPrank(address(erc20TokenEmitter));
        erc20Token.mint(address(this), mintAmount);
        vm.stopPrank();

        // Delegate voting power
        erc20Token.delegate(delegate);

        // Check the voting power of the delegate
        assertEq(erc20Token.getVotes(delegate), mintAmount, "Delegation failed to assign voting power");

        // Ensure that no tokens were transferred in the process of delegation
        assertEq(erc20Token.balanceOf(delegate), 0, "Delegation should not transfer tokens");
    }

    function testTokenMetadata() public {
        assertEq(erc20Token.name(), "Revolution Governance", "Incorrect token name");
        assertEq(erc20Token.symbol(), "GOV", "Incorrect token symbol");
        assertEq(erc20Token.decimals(), 18, "Incorrect number of decimals");
    }

    function testSupplyInvariants(uint256 mintAmount1) public {
        vm.assume(mintAmount1 < type(uint208).max);

        uint256 total = mintAmount1 + mintAmount1 / 10;

        vm.assume(total < type(uint208).max);
        address account1 = address(0x7);
        address account2 = address(0x8);

        // Mint tokens to different accounts
        vm.startPrank(address(erc20TokenEmitter));
        erc20Token.mint(account1, mintAmount1);
        erc20Token.mint(account2, mintAmount1 / 10);
        vm.stopPrank();

        // Check total supply
        uint256 totalSupply = erc20Token.totalSupply();

        emit Log("totalSupply", totalSupply);

        assertEq(totalSupply, mintAmount1 + mintAmount1 / 10, "Total supply should equal sum of balances");

        // Check individual balances
        assertEq(erc20Token.balanceOf(account1), mintAmount1, "Incorrect balance for account1");
        assertEq(erc20Token.balanceOf(account2), mintAmount1 / 10, "Incorrect balance for account2");
    }

    function testAccessControl() public {
        address nonOwner = address(0x9);
        uint256 mintAmount = 500 * 1e18;

        // Attempt to mint tokens by a non-owner
        vm.startPrank(nonOwner);
        vm.expectRevert();
        erc20Token.mint(address(1), mintAmount);
        vm.stopPrank();

        // Minting by the owner
        vm.startPrank(address(erc20TokenEmitter));
        erc20Token.mint(address(1), mintAmount);
        vm.stopPrank();

        // Verify that the minting was successful
        assertEq(erc20Token.balanceOf(address(1)), mintAmount, "Owner should be able to mint");
    }

    function testEdgeCases() public {
        // Minting an excessive amount of tokens (overflow check)
        uint256 excessiveAmount = type(uint256).max;
        vm.startPrank(address(erc20TokenEmitter));
        vm.expectRevert();
        erc20Token.mint(address(1), excessiveAmount);
        vm.stopPrank();
    }
}
