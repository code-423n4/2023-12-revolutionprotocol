// SPDX-License-Identifier: MIT
pragma solidity 0.8.22;

import "../ProtocolRewardsTest.sol";
import "../../src/abstract/RewardSplits.sol";

contract WithdrawTest is ProtocolRewardsTest {
    function setUp() public override {
        super.setUp();

        vm.deal(collector, 10 ether);

        vm.prank(collector);
        protocolRewards.deposit{ value: 10 ether }(builderReferral, "", "");
    }

    function getDomainSeparator() internal view virtual returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                    keccak256(bytes("RevolutionProtocolRewards")),
                    keccak256(bytes("1")),
                    block.chainid,
                    address(protocolRewards)
                )
            );
    }

    function testWithdraw() public {
        uint256 beforeBuilderBalance = builderReferral.balance;
        uint256 beforeTotalSupply = protocolRewards.totalRewardsSupply();

        uint256 builderRewardsBalance = protocolRewards.balanceOf(builderReferral);

        vm.prank(builderReferral);
        protocolRewards.withdraw(builderReferral, builderRewardsBalance);

        assertEq(builderReferral.balance, beforeBuilderBalance + builderRewardsBalance);
        assertEq(protocolRewards.totalRewardsSupply(), beforeTotalSupply - builderRewardsBalance);
    }

    function testWithdrawFullBalance() public {
        uint256 beforeBuilderBalance = builderReferral.balance;
        uint256 beforeTotalSupply = protocolRewards.totalRewardsSupply();

        uint256 builderRewardsBalance = protocolRewards.balanceOf(builderReferral);

        vm.prank(builderReferral);
        protocolRewards.withdraw(builderReferral, 0);

        assertEq(builderReferral.balance, beforeBuilderBalance + builderRewardsBalance);
        assertEq(protocolRewards.totalRewardsSupply(), beforeTotalSupply - builderRewardsBalance);
    }

    function testRevert_InvalidWithdrawToAddress() public {
        uint256 builderRewardsBalance = protocolRewards.balanceOf(builderReferral);

        vm.expectRevert(abi.encodeWithSignature("ADDRESS_ZERO()"));
        vm.prank(builderReferral);
        protocolRewards.withdraw(address(0), builderRewardsBalance);
    }

    function testRevert_WithdrawInvalidAmount() public {
        uint256 builderRewardsBalance = protocolRewards.balanceOf(builderReferral);

        vm.expectRevert(abi.encodeWithSignature("INVALID_WITHDRAW()"));
        vm.prank(builderReferral);
        protocolRewards.withdraw(builderReferral, builderRewardsBalance + 1);
    }

    function testWithdrawFor() public {
        uint256 beforeBuilderBalance = builderReferral.balance;
        uint256 beforeTotalSupply = protocolRewards.totalRewardsSupply();

        uint256 builderRewardsBalance = protocolRewards.balanceOf(builderReferral);

        protocolRewards.withdrawFor(builderReferral, builderRewardsBalance);

        assertEq(builderReferral.balance, beforeBuilderBalance + builderRewardsBalance);
        assertEq(protocolRewards.totalRewardsSupply(), beforeTotalSupply - builderRewardsBalance);
    }

    function testWithdrawForFullBalance() public {
        uint256 beforeBuilderBalance = builderReferral.balance;
        uint256 beforeTotalSupply = protocolRewards.totalRewardsSupply();

        uint256 builderRewardsBalance = protocolRewards.balanceOf(builderReferral);

        protocolRewards.withdrawFor(builderReferral, 0);

        assertEq(builderReferral.balance, beforeBuilderBalance + builderRewardsBalance);
        assertEq(protocolRewards.totalRewardsSupply(), beforeTotalSupply - builderRewardsBalance);
    }

    function testRevert_WithdrawForInvalidAmount() public {
        uint256 builderRewardsBalance = protocolRewards.balanceOf(builderReferral);

        vm.expectRevert(abi.encodeWithSignature("INVALID_WITHDRAW()"));
        protocolRewards.withdrawFor(builderReferral, builderRewardsBalance + 1);
    }

    function testRevert_WithdrawForInvalidToAddress() public {
        uint256 builderRewardsBalance = protocolRewards.balanceOf(builderReferral);

        vm.expectRevert(abi.encodeWithSignature("ADDRESS_ZERO()"));
        protocolRewards.withdrawFor(address(0), builderRewardsBalance);
    }

    function testWithdrawWithSig() public {
        uint256 builderRewardsBalance = protocolRewards.balanceOf(builderReferral);

        (, uint256 builderPrivateKey) = makeAddrAndKey("builderReferral");

        uint256 nonce = protocolRewards.nonces(builderReferral);
        uint256 deadline = block.timestamp + 1 days;

        bytes32 withdrawHash = keccak256(abi.encode(protocolRewards.WITHDRAW_TYPEHASH(), builderReferral, builderReferral, builderRewardsBalance, nonce, deadline));

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", getDomainSeparator(), withdrawHash));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(builderPrivateKey, digest);

        uint256 beforeBuilderBalance = builderReferral.balance;
        uint256 beforeTotalSupply = protocolRewards.totalRewardsSupply();

        protocolRewards.withdrawWithSig(builderReferral, builderReferral, builderRewardsBalance, deadline, v, r, s);

        assertEq(builderReferral.balance, beforeBuilderBalance + builderRewardsBalance);
        assertEq(protocolRewards.totalRewardsSupply(), beforeTotalSupply - builderRewardsBalance);
    }

    function testWithdrawWithSigFullBalance() public {
        uint256 builderRewardsBalance = protocolRewards.balanceOf(builderReferral);

        (, uint256 builderPrivateKey) = makeAddrAndKey("builderReferral");

        uint256 nonce = protocolRewards.nonces(builderReferral);
        uint256 deadline = block.timestamp + 1 days;

        bytes32 withdrawHash = keccak256(abi.encode(protocolRewards.WITHDRAW_TYPEHASH(), builderReferral, builderReferral, 0, nonce, deadline));

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", getDomainSeparator(), withdrawHash));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(builderPrivateKey, digest);

        uint256 beforeBuilderBalance = builderReferral.balance;
        uint256 beforeTotalSupply = protocolRewards.totalRewardsSupply();

        protocolRewards.withdrawWithSig(builderReferral, builderReferral, 0, deadline, v, r, s);

        assertEq(builderReferral.balance, beforeBuilderBalance + builderRewardsBalance);
        assertEq(protocolRewards.totalRewardsSupply(), beforeTotalSupply - builderRewardsBalance);
    }

    function testRevert_SigExpired() public {
        uint256 builderRewardsBalance = protocolRewards.balanceOf(builderReferral);
        (, uint256 builderPrivateKey) = makeAddrAndKey("builderReferral");

        uint256 nonce = protocolRewards.nonces(builderReferral);
        uint256 deadline = block.timestamp + 1 days;

        bytes32 withdrawHash = keccak256(abi.encode(protocolRewards.WITHDRAW_TYPEHASH(), builderReferral, builderReferral, builderRewardsBalance, nonce, deadline));

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", getDomainSeparator(), withdrawHash));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(builderPrivateKey, digest);

        vm.warp(deadline + 1);

        vm.expectRevert(abi.encodeWithSignature("SIGNATURE_DEADLINE_EXPIRED()"));
        protocolRewards.withdrawWithSig(builderReferral, builderReferral, builderRewardsBalance, deadline, v, r, s);
    }

    function testRevert_InvalidWithdrawWithSigToAddress() public {
        uint256 builderRewardsBalance = protocolRewards.balanceOf(builderReferral);

        (, uint256 builderPrivateKey) = makeAddrAndKey("builderReferral");

        uint256 nonce = protocolRewards.nonces(builderReferral);
        uint256 deadline = block.timestamp + 1 days;

        bytes32 withdrawHash = keccak256(abi.encode(protocolRewards.WITHDRAW_TYPEHASH(), builderReferral, address(0), builderRewardsBalance, nonce, deadline));

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", getDomainSeparator(), withdrawHash));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(builderPrivateKey, digest);

        vm.expectRevert(abi.encodeWithSignature("ADDRESS_ZERO()"));
        protocolRewards.withdrawWithSig(builderReferral, address(0), builderRewardsBalance, deadline, v, r, s);
    }

    function testRevert_InvalidNonce() public {
        uint256 builderRewardsBalance = protocolRewards.balanceOf(builderReferral);
        (, uint256 builderPrivateKey) = makeAddrAndKey("builderReferral");

        uint256 nonce = protocolRewards.nonces(builderReferral) + 1;
        uint256 deadline = block.timestamp + 1 days;

        bytes32 withdrawHash = keccak256(abi.encode(protocolRewards.WITHDRAW_TYPEHASH(), builderReferral, builderReferral, builderRewardsBalance, nonce, deadline));

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", getDomainSeparator(), withdrawHash));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(builderPrivateKey, digest);

        vm.expectRevert(abi.encodeWithSignature("INVALID_SIGNATURE()"));
        protocolRewards.withdrawWithSig(builderReferral, builderReferral, builderRewardsBalance, deadline, v, r, s);
    }

    function testRevert_InvalidSigner() public {
        uint256 builderRewardsBalance = protocolRewards.balanceOf(builderReferral);
        (address notbuilderReferral, uint256 notBuilderPrivateKey) = makeAddrAndKey("notBuilder");

        uint256 nonce = protocolRewards.nonces(builderReferral);
        uint256 deadline = block.timestamp + 1 days;

        bytes32 withdrawHash = keccak256(abi.encode(protocolRewards.WITHDRAW_TYPEHASH(), builderReferral, notbuilderReferral, builderRewardsBalance, nonce, deadline));

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", getDomainSeparator(), withdrawHash));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(notBuilderPrivateKey, digest);

        vm.expectRevert(abi.encodeWithSignature("INVALID_SIGNATURE()"));
        protocolRewards.withdrawWithSig(builderReferral, notbuilderReferral, builderRewardsBalance, deadline, v, r, s);
    }

    function testRevert_InvalidWithdrawAmount() public {
        uint256 builderRewardsBalance = protocolRewards.balanceOf(builderReferral);
        (, uint256 builderPrivateKey) = makeAddrAndKey("builderReferral");

        uint256 nonce = protocolRewards.nonces(builderReferral);
        uint256 deadline = block.timestamp + 1 days;

        bytes32 withdrawHash = keccak256(abi.encode(protocolRewards.WITHDRAW_TYPEHASH(), builderReferral, builderReferral, builderRewardsBalance + 1, nonce, deadline));

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", getDomainSeparator(), withdrawHash));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(builderPrivateKey, digest);

        vm.expectRevert(abi.encodeWithSignature("INVALID_WITHDRAW()"));
        protocolRewards.withdrawWithSig(builderReferral, builderReferral, builderRewardsBalance + 1, deadline, v, r, s);
    }

    function testRevert_InvalidReplay() public {
        uint256 builderRewardsBalance = protocolRewards.balanceOf(builderReferral);
        (, uint256 builderPrivateKey) = makeAddrAndKey("builderReferral");

        uint256 nonce = protocolRewards.nonces(builderReferral);
        uint256 deadline = block.timestamp + 1 days;

        bytes32 withdrawHash = keccak256(abi.encode(protocolRewards.WITHDRAW_TYPEHASH(), builderReferral, builderReferral, builderRewardsBalance, nonce, deadline));

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", getDomainSeparator(), withdrawHash));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(builderPrivateKey, digest);

        protocolRewards.withdrawWithSig(builderReferral, builderReferral, builderRewardsBalance, deadline, v, r, s);

        vm.expectRevert(abi.encodeWithSignature("INVALID_SIGNATURE()"));
        protocolRewards.withdrawWithSig(builderReferral, builderReferral, builderRewardsBalance, deadline, v, r, s);
    }
}
