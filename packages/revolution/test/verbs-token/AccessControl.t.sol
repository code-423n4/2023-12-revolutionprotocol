// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import { Test } from "forge-std/Test.sol";
import { VerbsToken } from "../../src/VerbsToken.sol";
import { IVerbsToken } from "../../src/interfaces/IVerbsToken.sol";
import { IDescriptor } from "../../src/interfaces/IDescriptor.sol";
import { ICultureIndex } from "../../src/interfaces/ICultureIndex.sol";
import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";
import { CultureIndex } from "../../src/CultureIndex.sol";
import { MockERC20 } from "../mock/MockERC20.sol";
import { Descriptor } from "../../src/Descriptor.sol";
import "../utils/Base64Decode.sol";
import "../utils/JsmnSolLib.sol";
import { VerbsTokenTestSuite } from "./VerbsToken.t.sol";
import { ERC1967Proxy } from "../../src/libs/proxy/ERC1967Proxy.sol";

/// @title VerbsTokenTest
/// @dev The test suite for the VerbsToken contract
contract TokenAccessControlTest is VerbsTokenTestSuite {
    /// @dev Tests that non-owners cannot call dropTopVotedPiece on CultureIndex
    function testNonOwnerCannotCallDropTopVotedPiece() public {
        // Assuming the CultureIndex is already set up and there are some pieces with votes
        createDefaultArtPiece();

        // Use an arbitrary non-owner address for the test
        address nonOwner = address(0xBEEF);
        vm.startPrank(nonOwner);

        bool hasErrorOccurred = false;
        try erc721Token.cultureIndex().dropTopVotedPiece() {
            fail("Should revert when non-owner tries to call dropTopVotedPiece");
        } catch {
            // Catch the revert to confirm that the correct access control is in place
            hasErrorOccurred = true;
        }

        vm.stopPrank();

        // Assert that an error did indeed occur, indicating that the call was not allowed
        assertEq(hasErrorOccurred, true, "Non-owner should not be able to call dropTopVotedPiece");
    }

    /// @dev Tests minting by non-minter should revert
    function testRevertOnNonMinterMint() public {
        vm.stopPrank();
        address nonMinter = address(0xABC); // This is an arbitrary address
        vm.startPrank(nonMinter);

        try erc721Token.mint() {
            fail("Should revert on non-minter mint");
        } catch Error(string memory reason) {
            assertEq(reason, "Sender is not the minter");
        }

        vm.stopPrank();
    }

    /// @dev Tests that only the owner can set the contract URI
    function testSetContractURIByOwner() public {
        erc721Token.setContractURIHash("NewHashHere");
        assertEq(erc721Token.contractURI(), "ipfs://NewHashHere", "Contract URI should be updated");
    }

    /// @dev Tests that non-owners cannot set the contract URI
    function testRevertOnNonOwnerSettingContractURI() public {
        vm.stopPrank();
        address nonOwner = address(0x1); // Non-owner address
        vm.startPrank(nonOwner);

        bool hasErrorOccurred = false;
        try erc721Token.setContractURIHash("NewHashHere") {
            fail("Should revert on non-owner setting contract URI");
        } catch {
            hasErrorOccurred = true;
        }

        vm.stopPrank();

        assertEq(hasErrorOccurred, true, "Expected an error but none was thrown.");
    }

    /// @dev Tests the locking of admin functions
    function testLockAdminFunctions() public {
        // Lock the minter, descriptor, and cultureIndex to prevent changes
        erc721Token.lockMinter();
        erc721Token.lockDescriptor();
        erc721Token.lockCultureIndex();

        // Attempt to change minter, descriptor, or cultureIndex and expect to fail
        address newMinter = address(0xABC);
        address newDescriptor = address(0xDEF);
        address newCultureIndex = address(0x123);

        bool minterLocked = false;
        bool descriptorLocked = false;
        bool cultureIndexLocked = false;

        try erc721Token.setMinter(newMinter) {
            fail("Should fail: minter is locked");
        } catch {
            minterLocked = true;
        }

        try erc721Token.setDescriptor(IDescriptor(newDescriptor)) {
            fail("Should fail: descriptor is locked");
        } catch {
            descriptorLocked = true;
        }

        try erc721Token.setCultureIndex(ICultureIndex(newCultureIndex)) {
            fail("Should fail: cultureIndex is locked");
        } catch {
            cultureIndexLocked = true;
        }

        assertTrue(minterLocked, "Minter should be locked");
        assertTrue(descriptorLocked, "Descriptor should be locked");
        assertTrue(cultureIndexLocked, "CultureIndex should be locked");
    }

    /// @dev Tests that only the owner can call owner-specific functions
    function testOwnerPrivileges() public {
        // Test only owner can change contract URI
        erc721Token.setContractURIHash("NewHashHere");
        assertEq(erc721Token.contractURI(), "ipfs://NewHashHere", "Owner should be able to change contract URI");

        // Test that non-owner cannot change contract URI
        address nonOwner = address(0x1);
        bool nonOwnerCantChangeContractURI = false;
        vm.startPrank(nonOwner);
        try erc721Token.setContractURIHash("FakeHash") {
            fail("Non-owner should not be able to change contract URI");
        } catch {
            nonOwnerCantChangeContractURI = true;
        }
        vm.stopPrank();

        assertTrue(nonOwnerCantChangeContractURI, "Non-owner should not be able to change contract URI");
    }

    /// @dev Tests setting and updating the minter address
    function testMinterAssignment() public {
        // Test only owner can change minter
        address newMinter = address(0xABC);
        erc721Token.setMinter(newMinter);
        assertEq(erc721Token.minter(), newMinter, "Owner should be able to change minter");

        // Test that non-owner cannot change minter
        address nonOwner = address(0x1);
        vm.startPrank(nonOwner);
        bool nonOwnerCantChangeMinter = false;
        try erc721Token.setMinter(nonOwner) {
            fail("Non-owner should not be able to change minter");
        } catch {
            nonOwnerCantChangeMinter = true;
        }
        vm.stopPrank();

        assertTrue(nonOwnerCantChangeMinter, "Non-owner should not be able to change minter");
    }

    /// @dev Tests that only the minter can burn tokens
    function testBurningPermission() public {
        vm.stopPrank();
        vm.startPrank(address(auction));
        createDefaultArtPiece();
        uint256 tokenId = erc721Token.mint();

        // Try to burn token as a minter
        erc721Token.burn(tokenId);

        // Try to burn token as a non-minter
        address nonMinter = address(0xABC);
        vm.startPrank(nonMinter);
        try erc721Token.burn(tokenId) {
            fail("Non-minter should not be able to burn tokens");
        } catch Error(string memory reason) {
            assertEq(reason, "Sender is not the minter");
        }
        vm.stopPrank();
    }

    /// @dev Tests setting a new minter.
    function testSetMinter() public {
        address newMinter = address(0x123);
        vm.expectEmit(true, true, true, true);
        emit IVerbsToken.MinterUpdated(newMinter);
        erc721Token.setMinter(newMinter);
        assertEq(erc721Token.minter(), newMinter, "Minter should be updated to new minter");
    }

    /// @dev Tests locking the minter and ensuring it cannot be changed afterwards.
    function testLockMinter() public {
        erc721Token.lockMinter();
        assertTrue(erc721Token.isMinterLocked(), "Minter should be locked");
        vm.expectRevert("Minter is locked");
        erc721Token.setMinter(address(0x456));
    }

    /// @dev Tests that the minter can be set and locked appropriately
    function testMinterAssignmentAndLocking() public {
        createDefaultArtPiece();
        // Test setting the minter and minting a token
        erc721Token.setMinter(address(0x2));
        vm.startPrank(address(0x2)); // simulate calls from the new minter address
        erc721Token.mint();

        vm.startPrank(address(dao));
        // Lock the minter and attempt to change it, expecting a revert
        erc721Token.lockMinter();
        vm.expectRevert("Minter is locked");
        erc721Token.setMinter(address(0x3));
    }

    /// @dev Tests that the descriptor can be set and locked appropriately
    function testDescriptorLocking() public {
        vm.stopPrank();

        // Test setting the descriptor
        // IDescriptor newDescriptor = new Descriptor(address(this));
        address newDescriptor = address(new ERC1967Proxy(descriptorImpl, ""));

        vm.startPrank(address(manager));
        IDescriptor(newDescriptor).initialize(address(this), "Verb");

        vm.startPrank(address(dao));
        erc721Token.setDescriptor(IDescriptor(newDescriptor));

        // Lock the descriptor and attempt to change it, expecting a revert
        erc721Token.lockDescriptor();
        vm.expectRevert("Descriptor is locked");
        erc721Token.setDescriptor(IDescriptor(newDescriptor));
    }

    /// @dev Tests updating and locking the descriptor.
    function testDescriptorUpdateAndLock() public {
        IDescriptor newDescriptor = IDescriptor(address(0x789));
        erc721Token.setDescriptor(newDescriptor);
        assertEq(address(erc721Token.descriptor()), address(newDescriptor), "Descriptor should be updated");

        erc721Token.lockDescriptor();
        assertTrue(erc721Token.isDescriptorLocked(), "Descriptor should be locked");
        vm.expectRevert("Descriptor is locked");
        erc721Token.setDescriptor(IDescriptor(address(0xABC)));
    }

    /// @dev Tests updating and locking the CultureIndex.
    function testCultureIndexUpdateAndLock() public {
        ICultureIndex newCultureIndex = ICultureIndex(address(0xDEF));
        erc721Token.setCultureIndex(newCultureIndex);
        assertEq(address(erc721Token.cultureIndex()), address(newCultureIndex), "CultureIndex should be updated");

        erc721Token.lockCultureIndex();
        assertTrue(erc721Token.isCultureIndexLocked(), "CultureIndex should be locked");
        vm.expectRevert("CultureIndex is locked");
        erc721Token.setCultureIndex(ICultureIndex(address(0x101112)));
    }
}
