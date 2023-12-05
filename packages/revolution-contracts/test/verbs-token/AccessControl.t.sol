// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import { Test } from "forge-std/Test.sol";
import { VerbsToken } from "../../src/VerbsToken.sol";
import { IVerbsToken } from "../../src/interfaces/IVerbsToken.sol";
import { IVerbsDescriptorMinimal } from "../../src/interfaces/IVerbsDescriptorMinimal.sol";
import { IProxyRegistry } from "../../src/external/opensea/IProxyRegistry.sol";
import { ICultureIndex } from "../../src/interfaces/ICultureIndex.sol";
import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";
import { CultureIndex } from "../../src/CultureIndex.sol";
import { MockERC20 } from "../mock/MockERC20.sol";
import { VerbsDescriptor } from "../../src/VerbsDescriptor.sol";
import "../utils/Base64Decode.sol";
import "../utils/JsmnSolLib.sol";
import { VerbsTokenTestSuite } from "./VerbsToken.t.sol";

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
        try verbsToken.cultureIndex().dropTopVotedPiece() {
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
        address nonMinter = address(0xABC); // This is an arbitrary address
        vm.startPrank(nonMinter);

        try verbsToken.mint() {
            fail("Should revert on non-minter mint");
        } catch Error(string memory reason) {
            assertEq(reason, "Sender is not the minter");
        }

        vm.stopPrank();
    }

    /// @dev Tests that only the owner can set the contract URI
    function testSetContractURIByOwner() public {
        verbsToken.setContractURIHash("NewHashHere");
        assertEq(verbsToken.contractURI(), "ipfs://NewHashHere", "Contract URI should be updated");
    }

    /// @dev Tests that non-owners cannot set the contract URI
    function testRevertOnNonOwnerSettingContractURI() public {
        address nonOwner = address(0x1); // Non-owner address
        vm.startPrank(nonOwner);

        bool hasErrorOccurred = false;
        try verbsToken.setContractURIHash("NewHashHere") {
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
        verbsToken.lockMinter();
        verbsToken.lockDescriptor();
        verbsToken.lockCultureIndex();

        // Attempt to change minter, descriptor, or cultureIndex and expect to fail
        address newMinter = address(0xABC);
        address newDescriptor = address(0xDEF);
        address newCultureIndex = address(0x123);

        bool minterLocked = false;
        bool descriptorLocked = false;
        bool cultureIndexLocked = false;

        try verbsToken.setMinter(newMinter) {
            fail("Should fail: minter is locked");
        } catch {
            minterLocked = true;
        }

        try verbsToken.setDescriptor(IVerbsDescriptorMinimal(newDescriptor)) {
            fail("Should fail: descriptor is locked");
        } catch {
            descriptorLocked = true;
        }

        try verbsToken.setCultureIndex(ICultureIndex(newCultureIndex)) {
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
        verbsToken.setContractURIHash("NewHashHere");
        assertEq(verbsToken.contractURI(), "ipfs://NewHashHere", "Owner should be able to change contract URI");

        // Test that non-owner cannot change contract URI
        address nonOwner = address(0x1);
        bool nonOwnerCantChangeContractURI = false;
        vm.startPrank(nonOwner);
        try verbsToken.setContractURIHash("FakeHash") {
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
        verbsToken.setMinter(newMinter);
        assertEq(verbsToken.minter(), newMinter, "Owner should be able to change minter");

        // Test that non-owner cannot change minter
        address nonOwner = address(0x1);
        vm.startPrank(nonOwner);
        bool nonOwnerCantChangeMinter = false;
        try verbsToken.setMinter(nonOwner) {
            fail("Non-owner should not be able to change minter");
        } catch {
            nonOwnerCantChangeMinter = true;
        }
        vm.stopPrank();

        assertTrue(nonOwnerCantChangeMinter, "Non-owner should not be able to change minter");
    }

    /// @dev Tests that only the minter can burn tokens
    function testBurningPermission() public {
        createDefaultArtPiece();
        uint256 tokenId = verbsToken.mint();

        // Try to burn token as a minter
        verbsToken.burn(tokenId);

        // Try to burn token as a non-minter
        address nonMinter = address(0xABC);
        vm.startPrank(nonMinter);
        try verbsToken.burn(tokenId) {
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
        verbsToken.setMinter(newMinter);
        assertEq(verbsToken.minter(), newMinter, "Minter should be updated to new minter");
    }

    /// @dev Tests locking the minter and ensuring it cannot be changed afterwards.
    function testLockMinter() public {
        verbsToken.lockMinter();
        assertTrue(verbsToken.isMinterLocked(), "Minter should be locked");
        vm.expectRevert("Minter is locked");
        verbsToken.setMinter(address(0x456));
    }

    /// @dev Tests that the minter can be set and locked appropriately
    function testMinterAssignmentAndLocking() public {
        createDefaultArtPiece();
        // Test setting the minter and minting a token
        verbsToken.setMinter(address(0x2));
        vm.prank(address(0x2)); // simulate calls from the new minter address
        verbsToken.mint();

        // Lock the minter and attempt to change it, expecting a revert
        verbsToken.lockMinter();
        vm.expectRevert("Minter is locked");
        verbsToken.setMinter(address(0x3));
    }

    /// @dev Tests that the descriptor can be set and locked appropriately
    function testDescriptorLocking() public {
        // Test setting the descriptor
        IVerbsDescriptorMinimal newDescriptor = new VerbsDescriptor(address(this), "Verb");
        verbsToken.setDescriptor(newDescriptor);

        // Lock the descriptor and attempt to change it, expecting a revert
        verbsToken.lockDescriptor();
        vm.expectRevert("Descriptor is locked");
        verbsToken.setDescriptor(newDescriptor);
    }

    /// @dev Tests that the CultureIndex can be set and locked appropriately
    function testCultureIndexLocking() public {
        // Test setting the CultureIndex
        CultureIndex newCultureIndex = new CultureIndex("Vrbs", "Our community Vrbs. Must be 32x32.", address(govToken), address(verbsToken), address(this), 10, 200);
        verbsToken.setCultureIndex(ICultureIndex(address(newCultureIndex)));

        newCultureIndex.setERC721VotingToken(verbsToken);

        // Lock the CultureIndex and attempt to change it, expecting a revert
        verbsToken.lockCultureIndex();
        vm.expectRevert("CultureIndex is locked");
        verbsToken.setCultureIndex(ICultureIndex(address(newCultureIndex)));
    }

    /// @dev Tests updating and locking the descriptor.
    function testDescriptorUpdateAndLock() public {
        IVerbsDescriptorMinimal newDescriptor = IVerbsDescriptorMinimal(address(0x789));
        verbsToken.setDescriptor(newDescriptor);
        assertEq(address(verbsToken.descriptor()), address(newDescriptor), "Descriptor should be updated");

        verbsToken.lockDescriptor();
        assertTrue(verbsToken.isDescriptorLocked(), "Descriptor should be locked");
        vm.expectRevert("Descriptor is locked");
        verbsToken.setDescriptor(IVerbsDescriptorMinimal(address(0xABC)));
    }

    /// @dev Tests updating and locking the CultureIndex.
    function testCultureIndexUpdateAndLock() public {
        ICultureIndex newCultureIndex = ICultureIndex(address(0xDEF));
        verbsToken.setCultureIndex(newCultureIndex);
        assertEq(address(verbsToken.cultureIndex()), address(newCultureIndex), "CultureIndex should be updated");

        verbsToken.lockCultureIndex();
        assertTrue(verbsToken.isCultureIndexLocked(), "CultureIndex should be locked");
        vm.expectRevert("CultureIndex is locked");
        verbsToken.setCultureIndex(ICultureIndex(address(0x101112)));
    }

    /// @dev Tests the `isApprovedForAll` function override for OpenSea proxy.
    function testIsApprovedForAllOverride() public {
        address owner = address(this);
        emit log_address(owner);

        address operator = address(verbsToken.proxyRegistry().proxies(owner));

        emit log_address(operator);

        assertTrue(verbsToken.isApprovedForAll(owner, operator), "OpenSea proxy should be approved");
    }
}

contract ProxyRegistry is IProxyRegistry {
    mapping(address => address) public proxies;
}
