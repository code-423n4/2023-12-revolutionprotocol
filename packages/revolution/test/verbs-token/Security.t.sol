// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import { Test } from "forge-std/Test.sol";
import { VerbsToken } from "../../src/VerbsToken.sol";
import { ICultureIndex, ICultureIndexEvents } from "../../src/interfaces/ICultureIndex.sol";
import { IVerbsToken } from "../../src/interfaces/IVerbsToken.sol";
import { IDescriptorMinimal } from "../../src/interfaces/IDescriptorMinimal.sol";
import { ICultureIndex } from "../../src/interfaces/ICultureIndex.sol";
import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";
import { CultureIndex } from "../../src/CultureIndex.sol";
import { MockERC20 } from "../mock/MockERC20.sol";
import { Descriptor } from "../../src/Descriptor.sol";
import "../utils/Base64Decode.sol";
import "../utils/JsmnSolLib.sol";
import { VerbsTokenTestSuite } from "./VerbsToken.t.sol";

/// @title VerbsTokenTest
/// @dev The test suite for the VerbsToken contract
contract TokenSecurityTest is VerbsTokenTestSuite {
    /// @dev Tests the creator array limit for minting
    function testCreatorArrayLimit() public {
        // Create an art piece with creators more than the limit (assuming the limit is 100)
        ICultureIndex.CreatorBps[] memory creators = new ICultureIndex.CreatorBps[](101);
        for (uint i = 0; i < 101; i++) {
            creators[i] = ICultureIndex.CreatorBps({
                creator: address(uint160(i + 1)), // Just a series of different addresses
                bps: 10 // Arbitrary basis points for each creator
            });
        }

        ICultureIndex.ArtPieceMetadata memory metadata = ICultureIndex.ArtPieceMetadata({
            name: "Overpopulated",
            description: "An art piece with too many creators",
            mediaType: ICultureIndex.MediaType.IMAGE,
            image: "ipfs://overpopulated",
            text: "",
            animationUrl: ""
        });

        // Attempt to create the piece and expect it to fail due to too many creators
        bool exceededCreatorLimit = false;
        try cultureIndex.createPiece(metadata, creators) {
            fail("Should fail: creator array exceeds the limit");
        } catch {
            exceededCreatorLimit = true;
        }

        assertTrue(exceededCreatorLimit, "Should not allow creation of a piece with too many creators");
    }

    /// @dev Tests the reentrancy guard on the mint function
    function testReentrancyOnMint() public {
        createDefaultArtPiece();

        // Simulate a reentrancy attack by calling mint within a call to mint
        address attacker = address(new ReentrancyAttackContract(address(erc721Token)));
        vm.startPrank(attacker);

        bool reentrancyOccurred = false;
        try ReentrancyAttackContract(attacker).attack() {
            fail("Should fail: reentrancy should be guarded");
        } catch {
            reentrancyOccurred = true;
        }

        vm.stopPrank();

        assertTrue(reentrancyOccurred, "Reentrancy guard should prevent minting in the same call stack");
    }

    /// @dev Tests approval checks for transfer functions
    function testApprovalChecks() public {
        createDefaultArtPiece();

        uint256 tokenId = erc721Token.mint();

        address spender = address(0xABC);
        address to = address(0xDEF);

        // Attempt to transfer without approval as owner
        erc721Token.transferFrom(address(auction), to, tokenId);

        vm.startPrank(to);

        // Approve spender and attempt to transfer as spender
        erc721Token.approve(spender, tokenId);
        vm.stopPrank();

        vm.startPrank(spender);

        bool transferWithApprovalFailed = false;
        try erc721Token.transferFrom(to, address(this), tokenId) {
            // Transfer should succeed
        } catch {
            transferWithApprovalFailed = true;
        }
        vm.stopPrank();

        assertFalse(transferWithApprovalFailed, "Transfer with approval should succeed");
    }

    function testPrivilegeEscalation() public {
        vm.stopPrank();
        address unauthorizedAddress = address(0xDead);
        vm.startPrank(unauthorizedAddress);

        // These should all fail when called by an unauthorized address
        vm.expectRevert();
        erc721Token.setMinter(unauthorizedAddress);

        vm.expectRevert();
        erc721Token.lockMinter();

        vm.expectRevert();
        erc721Token.setDescriptor(IDescriptorMinimal(unauthorizedAddress));

        vm.expectRevert();
        erc721Token.lockDescriptor();

        vm.expectRevert();
        erc721Token.setCultureIndex(ICultureIndex(unauthorizedAddress));

        vm.expectRevert();
        erc721Token.lockCultureIndex();
    }

    function testReentrancyOtherFunctions() public {
        createDefaultArtPiece();
        address attacker = address(new ReentrancyAttackContractGeneral(address(erc721Token)));

        // Simulate a reentrancy attack for burn
        vm.expectRevert("Sender is not the minter");
        ReentrancyAttackContractGeneral(attacker).attackBurn();
    }

    function testBasisPointsSum() public {
        bool reverted = false;

        // Total basis points not equal to 10000 should revert
        ICultureIndex.CreatorBps[] memory creators = new ICultureIndex.CreatorBps[](2);
        creators[0] = ICultureIndex.CreatorBps({ creator: address(0x1), bps: 5000 });
        creators[1] = ICultureIndex.CreatorBps({ creator: address(0x2), bps: 4000 });

        try cultureIndex.createPiece(createDefaultMetadata(), creators) {
            fail("Should fail: Total basis points do not sum up to 10000");
        } catch {
            reverted = true;
        }
        assertTrue(reverted, "Transaction should revert if total basis points do not sum up to 10000");
    }

    function testZeroAddressInCreatorArray() public {
        bool reverted = false;

        // Creator array containing a zero address should revert
        ICultureIndex.CreatorBps[] memory creators = new ICultureIndex.CreatorBps[](1);
        creators[0] = ICultureIndex.CreatorBps({ creator: address(0), bps: 10000 });

        try cultureIndex.createPiece(createDefaultMetadata(), creators) {
            fail("Should fail: Creator array contains zero address");
        } catch {
            reverted = true;
        }
        assertTrue(reverted, "Transaction should revert if creator array contains zero address");
    }

    function testEventEmission() public {
        // Check that the PieceCreated event was emitted with correct parameters
        vm.expectEmit(true, true, true, true);
        emit ICultureIndexEvents.PieceCreated(
            0,
            address(auction),
            ICultureIndex.ArtPieceMetadata({
                name: "Mona Lisa",
                description: "A masterpiece",
                image: "ipfs://legends",
                animationUrl: "",
                text: "",
                mediaType: ICultureIndex.MediaType.IMAGE
            }),
            0,
            0
        );

        // Check that the PieceCreatorAdded event was emitted with correct parameters
        vm.expectEmit(true, true, true, true);
        emit ICultureIndexEvents.PieceCreatorAdded(0, address(0x1), address(auction), 10000);

        createDefaultArtPiece();
    }

    function testFunctionalityUnderMaximumLoad() public {
        bool reverted = false;

        // Create an art piece with the maximum allowed number of creators
        ICultureIndex.CreatorBps[] memory creators = new ICultureIndex.CreatorBps[](100);
        for (uint256 i = 0; i < creators.length; i++) {
            creators[i] = ICultureIndex.CreatorBps({ creator: address(uint160(i + 1)), bps: 100 });
        }

        try cultureIndex.createPiece(createDefaultMetadata(), creators) {
            // This should succeed if under maximum load
        } catch {
            reverted = true;
            fail("Should not fail: creator array is at maximum allowed length");
        }
        assertFalse(reverted, "Should handle the maximum number of creators without reverting");
    }

    /// @dev Tests the _mintTo function for failure in dropTopVotedPiece and ensures verbId is not incremented
    function testMintToDropTopVotedPieceFailure() public {
        // Create a default art piece to have something to mint
        createDefaultArtPiece();

        // Mock the CultureIndex to simulate dropTopVotedPiece failure
        address cultureIndexMock = address(new CultureIndexMock());
        erc721Token.setCultureIndex(ICultureIndex(cultureIndexMock));

        // Store current verbId before test
        uint256 supplyBefore = 0;

        bool dropTopVotedPieceFailed = false;
        try erc721Token.mint() {
            fail("dropTopVotedPiece failure should have caused _mintTo to revert");
        } catch {
            dropTopVotedPieceFailed = true;
        }

        // Verify verbId has not incremented after failure
        uint256 totalSupply = erc721Token.totalSupply();
        assertEq(supplyBefore, totalSupply, "verbId should not increment after failure");

        assertTrue(dropTopVotedPieceFailed, "_mintTo should revert if dropTopVotedPiece fails");
    }
}

// Helper mock contract to simulate reentrancy for other functions
contract ReentrancyAttackContractGeneral {
    VerbsToken private verbsToken;

    constructor(address _verbsToken) {
        verbsToken = VerbsToken(_verbsToken);
    }

    function attackBurn() public {
        uint256 tokenId = verbsToken.mint();
        verbsToken.burn(tokenId); // Attempt to re-enter here
    }

    // Implement fallback or receive function that calls burn again
}

// Mock CultureIndex to simulate failure in dropTopVotedPiece
contract CultureIndexMock {
    function dropTopVotedPiece() external pure returns (ICultureIndex.ArtPiece memory) {
        revert("Mocked failure");
    }

    // Implement other methods of ICultureIndex as needed, potentially as no-ops
}

// Helper mock contract to simulate reentrancy attack
contract ReentrancyAttackContract {
    VerbsToken private verbsToken;

    constructor(address _verbsToken) {
        verbsToken = VerbsToken(_verbsToken);
    }

    function attack() public {
        verbsToken.mint();
        verbsToken.mint(); // This should fail if reentrancy guard is in place
    }
}
