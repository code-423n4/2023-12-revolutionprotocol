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
import { NontransferableERC20Votes } from "../../src/NontransferableERC20Votes.sol";
import "../utils/Base64Decode.sol";
import "../utils/JsmnSolLib.sol";
import { VerbsTokenTestSuite } from "./VerbsToken.t.sol";

/// @title VerbsTokenTest
/// @dev The test suite for the VerbsToken contract
contract TokenMintingTest is VerbsTokenTestSuite {
    /// @dev Ensures the dropped art piece is equivalent to the top-voted piece
    function testDroppedArtPieceMatchesTopVoted() public {
        govToken.mint(address(this), 10);

        // Create a new art piece and simulate it being the top voted piece
        uint256 pieceId = createDefaultArtPiece();

        // ensure vote snapshot is taken
        vm.roll(block.number + 1);

        cultureIndex.vote(pieceId); // Simulate voting for the piece to make it top-voted

        // Fetch the top voted piece before minting
        ICultureIndex.ArtPiece memory topVotedPieceBeforeMint = cultureIndex.getTopVotedPiece();

        // Mint a token
        uint256 tokenId = verbsToken.mint();

        // Fetch the dropped art piece associated with the minted token
        ICultureIndex.ArtPiece memory droppedArtPiece = verbsToken.getArtPieceById(tokenId);

        // Now compare the relevant fields of topVotedPieceBeforeMint and droppedArtPiece
        assertEq(droppedArtPiece.pieceId, topVotedPieceBeforeMint.pieceId, "Piece ID should match");
        assertEq(droppedArtPiece.dropper, topVotedPieceBeforeMint.dropper, "Dropper address should match");
        //ensure isDropped is now true
        assertTrue(droppedArtPiece.isDropped, "isDropped should be true");
        assertTrue(areArraysEqual(droppedArtPiece.creators, topVotedPieceBeforeMint.creators), "Creators array should match");
        assertTrue(areArtPieceMetadataEqual(droppedArtPiece.metadata, topVotedPieceBeforeMint.metadata), "Metadata should match");
    }

    // Helper function to compare ArtPieceMetadata structs
    function areArtPieceMetadataEqual(ICultureIndex.ArtPieceMetadata memory metadata1, ICultureIndex.ArtPieceMetadata memory metadata2) internal pure returns (bool) {
        return (keccak256(bytes(metadata1.name)) == keccak256(bytes(metadata2.name)) &&
            keccak256(bytes(metadata1.description)) == keccak256(bytes(metadata2.description)) &&
            metadata1.mediaType == metadata2.mediaType &&
            keccak256(bytes(metadata1.image)) == keccak256(bytes(metadata2.image)) &&
            keccak256(bytes(metadata1.text)) == keccak256(bytes(metadata2.text)) &&
            keccak256(bytes(metadata1.animationUrl)) == keccak256(bytes(metadata2.animationUrl)));
    }

    // Helper function to compare arrays of creators
    function areArraysEqual(ICultureIndex.CreatorBps[] memory arr1, ICultureIndex.CreatorBps[] memory arr2) internal pure returns (bool) {
        if (arr1.length != arr2.length) {
            return false;
        }
        for (uint i = 0; i < arr1.length; i++) {
            if (arr1[i].creator != arr2[i].creator || arr1[i].bps != arr2[i].bps) {
                return false;
            }
        }
        return true;
    }

    /// @dev Tests the minting with no pieces added
    function testMintWithNoPieces() public {
        // Try to remove max and expect to fail
        try verbsToken.mint() {
            fail("Should revert on removing max from empty heap");
        } catch Error(string memory reason) {
            assertEq(reason, "Heap is empty");
        }
    }

    /// @dev Tests basic minting
    function testMint() public {
        // Add a piece to the CultureIndex
        createDefaultArtPiece();

        // Mint a token
        uint256 tokenId = verbsToken.mint();

        // Validate the token
        uint256 totalSupply = verbsToken.totalSupply();
        assertEq(verbsToken.ownerOf(tokenId), address(this), "The contract should own the newly minted token");
        assertEq(tokenId, 0, "First token ID should be 1");
        assertEq(totalSupply, 1, "Total supply should be 1");
    }

    /// @dev Tests minting a verb token to itself
    function testMintToItself() public {
        createDefaultArtPiece();

        uint256 initialTotalSupply = verbsToken.totalSupply();
        uint256 newTokenId = verbsToken.mint();
        assertEq(verbsToken.totalSupply(), initialTotalSupply + 1, "One new token should have been minted");
        assertEq(verbsToken.ownerOf(newTokenId), address(this), "The contract should own the newly minted token");
    }

    /// @dev Tests burning a verb token
    function testBurn() public {
        createDefaultArtPiece();

        uint256 tokenId = verbsToken.mint();
        uint256 initialTotalSupply = verbsToken.totalSupply();
        verbsToken.burn(tokenId);
        uint256 newTotalSupply = verbsToken.totalSupply();
        assertEq(newTotalSupply, initialTotalSupply - 1, "Total supply should decrease by 1 after burning");
    }

    /// @dev Ensures _currentVerbId increments correctly after each mint
    function testMintingIncrement(uint200 voteWeight) public {
        govToken.mint(address(1), 10000);

        govToken.mint(address(this), voteWeight);

        uint256 pieceId1 = createDefaultArtPiece();
        uint256 pieceId2 = createDefaultArtPiece();

        // ensure vote snapshot is taken
        vm.roll(block.number + 1);

        if (voteWeight == 0) vm.expectRevert("Weight must be greater than zero");
        cultureIndex.vote(pieceId1);

        bool shouldRevertMint = voteWeight <= (10_000 * cultureIndex.quorumVotesBPS()) / 10_000;

        if (shouldRevertMint) vm.expectRevert("dropTopVotedPiece failed");
        uint256 tokenId1 = verbsToken.mint();
        if (!shouldRevertMint) assertEq(verbsToken.totalSupply(), tokenId1 + 1, "CurrentVerbId should increment after first mint");

        if (voteWeight == 0) vm.expectRevert("Weight must be greater than zero");
        cultureIndex.vote(pieceId2);

        if (shouldRevertMint) vm.expectRevert("dropTopVotedPiece failed");
        uint256 tokenId2 = verbsToken.mint();
        if (!shouldRevertMint) assertEq(verbsToken.totalSupply(), tokenId2 + 1, "CurrentVerbId should increment after second mint");
    }

    /// @dev Checks if the VerbCreated event is emitted with correct parameters on minting
    function testMintingEvent() public {
        createDefaultArtPiece();

        (uint256 pieceId, ICultureIndex.ArtPieceMetadata memory metadata, , , , , , ) = cultureIndex.pieces(0);

        emit log_uint(pieceId);

        ICultureIndex.CreatorBps[] memory creators = new ICultureIndex.CreatorBps[](1);
        creators[0] = ICultureIndex.CreatorBps({ creator: address(0x1), bps: 10000 });

        ICultureIndex.ArtPiece memory expectedArtPiece = ICultureIndex.ArtPiece({
            pieceId: 0,
            metadata: metadata,
            creators: creators,
            dropper: address(this),
            isDropped: true,
            creationBlock: block.number,
            quorumVotes: 0,
            totalERC20Supply: 0,
            totalVotesSupply: 0
        });

        vm.expectEmit(true, true, true, true);

        emit IVerbsToken.VerbCreated(0, expectedArtPiece);

        verbsToken.mint();
    }

    /// @dev Tests the burn function.
    function testBurnFunction() public {
        //create piece
        createDefaultArtPiece();
        uint256 tokenId = verbsToken.mint();

        vm.expectEmit(true, true, true, true);
        emit IVerbsToken.VerbBurned(tokenId);

        verbsToken.burn(tokenId);
        vm.expectRevert("ERC721: owner query for nonexistent token");
        verbsToken.ownerOf(tokenId); // This should fail because the token was burned
    }

    /// @dev Validates that the token URI is correctly set and retrieved
    function testTokenURI() public {
        uint256 artPieceId = createDefaultArtPiece();
        uint256 tokenId = verbsToken.mint();
        (, ICultureIndex.ArtPieceMetadata memory metadata, , , , , , ) = cultureIndex.pieces(artPieceId);
        // Assuming the descriptor returns a fixed URI for the given tokenId
        string memory expectedTokenURI = descriptor.tokenURI(tokenId, metadata);
        assertEq(verbsToken.tokenURI(tokenId), expectedTokenURI, "Token URI should be correctly set and retrieved");
    }

    /// @dev Ensures minting fetches and associates the top-voted piece from CultureIndex
    function testTopVotedPieceMinting() public {
        // Create a new piece and simulate it being the top voted piece
        uint256 pieceId = createDefaultArtPiece(); // This function should exist within the test contract

        govToken.mint(address(this), 10);

        // ensure vote snapshot is taken
        vm.roll(block.number + 1);

        cultureIndex.vote(pieceId); // Assuming vote function exists and we cast 10 votes

        // Mint a token
        uint256 tokenId = verbsToken.mint();

        // Validate the token is associated with the top voted piece
        (uint256 mintedPieceId, , , , , , , ) = verbsToken.artPieces(tokenId);
        assertEq(mintedPieceId, pieceId, "Minted token should be associated with the top voted piece");
    }
}

contract ProxyRegistry is IProxyRegistry {
    mapping(address => address) public proxies;
}
