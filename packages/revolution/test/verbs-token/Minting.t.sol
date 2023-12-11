// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import { Test } from "forge-std/Test.sol";
import { VerbsToken } from "../../src/VerbsToken.sol";
import { IVerbsToken } from "../../src/interfaces/IVerbsToken.sol";
import { IDescriptorMinimal } from "../../src/interfaces/IDescriptorMinimal.sol";
import { ICultureIndex } from "../../src/interfaces/ICultureIndex.sol";
import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";
import { CultureIndex } from "../../src/CultureIndex.sol";
import { MockERC20 } from "../mock/MockERC20.sol";
import { Descriptor } from "../../src/Descriptor.sol";
import { NontransferableERC20Votes } from "../../src/NontransferableERC20Votes.sol";
import "../utils/Base64Decode.sol";
import "../utils/JsmnSolLib.sol";
import { VerbsTokenTestSuite } from "./VerbsToken.t.sol";

/// @title VerbsTokenTest
/// @dev The test suite for the VerbsToken contract
contract TokenMintingTest is VerbsTokenTestSuite {
    /// @dev Ensures the dropped art piece is equivalent to the top-voted piece
    function testDroppedArtPieceMatchesTopVoted() public {
        vm.stopPrank();

        vm.startPrank(address(erc20TokenEmitter));
        erc20Token.mint(address(this), 10);

        // Create a new art piece and simulate it being the top voted piece
        uint256 pieceId = createDefaultArtPiece();

        // ensure vote snapshot is taken
        vm.roll(block.number + 1);

        vm.startPrank(address(this));
        cultureIndex.vote(pieceId); // Simulate voting for the piece to make it top-voted

        // Fetch the top voted piece before minting
        ICultureIndex.ArtPiece memory topVotedPieceBeforeMint = cultureIndex.getTopVotedPiece();

        // Mint a token
        vm.startPrank(address(auction));
        uint256 tokenId = erc721Token.mint();

        // Fetch the dropped art piece associated with the minted token
        ICultureIndex.ArtPiece memory droppedArtPiece = erc721Token.getArtPieceById(tokenId);

        // Now compare the relevant fields of topVotedPieceBeforeMint and droppedArtPiece
        assertEq(droppedArtPiece.pieceId, topVotedPieceBeforeMint.pieceId, "Piece ID should match");
        assertEq(droppedArtPiece.dropper, topVotedPieceBeforeMint.dropper, "Dropper address should match");
        //ensure isDropped is now true
        assertTrue(droppedArtPiece.isDropped, "isDropped should be true");
        assertTrue(
            areArraysEqual(droppedArtPiece.creators, topVotedPieceBeforeMint.creators),
            "Creators array should match"
        );
        assertTrue(
            areArtPieceMetadataEqual(droppedArtPiece.metadata, topVotedPieceBeforeMint.metadata),
            "Metadata should match"
        );
    }

    // Helper function to compare ArtPieceMetadata structs
    function areArtPieceMetadataEqual(
        ICultureIndex.ArtPieceMetadata memory metadata1,
        ICultureIndex.ArtPieceMetadata memory metadata2
    ) internal pure returns (bool) {
        return (keccak256(bytes(metadata1.name)) == keccak256(bytes(metadata2.name)) &&
            keccak256(bytes(metadata1.description)) == keccak256(bytes(metadata2.description)) &&
            metadata1.mediaType == metadata2.mediaType &&
            keccak256(bytes(metadata1.image)) == keccak256(bytes(metadata2.image)) &&
            keccak256(bytes(metadata1.text)) == keccak256(bytes(metadata2.text)) &&
            keccak256(bytes(metadata1.animationUrl)) == keccak256(bytes(metadata2.animationUrl)));
    }

    // Helper function to compare arrays of creators
    function areArraysEqual(
        ICultureIndex.CreatorBps[] memory arr1,
        ICultureIndex.CreatorBps[] memory arr2
    ) internal pure returns (bool) {
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
        try erc721Token.mint() {
            fail("Should revert on removing max from empty heap");
        } catch Error(string memory reason) {
            assertEq(reason, "Culture index is empty");
        }
    }

    /// @dev Tests basic minting
    function testMint() public {
        // Add a piece to the CultureIndex
        createDefaultArtPiece();

        // Mint a token
        uint256 tokenId = erc721Token.mint();

        // Validate the token
        uint256 totalSupply = erc721Token.totalSupply();
        assertEq(erc721Token.ownerOf(tokenId), address(auction), "The contract should own the newly minted token");
        assertEq(tokenId, 0, "First token ID should be 1");
        assertEq(totalSupply, 1, "Total supply should be 1");
    }

    /// @dev Tests minting a verb token to itself
    function testMintToItself() public {
        createDefaultArtPiece();

        uint256 initialTotalSupply = erc721Token.totalSupply();
        uint256 newTokenId = erc721Token.mint();
        assertEq(erc721Token.totalSupply(), initialTotalSupply + 1, "One new token should have been minted");
        assertEq(erc721Token.ownerOf(newTokenId), address(auction), "The contract should own the newly minted token");
    }

    /// @dev Tests burning a verb token
    function testBurn() public {
        createDefaultArtPiece();

        uint256 tokenId = erc721Token.mint();
        uint256 initialTotalSupply = erc721Token.totalSupply();
        erc721Token.burn(tokenId);
        uint256 newTotalSupply = erc721Token.totalSupply();
        assertEq(newTotalSupply, initialTotalSupply - 1, "Total supply should decrease by 1 after burning");
    }

    /// @dev Ensures _currentVerbId increments correctly after each mint
    function testMintingIncrement(uint200 voteWeight) public {
        vm.stopPrank();
        vm.startPrank(address(erc20TokenEmitter));
        erc20Token.mint(address(1), 10000);

        erc20Token.mint(address(this), voteWeight);

        uint256 pieceId1 = createDefaultArtPiece();
        uint256 pieceId2 = createDefaultArtPiece();

        // ensure vote snapshot is taken
        vm.roll(block.number + 1);

        vm.startPrank(address(this));
        if (voteWeight == 0) vm.expectRevert("Weight must be greater than minVoteWeight");
        cultureIndex.vote(pieceId1);

        bool shouldRevertMint = voteWeight <= (10_000 * cultureIndex.quorumVotesBPS()) / 10_000;

        vm.startPrank(address(auction));
        if (shouldRevertMint) vm.expectRevert("dropTopVotedPiece failed");
        uint256 tokenId1 = erc721Token.mint();
        if (!shouldRevertMint)
            assertEq(erc721Token.totalSupply(), tokenId1 + 1, "CurrentVerbId should increment after first mint");

        vm.startPrank(address(this));
        if (voteWeight == 0) vm.expectRevert("Weight must be greater than minVoteWeight");
        cultureIndex.vote(pieceId2);

        vm.startPrank(address(auction));
        if (shouldRevertMint) vm.expectRevert("dropTopVotedPiece failed");
        uint256 tokenId2 = erc721Token.mint();
        if (!shouldRevertMint)
            assertEq(erc721Token.totalSupply(), tokenId2 + 1, "CurrentVerbId should increment after second mint");
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
            dropper: address(auction),
            isDropped: true,
            creationBlock: block.number,
            quorumVotes: 0,
            totalERC20Supply: 0,
            totalVotesSupply: 0
        });

        vm.expectEmit(true, true, true, true);

        emit IVerbsToken.VerbCreated(0, expectedArtPiece);

        erc721Token.mint();
    }

    /// @dev Tests the burn function.
    function testBurnFunction() public {
        //create piece
        createDefaultArtPiece();
        uint256 tokenId = erc721Token.mint();

        vm.expectEmit(true, true, true, true);
        emit IVerbsToken.VerbBurned(tokenId);

        erc721Token.burn(tokenId);
        assertEq(erc721Token.totalSupply(), 0, "Total supply should be 0 after burning");
        assertEq(erc721Token.balanceOf(address(auction)), 0, "Auction should not own any tokens after burning");
    }

    /// @dev Validates that the token URI is correctly set and retrieved
    function testTokenURI() public {
        uint256 artPieceId = createDefaultArtPiece();
        uint256 tokenId = erc721Token.mint();
        (, ICultureIndex.ArtPieceMetadata memory metadata, , , , , , ) = cultureIndex.pieces(artPieceId);
        // Assuming the descriptor returns a fixed URI for the given tokenId
        string memory expectedTokenURI = descriptor.tokenURI(tokenId, metadata);
        assertEq(erc721Token.tokenURI(tokenId), expectedTokenURI, "Token URI should be correctly set and retrieved");
    }

    /// @dev Ensures minting fetches and associates the top-voted piece from CultureIndex
    function testTopVotedPieceMinting() public {
        // Create a new piece and simulate it being the top voted piece
        uint256 pieceId = createDefaultArtPiece(); // This function should exist within the test contract

        vm.startPrank(address(erc20TokenEmitter));
        erc20Token.mint(address(this), 10);

        // ensure vote snapshot is taken
        vm.roll(block.number + 1);

        vm.startPrank(address(this));
        cultureIndex.vote(pieceId); // Assuming vote function exists and we cast 10 votes

        // Mint a token
        vm.startPrank(address(auction));
        uint256 tokenId = erc721Token.mint();

        // Validate the token is associated with the top voted piece
        (uint256 mintedPieceId, , , , , , , ) = erc721Token.artPieces(tokenId);
        assertEq(mintedPieceId, pieceId, "Minted token should be associated with the top voted piece");
    }
}
