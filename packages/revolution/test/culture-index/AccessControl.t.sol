// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import { Test } from "forge-std/Test.sol";
import { VerbsToken } from "../../src/VerbsToken.sol";
import { IVerbsToken } from "../../src/interfaces/IVerbsToken.sol";
import { IDescriptorMinimal } from "../../src/interfaces/IDescriptorMinimal.sol";
import { ICultureIndex, ICultureIndexEvents } from "../../src/interfaces/ICultureIndex.sol";
import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";
import { CultureIndex } from "../../src/CultureIndex.sol";
import { MockERC20 } from "../mock/MockERC20.sol";
import { Descriptor } from "../../src/Descriptor.sol";
import "../utils/Base64Decode.sol";
import "../utils/JsmnSolLib.sol";
import { CultureIndexTestSuite } from "./CultureIndex.t.sol";
import { ERC721CheckpointableUpgradeable } from "../../src/base/ERC721CheckpointableUpgradeable.sol";

/// @title VerbsTokenTest
/// @dev The test suite for the VerbsToken contract
contract CultureIndexAccessControlTest is CultureIndexTestSuite {
    function testSetQuorumVotesBPSWithinRange(uint104 newQuorumBPS) public {
        vm.assume(newQuorumBPS <= cultureIndex.MAX_QUORUM_VOTES_BPS());

        // Set new quorum BPS by owner
        vm.startPrank(address(erc721Token));
        cultureIndex._setQuorumVotesBPS(newQuorumBPS);
        vm.stopPrank();

        // Check if the quorum BPS is updated correctly
        uint256 currentQuorumBPS = cultureIndex.quorumVotesBPS();
        assertEq(currentQuorumBPS, newQuorumBPS, "Quorum BPS should be updated within valid range");
    }

    function testSetQuorumVotesBPSOutsideRange(uint104 newQuorumBPS) public {
        uint256 currentQuorumBPS = cultureIndex.quorumVotesBPS();
        vm.assume(newQuorumBPS > cultureIndex.MAX_QUORUM_VOTES_BPS());

        // Set new quorum BPS by owner
        vm.startPrank(address(erc721Token));
        vm.expectRevert("CultureIndex::_setQuorumVotesBPS: invalid quorum bps");
        cultureIndex._setQuorumVotesBPS(newQuorumBPS);
        vm.stopPrank();

        // Check if the quorum BPS is updated correctly
        assertEq(cultureIndex.quorumVotesBPS(), currentQuorumBPS, "Quorum BPS should be updated within valid range");
    }

    function testRevertNonOwnerSetQuorumVotesBPS() public {
        vm.stopPrank();
        address nonOwner = address(0x123); // An arbitrary non-owner address
        uint256 newQuorumBPS = 3000; // A valid quorum BPS value

        // Attempt to set new quorum BPS by non-owner and expect revert
        vm.startPrank(nonOwner);
        vm.expectRevert();
        cultureIndex._setQuorumVotesBPS(newQuorumBPS);
        vm.stopPrank();
    }

    function testDropTopVotedPieceOnlyIfQuorumIsMet(uint256 quorumBps) public {
        vm.assume(quorumBps > 200 && quorumBps <= cultureIndex.MAX_QUORUM_VOTES_BPS());

        // Set quorum BPS
        vm.startPrank(address(erc721Token));
        cultureIndex._setQuorumVotesBPS(quorumBps);
        vm.stopPrank();

        vm.startPrank(address(erc20TokenEmitter));
        erc20Token.mint(address(0x21), quorumBps * 10);
        erc20Token.mint(address(this), ((quorumBps / 2) * (quorumBps)) / 10_000);

        // Create an art piece
        uint256 pieceId = createDefaultArtPiece();

        vm.roll(block.number + 2);

        // Vote for the piece, but do not meet the quorum
        vm.startPrank(address(this));
        cultureIndex.vote(pieceId);

        // Attempt to drop the top-voted piece and expect it to fail
        vm.expectRevert("Does not meet quorum votes to be dropped.");
        vm.startPrank(address(erc721Token));
        cultureIndex.dropTopVotedPiece();

        // Additional votes to meet/exceed the quorum
        vm.startPrank(address(0x21));
        cultureIndex.vote(pieceId);
        vm.stopPrank();

        // Attempt to drop the top-voted piece, should succeed
        vm.startPrank(address(erc721Token));
        ICultureIndex.ArtPiece memory droppedPiece = cultureIndex.dropTopVotedPiece();
        assertTrue(droppedPiece.isDropped, "Top voted piece should be dropped");
    }
}
