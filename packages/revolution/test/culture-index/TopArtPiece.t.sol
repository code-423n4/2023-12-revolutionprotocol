// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import { Test } from "forge-std/Test.sol";
import { CultureIndex } from "../../src/CultureIndex.sol";
import { MockERC20 } from "../mock/MockERC20.sol";
import { ICultureIndex } from "../../src/interfaces/ICultureIndex.sol";
import { CultureIndexTestSuite } from "./CultureIndex.t.sol";

/**
 * @title CultureIndexArtPieceTest
 * @dev Test contract for CultureIndex art piece creation
 */
contract CultureIndexArtPieceTest is CultureIndexTestSuite {
    function testVoteAndVerifyTopVotedPiece() public {
        uint256 firstPieceId = voter1Test.createDefaultArtPiece();
        uint256 secondPieceId = voter2Test.createDefaultArtPiece();

        // Mint tokens to the test contracts (acting as voters)
        vm.stopPrank();
        vm.startPrank(address(erc20TokenEmitter));

        erc20Token.mint(address(voter1Test), 100);
        erc20Token.mint(address(voter2Test), 200);

        vm.roll(block.number + 1); // roll block number to enable voting snapshot

        // Vote for the first piece with voter1
        voter1Test.voteForPiece(firstPieceId);
        assertEq(cultureIndex.topVotedPieceId(), firstPieceId, "First piece should be top-voted");

        // Vote for the second piece with voter2
        voter2Test.voteForPiece(secondPieceId);
        assertEq(cultureIndex.topVotedPieceId(), secondPieceId, "Second piece should now be top-voted");

        // Vote for the first piece with voter2
        voter2Test.voteForPiece(firstPieceId);
        assertEq(cultureIndex.topVotedPieceId(), firstPieceId, "First piece should now be top-voted again");

        uint256 thirdPieceId = voter2Test.createDefaultArtPiece();

        erc20Token.mint(address(voter2Test), 21_000);
        vm.roll(block.number + 1); // roll block number to enable voting snapshot

        voter2Test.voteForPiece(thirdPieceId);
        assertEq(cultureIndex.topVotedPieceId(), thirdPieceId, "Third piece should now be top-voted");
    }

    function testFetchTopVotedPiece() public {
        uint256 firstPieceId = voter1Test.createDefaultArtPiece();

        // Mint tokens to voter1
        vm.stopPrank();
        vm.startPrank(address(erc20TokenEmitter));
        erc20Token.mint(address(voter1Test), 100);

        vm.roll(block.number + 1); // roll block number to enable voting snapshot

        // Vote for the first piece
        voter1Test.voteForPiece(firstPieceId);

        ICultureIndex.ArtPiece memory topVotedPiece = cultureIndex.getTopVotedPiece();
        assertEq(topVotedPiece.pieceId, firstPieceId, "Top voted piece should match the voted piece");
    }

    function testCorrectTopVotedPiece() public {
        uint256 firstPieceId = voter1Test.createDefaultArtPiece();
        uint256 secondPieceId = voter2Test.createDefaultArtPiece();

        // Mint tokens to the test contracts (acting as voters)
        vm.stopPrank();
        vm.startPrank(address(erc20TokenEmitter));
        erc20Token.mint(address(voter1Test), 100);
        erc20Token.mint(address(voter2Test), 200);

        vm.roll(block.number + 1); // roll block number to enable voting snapshot

        // Vote for the first piece with voter1
        voter1Test.voteForPiece(firstPieceId);

        // Vote for the second piece with voter2
        voter2Test.voteForPiece(secondPieceId);

        ICultureIndex.ArtPiece memory poppedPiece = cultureIndex.getTopVotedPiece();
        assertEq(poppedPiece.pieceId, secondPieceId, "Top voted piece should be the second piece");
    }

    function testPopTopVotedPiece() public {
        uint256 firstPieceId = voter1Test.createDefaultArtPiece();
        vm.stopPrank();
        vm.startPrank(address(erc20TokenEmitter));
        erc20Token.mint(address(voter1Test), 100);

        vm.roll(block.number + 1); // roll block number to enable voting snapshot

        voter1Test.voteForPiece(firstPieceId);
        vm.startPrank(address(erc721Token));

        ICultureIndex.ArtPiece memory poppedPiece = cultureIndex.dropTopVotedPiece();
        assertEq(poppedPiece.pieceId, firstPieceId, "Popped piece should be the first piece");
    }

    function testRemovedPieceShouldBeReplaced() public {
        uint256 firstPieceId = voter1Test.createDefaultArtPiece();
        uint256 secondPieceId = voter2Test.createDefaultArtPiece();

        vm.stopPrank();
        vm.startPrank(address(erc20TokenEmitter));
        erc20Token.mint(address(voter1Test), 100);
        erc20Token.mint(address(voter2Test), 200);
        vm.roll(block.number + 1); // roll block number to enable voting snapshot

        voter1Test.voteForPiece(firstPieceId);
        voter2Test.voteForPiece(secondPieceId);

        vm.startPrank(address(erc721Token));

        ICultureIndex.ArtPiece memory poppedPiece = cultureIndex.dropTopVotedPiece();
        //assert its the second piece
        assertEq(poppedPiece.pieceId, secondPieceId, "Popped piece should be the second piece");

        uint256 topPieceId = cultureIndex.topVotedPieceId();
        assertEq(topPieceId, firstPieceId, "Top voted piece should be the first piece");
    }

    /// @dev Tests that log gas required to vote on a piece isn't out of control as heap grows
    function testGasForLargeVotes() public {
        vm.stopPrank();
        vm.startPrank(address(erc20TokenEmitter));
        erc20Token.mint(address(voter1Test), 100);
        erc20Token.mint(address(voter2Test), 200);
        vm.roll(block.number + 1); // roll block number to enable voting snapshot

        // Insert a large number of items
        for (uint i = 0; i < 5_000; i++) {
            voter1Test.createDefaultArtPiece();
        }

        vm.roll(block.number + 2); // roll block number to enable voting snapshot

        //vote on all pieces
        for (uint i = 2; i < 5_00; i++) {
            voter1Test.voteForPiece(i);
            voter2Test.voteForPiece(i);
        }

        //vote once and calculate gas used
        uint256 startGas = gasleft();
        voter1Test.voteForPiece(1);
        uint256 gasUsed = startGas - gasleft();
        emit log_uint(gasUsed);

        // Insert a large number of items
        for (uint i = 0; i < 20_000; i++) {
            voter1Test.createDefaultArtPiece();
        }
        vm.stopPrank();
        vm.startPrank(address(erc20TokenEmitter));
        erc20Token.mint(address(voter1Test), 100);
        erc20Token.mint(address(voter2Test), 200);
        vm.roll(block.number + 1); // roll block number to enable voting snapshot

        //vote on all pieces
        for (uint i = 5_002; i < 25_000; i++) {
            voter1Test.voteForPiece(i);
            vm.stopPrank();
            vm.startPrank(address(erc20TokenEmitter));
            erc20Token.mint(address(voter1Test), i);
            erc20Token.mint(address(voter2Test), i * 2);

            voter2Test.voteForPiece(i);
        }

        //vote once and calculate gas used
        startGas = gasleft();
        voter1Test.voteForPiece(5_001);
        uint256 gasUsed2 = startGas - gasleft();
        emit log_uint(gasUsed2);

        //make sure gas used isn't more than double
        assertLt(gasUsed2, 2 * gasUsed, "Gas used should not be more than 100% increase");
    }

    /// @dev Tests the gas used for creating art pieces as the number of items grows.
    function testGasForCreatingArtPieces() public {
        //log gas used for creating the first piece
        uint256 startGas = gasleft();
        voter1Test.createDefaultArtPiece();
        vm.roll(block.number + 1); // roll block number to enable voting snapshot

        uint256 gasUsed = startGas - gasleft();
        emit log_uint(gasUsed);

        // Create a set number of pieces and log the gas used for the last creation.
        vm.stopPrank();
        vm.startPrank(address(erc20TokenEmitter));
        //vote on all pieces
        for (uint i = 1; i < 5_000; i++) {
            erc20Token.mint(address(voter1Test), i + 1);

            if (i == 4_999) {
                startGas = gasleft();
                voter1Test.createDefaultArtPiece();
                gasUsed = startGas - gasleft();
                emit log_uint(gasUsed);
            } else {
                voter1Test.createDefaultArtPiece();
            }
            vm.roll(block.number + 1); // roll block number to enable voting snapshot

            voter1Test.voteForPiece(i);
        }

        //assert dropping top piece is the correct pieceId
        assertEq(cultureIndex.topVotedPieceId(), 4_999, "Top voted piece should be the 4_999th piece");
    }

    /// @dev Tests the gas used for popping the top voted piece to ensure somewhat constant time
    function testGasForPopTopVotedPiece() public {
        // Create and vote on a set number of pieces.
        vm.stopPrank();
        vm.startPrank(address(erc20TokenEmitter));
        for (uint i = 0; i < 5_000; i++) {
            uint256 pieceId = voter1Test.createDefaultArtPiece();
            erc20Token.mint(address(voter1Test), i * 2 + 1);
            vm.roll(block.number + 1); // roll block number to enable voting snapshot

            voter1Test.voteForPiece(pieceId);
        }

        vm.startPrank(address(erc721Token));

        // Pop the top voted piece and log the gas used.
        uint256 startGas = gasleft();

        cultureIndex.dropTopVotedPiece();
        uint256 gasUsed = startGas - gasleft();
        emit log_uint(gasUsed);

        vm.stopPrank();
        vm.startPrank(address(erc20TokenEmitter));
        // Create and vote on another set of pieces.
        for (uint i = 0; i < 25_000; i++) {
            uint256 pieceId = voter1Test.createDefaultArtPiece();
            erc20Token.mint(address(voter1Test), i * 3 + 1);
            vm.roll(block.number + 1); // roll block number to enable voting snapshot

            voter1Test.voteForPiece(pieceId);
        }

        vm.startPrank(address(erc721Token));

        // Pop the top voted piece and log the gas used.
        startGas = gasleft();
        cultureIndex.dropTopVotedPiece();
        uint256 gasUsed2 = startGas - gasleft();
        emit log_uint(gasUsed2);

        assertLt(gasUsed2, gasUsed * 2, "Should not be more than double the gas");
    }

    function testDropTopVotedPieceSequentialOrder() public {
        vm.stopPrank();
        vm.startPrank(address(erc20TokenEmitter));
        // Create some pieces and vote on them
        uint256 pieceId1 = voter1Test.createDefaultArtPiece();
        erc20Token.mint(address(voter1Test), 10);
        vm.roll(block.number + 1); // roll block number to enable voting snapshot

        voter1Test.voteForPiece(pieceId1);

        uint256 pieceId2 = voter1Test.createDefaultArtPiece();
        erc20Token.mint(address(voter1Test), 20);
        vm.roll(block.number + 1); // roll block number to enable voting snapshot

        voter1Test.voteForPiece(pieceId2);

        // Drop the top voted piece
        vm.startPrank(address(erc721Token));
        ICultureIndex.ArtPiece memory artPiece2 = cultureIndex.dropTopVotedPiece();

        // Verify that the dropped piece is correctly indexed
        assertEq(artPiece2.pieceId, pieceId2, "First dropped piece should be pieceId2");

        // Drop another top voted piece
        ICultureIndex.ArtPiece memory artPiece1 = cultureIndex.dropTopVotedPiece();

        // Verify again
        assertEq(artPiece1.pieceId, pieceId1, "Second dropped piece should be pieceId1");
    }

    /// @dev Ensure that the dropTopVotedPiece function behaves correctly when there are no more pieces to drop
    function testDropTopVotedPieceWithNoMorePieces() public {
        vm.stopPrank();
        vm.startPrank(address(erc20TokenEmitter));
        // Create and vote on a single piece
        uint256 pieceId = voter1Test.createDefaultArtPiece();
        erc20Token.mint(address(voter1Test), 10);
        vm.roll(block.number + 1); // roll block number to enable voting snapshot
        voter1Test.voteForPiece(pieceId);

        vm.startPrank(address(erc721Token));

        // Drop the top voted piece
        cultureIndex.dropTopVotedPiece();

        // Try to drop again and expect a failure
        bool hasErrorOccurred = false;
        try cultureIndex.dropTopVotedPiece() {
            // if this executes, there was no error
        } catch {
            // if we're here, an error occurred
            hasErrorOccurred = true;
        }
        assertEq(hasErrorOccurred, true, "Expected an error when trying to drop with no more pieces.");
    }
}
