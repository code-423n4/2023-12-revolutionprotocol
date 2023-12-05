// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import { Test } from "forge-std/Test.sol";
import { CultureIndex } from "../../src/CultureIndex.sol";
import { MockERC20 } from "../mock/MockERC20.sol";
import { CultureIndexTestSuite } from "./CultureIndex.t.sol";

contract CultureIndexVotingTestManager is CultureIndexTestSuite {
    function testVotingWithDifferentWeights() public {
        uint256 newPieceId = voter1Test.createDefaultArtPiece();

        // Mint tokens to the test contracts (acting as voters)
        govToken.mint(address(voter1Test), 100);
        govToken.mint(address(voter2Test), 200);

        vm.roll(block.number + 1); // advance block for vote snapshotting

        // Call vote from both test instances
        voter1Test.voteForPiece(newPieceId);
        voter2Test.voteForPiece(newPieceId);

        // Validate the weights
        CultureIndex.Vote memory pieceVotes1 = cultureIndex.getVote(newPieceId, address(voter1Test));
        CultureIndex.Vote memory pieceVotes2 = cultureIndex.getVote(newPieceId, address(voter2Test));
        uint256 totalVoteWeight = cultureIndex.totalVoteWeights(newPieceId);

        assertEq(pieceVotes1.voterAddress, address(voter1Test), "Voter address should match");
        assertEq(pieceVotes1.weight, 100, "Voting weight should be 100");

        assertEq(pieceVotes2.voterAddress, address(voter2Test), "Voter address should match");
        assertEq(pieceVotes2.weight, 200, "Voting weight should be 200");
        assertEq(totalVoteWeight, 300, "Total voting weight should be 300");
    }

    function testVoteOnMultiplePieces() public {
        uint256 firstPieceId = voter1Test.createDefaultArtPiece();
        uint256 secondPieceId = voter2Test.createDefaultArtPiece();

        // Mint tokens to a test contract (acting as a voter)
        govToken.mint(address(voter1Test), 100);
        vm.roll(block.number + 1); // advance block for vote snapshotting

        // Call vote from the same test instance for both pieces
        voter1Test.voteForPiece(firstPieceId);
        voter1Test.voteForPiece(secondPieceId);

        // Validate the weights for the first piece
        CultureIndex.Vote memory firstPieceVote = cultureIndex.getVote(firstPieceId, address(voter1Test));
        assertEq(firstPieceVote.voterAddress, address(voter1Test), "Voter address should match");
        assertEq(firstPieceVote.weight, 100, "Voting weight for the first piece should be 100");

        // Validate the weights for the second piece
        CultureIndex.Vote memory secondPieceVote = cultureIndex.getVote(secondPieceId, address(voter1Test));
        assertEq(secondPieceVote.voterAddress, address(voter1Test), "Voter address should match");
        assertEq(secondPieceVote.weight, 100, "Voting weight for the second piece should be 100");
    }
}
