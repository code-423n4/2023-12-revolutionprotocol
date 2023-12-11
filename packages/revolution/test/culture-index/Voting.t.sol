// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import { Test } from "forge-std/Test.sol";
import { CultureIndex } from "../../src/CultureIndex.sol";
import { MockERC20 } from "../mock/MockERC20.sol";
import { ICultureIndex } from "../../src/interfaces/ICultureIndex.sol";
import { NontransferableERC20Votes } from "../../src/NontransferableERC20Votes.sol";
import { CultureIndexTestSuite } from "./CultureIndex.t.sol";

/**
 * @title CultureIndexTest
 * @dev Test contract for CultureIndex
 */
contract CultureIndexVotingBasicTest is CultureIndexTestSuite {
    /// @dev Tests the vote weight calculation with ERC721 token
    function testCalculateVoteWeight() public {
        address voter = address(0x1);
        uint256 erc20Weight = 100;
        uint256 erc721Weight = 2; // Number of ERC721 tokens held by the voter

        // Mock the ERC20 and ERC721 token balances
        vm.mockCall(
            address(cultureIndex.erc20VotingToken()),
            abi.encodeWithSelector(erc20Token.getVotes.selector, voter),
            abi.encode(erc20Weight)
        );
        vm.mockCall(
            address(cultureIndex.erc721VotingToken()),
            abi.encodeWithSelector(cultureIndex.getVotes.selector, voter),
            abi.encode(erc721Weight)
        );

        uint256 expectedWeight = erc20Weight + (erc721Weight * cultureIndex.erc721VotingTokenWeight() * 1e18);
        uint256 actualWeight = cultureIndex.getVotes(voter);
        assertEq(expectedWeight, actualWeight);
    }

    /// @dev Tests voting with ERC721 token
    function testVoteWithERC721Token() public {
        uint pieceId = createDefaultArtPiece();

        address voter = address(0x1);
        uint256 erc721Weight = 3; // Number of ERC721 tokens held by the voter

        // Mock ERC721 token balance
        vm.mockCall(
            address(cultureIndex.erc721VotingToken()),
            abi.encodeWithSelector(cultureIndex.getPastVotes.selector, voter, block.number),
            abi.encode(erc721Weight)
        );

        // Cast vote
        vm.startPrank(voter);
        vm.roll(block.number + 1);
        cultureIndex.vote(pieceId);
        vm.stopPrank();

        // Check vote is recorded with correct weight
        uint256 expectedWeight = erc721Weight * cultureIndex.erc721VotingTokenWeight() * 1e18;
        ICultureIndex.Vote memory vote = cultureIndex.getVote(pieceId, voter);
        assertEq(vote.weight, expectedWeight);
    }

    /// @dev Tests impact of vote weights on top-voted piece ranking
    function testVoteWeightImpactOnTopVotedPiece() public {
        uint256 pieceId1 = createDefaultArtPiece();
        address voter1 = address(0x1);
        address voter2 = address(0x2);

        // Voter1 votes for piece1
        vm.stopPrank();
        vm.startPrank(address(erc20TokenEmitter));
        erc20Token.mint(voter1, 100);
        vm.roll(block.number + 1); // Roll forward to ensure votes are snapshotted

        vm.startPrank(voter1);
        cultureIndex.vote(pieceId1);
        vm.stopPrank();

        uint256 pieceId2 = createDefaultArtPiece();

        // Voter2 votes for piece2 with higher weight
        vm.startPrank(address(erc20TokenEmitter));
        erc20Token.mint(voter2, 200);
        vm.roll(block.number + 2); // Roll forward to ensure votes are snapshotted

        vm.startPrank(voter2);
        cultureIndex.vote(pieceId2);

        // Check top-voted piece
        ICultureIndex.ArtPiece memory topVotedPiece = cultureIndex.getTopVotedPiece();
        assertEq(topVotedPiece.pieceId, pieceId2, "Piece with higher total vote weight should be top voted");
    }

    function testNoDoubleVotingAfterERC721Transfer() public {
        // create 2 art pieces
        createDefaultArtPiece();
        uint256 artPieceId = createDefaultArtPiece();
        address voter = address(0x1);
        address recipient = address(0x2);
        uint256 tokenId = 0;

        // Mint an ERC721 token to the voter
        vm.startPrank(address(auction));
        erc721Token.mint();
        erc721Token.transferFrom(address(auction), voter, tokenId);
        assertEq(erc721Token.ownerOf(tokenId), voter);

        // Voter casts a vote for the art piece
        vm.startPrank(voter);
        vm.roll(block.number + 1);
        cultureIndex.vote(artPieceId);
        vm.stopPrank();

        // Transfer the ERC721 token from voter to recipient
        vm.startPrank(voter);
        erc721Token.transferFrom(voter, recipient, tokenId);
        vm.stopPrank();
        assertEq(erc721Token.ownerOf(tokenId), recipient);

        // Attempt to have the original voter cast another vote
        vm.startPrank(voter);
        vm.expectRevert("Already voted");
        cultureIndex.vote(artPieceId);
        vm.stopPrank();

        // Attempt to have recipient cast a vote
        vm.startPrank(recipient);
        vm.expectRevert("Weight must be greater than minVoteWeight");
        cultureIndex.vote(artPieceId);
        vm.stopPrank();
    }

    /// @dev Tests reset of vote weight after transferring all tokens
    function testVoteWeightResetAfterTokenTransfer() public {
        uint256 pieceId = createDefaultArtPiece();
        address voter = address(0x1);
        uint256 voteWeight = 100;

        // Set initial token balance and cast vote
        vm.stopPrank();
        vm.startPrank(address(erc20TokenEmitter));
        erc20Token.mint(voter, voteWeight);
        vm.startPrank(voter);
        vm.roll(block.number + 1);

        cultureIndex.vote(pieceId);
        vm.stopPrank();

        vm.startPrank(address(erc20TokenEmitter));
        erc20Token.mint(voter, voteWeight);

        vm.startPrank(address(auction));
        erc721Token.mint(); // Mint an ERC721 token to the owner

        // ensure that the ERC721 token is minted
        assertEq(erc721Token.balanceOf(address(auction)), 1, "ERC721 token should be minted");
        // ensure cultureindex currentvotes is correct
        assertEq(
            cultureIndex.getVotes(address(auction)),
            cultureIndex.erc721VotingTokenWeight() * 1e18,
            "Vote weight should be correct"
        );

        // burn the 721
        erc721Token.burn(0);

        // ensure that the ERC721 token is burned
        assertEq(erc721Token.balanceOf(address(auction)), 0, "ERC721 token should be burned");

        // ensure cultureindex currentvotes is correct
        assertEq(cultureIndex.getVotes(address(auction)), 0, "Vote weight should be correct");

        // ensure that the erc20 token balance is reflected for voter
        uint256 newWeight = cultureIndex.getVotes(voter);
        assertEq(newWeight, voteWeight * 2, "Vote weight should reset to zero after transferring all tokens");
    }

    /// @dev Tests that voting for an invalid piece ID fails
    function testRejectVoteForInvalidPieceId() public {
        uint256 invalidPieceId = 99999; // Assume this is an invalid ID
        address voter = address(0x1);
        vm.stopPrank();
        vm.startPrank(address(erc20TokenEmitter));
        erc20Token.mint(voter, 100);

        vm.startPrank(voter);
        vm.roll(block.number + 1);
        vm.expectRevert("Invalid piece ID");
        cultureIndex.vote(invalidPieceId);
        vm.stopPrank();
    }

    /// @dev Tests vote weight calculation with changing token balances
    function testVoteWeightWithChangingTokenBalances() public {
        uint256 pieceId = createDefaultArtPiece();
        createDefaultArtPiece();
        address voter = address(this);
        uint256 initialErc20Weight = 50;

        // Set initial token balances
        vm.stopPrank();
        vm.startPrank(address(erc20TokenEmitter));
        erc20Token.mint(voter, initialErc20Weight);

        vm.startPrank(address(auction));
        erc721Token.mint();
        //transfer to voter
        erc721Token.transferFrom(address(auction), voter, 0);

        uint256 initialWeight = cultureIndex.getVotes(voter);
        uint256 expectedInitialWeight = initialErc20Weight + (1 * cultureIndex.erc721VotingTokenWeight() * 1e18);
        assertEq(initialWeight, expectedInitialWeight);

        // Change token balances
        uint256 updateErc20Weight = 100; // Increased ERC20 weight

        vm.startPrank(address(erc20TokenEmitter));
        erc20Token.mint(voter, updateErc20Weight);

        vm.startPrank(address(auction));
        erc721Token.mint();
        // transfer to voter
        erc721Token.transferFrom(address(auction), voter, 1);

        uint256 updatedWeight = cultureIndex.getVotes(voter);
        uint256 expectedUpdatedWeight = updateErc20Weight +
            initialErc20Weight +
            (2 * cultureIndex.erc721VotingTokenWeight() * 1e18);
        assertEq(updatedWeight, expectedUpdatedWeight);

        //burn the first 2 verbs
        erc721Token.burn(0);
        erc721Token.burn(1);

        // ensure that the ERC721 token is burned
        assertEq(erc721Token.balanceOf(address(voter)), 0, "ERC721 token should be burned");

        // ensure cultureindex currentvotes is correct
        assertEq(
            cultureIndex.getVotes(address(voter)),
            updateErc20Weight + initialErc20Weight,
            "Vote weight should be correct"
        );
    }

    /**
     * @dev Test case to validate voting functionality
     *
     * We create a new art piece and cast a vote for it.
     * Then we validate the recorded vote and total voting weight.
     */
    function testVoting() public {
        uint256 newPieceId = createArtPiece(
            "Mona Lisa",
            "A masterpiece",
            ICultureIndex.MediaType.IMAGE,
            "ipfs://legends",
            "",
            "",
            address(0x1),
            10000
        );

        // Mint some tokens to the voter
        vm.stopPrank();
        vm.startPrank(address(erc20TokenEmitter));
        erc20Token.mint(address(this), 100);

        vm.roll(block.number + 1); // Roll forward to ensure votes are snapshotted

        // Cast a vote
        vm.startPrank(address(this));
        cultureIndex.vote(newPieceId);

        // Validate the vote
        ICultureIndex.Vote memory pieceVotes = cultureIndex.getVote(newPieceId, address(this));
        uint256 totalVoteWeight = cultureIndex.totalVoteWeights(newPieceId);

        assertEq(pieceVotes.voterAddress, address(this), "Voter address should match");
        assertEq(pieceVotes.weight, 100, "Voting weight should be 100");
        assertEq(totalVoteWeight, 100, "Total voting weight should be 100");
    }

    function testBatchVotingSuccess() public {
        // Preconditions setup
        uint256[] memory pieceIds = new uint256[](2);
        pieceIds[0] = createDefaultArtPiece();
        pieceIds[1] = createDefaultArtPiece();
        vm.stopPrank();
        vm.startPrank(address(erc20TokenEmitter));
        erc20Token.mint(address(this), 200);
        vm.roll(block.number + 1); // Roll forward to ensure votes are snapshotted

        // Perform batch voting
        vm.startPrank(address(this));
        cultureIndex.voteForMany(pieceIds);

        // Assertions
        for (uint256 i = 0; i < pieceIds.length; i++) {
            ICultureIndex.Vote memory vote = cultureIndex.getVote(pieceIds[i], address(this));
            assertEq(vote.voterAddress, address(this), "Voter address should match");
            assertEq(vote.weight, 200, "Vote weight should be correct");
        }
    }

    function testBatchVotingFailsForInvalidPieceIds() public {
        uint256[] memory pieceIds = new uint256[](2);
        pieceIds[0] = 999; // Invalid pieceId
        pieceIds[1] = createDefaultArtPiece(); // Valid pieceId
        vm.stopPrank();
        vm.startPrank(address(erc20TokenEmitter));
        erc20Token.mint(address(this), 200);
        vm.roll(block.number + 1); // Roll forward to ensure votes are snapshotted

        // This should revert because one of the pieceIds is invalid
        try cultureIndex.voteForMany(pieceIds) {
            fail("Batch voting with an invalid pieceId should fail");
        } catch Error(string memory reason) {
            assertEq(reason, "Invalid piece ID", "Should revert with invalid piece ID error");
        }
    }

    function testBatchVotingFailsIfAlreadyVoted() public {
        uint256 pieceId = createDefaultArtPiece();
        vm.stopPrank();
        vm.startPrank(address(erc20TokenEmitter));
        erc20Token.mint(address(this), 100);
        vm.roll(block.number + 1); // Roll forward to ensure votes are snapshotted

        vm.startPrank(address(this));
        cultureIndex.vote(pieceId); // Vote for the pieceId

        uint256[] memory pieceIds = new uint256[](1);
        pieceIds[0] = pieceId;

        // This should revert because the voter has already voted for this pieceId
        try cultureIndex.voteForMany(pieceIds) {
            fail("Batch voting for an already voted pieceId should fail");
        } catch Error(string memory reason) {
            assertEq(reason, "Already voted", "Should revert with already voted error");
        }
    }

    function testBatchVotingFailsIfPieceDropped() public {
        uint256 pieceId = createDefaultArtPiece();
        vm.stopPrank();
        vm.startPrank(address(erc20TokenEmitter));
        erc20Token.mint(address(this), 100);
        vm.roll(block.number + 1); // Roll forward to ensure votes are snapshotted

        vm.startPrank(address(erc721Token));
        cultureIndex.dropTopVotedPiece(); // Drop the piece

        uint256[] memory pieceIds = new uint256[](1);
        pieceIds[0] = pieceId;

        // This should revert because the piece has been dropped
        try cultureIndex.voteForMany(pieceIds) {
            fail("Batch voting for a dropped pieceId should fail");
        } catch Error(string memory reason) {
            assertEq(reason, "Piece has already been dropped", "Should revert with piece dropped error");
        }
    }

    function testBatchVotingFailsForZeroWeight() public {
        uint256[] memory pieceIds = new uint256[](1);
        pieceIds[0] = createDefaultArtPiece();
        vm.roll(block.number + 1); // Roll forward to ensure votes are snapshotted
        // Do not mint any tokens to ensure weight is zero

        // This should revert because the voter weight is zero
        try cultureIndex.voteForMany(pieceIds) {
            fail("Batch voting with zero weight should fail");
        } catch Error(string memory reason) {
            assertEq(reason, "Weight must be greater than minVoteWeight", "Should revert with weight zero error");
        }
    }

    function testGasUsage() public {
        // Assume createArtPiece() is a function that sets up an art piece and returns its ID
        uint256[] memory pieceIds = new uint256[](100);
        for (uint256 i = 0; i < 100; i++) {
            pieceIds[i] = createDefaultArtPiece(); // Setup each art piece
        }

        // Mint enough tokens for voting
        vm.stopPrank();
        vm.startPrank(address(erc20TokenEmitter));
        erc20Token.mint(address(this), 100 * 100); // Mint enough tokens (e.g., 100 tokens per vote)
        vm.roll(block.number + 1); // Roll forward to ensure votes are snapshotted

        vm.startPrank(address(this));
        // Measure gas for individual voting
        uint256 startGasIndividual = gasleft();
        for (uint256 i = 0; i < 100; i++) {
            cultureIndex.vote(pieceIds[i]);
        }
        uint256 gasUsedIndividual = startGasIndividual - gasleft();
        emit log_string("Gas used for individual votes");
        emit log_uint(gasUsedIndividual); // Log gas used for individual votes

        vm.stopPrank();

        setUp();
        // Resetting state for a fair comparison
        // Reset contract state (this would need to be implemented to revert to initial state)
        uint256[] memory batchPieceIds = new uint256[](100);
        for (uint256 i = 0; i < 100; i++) {
            batchPieceIds[i] = createDefaultArtPiece(); // Setup each art piece
        }
        vm.stopPrank();
        vm.startPrank(address(erc20TokenEmitter));
        erc20Token.mint(address(this), 100 * 100); // Mint enough tokens (e.g., 100 tokens per vote)
        vm.roll(block.number + 1); // Roll forward to ensure votes are snapshotted

        vm.startPrank(address(this));
        // Measure gas for batch voting
        uint256 startGasBatch = gasleft();
        cultureIndex.voteForMany(batchPieceIds);
        uint256 gasUsedBatch = startGasBatch - gasleft();
        emit log_string("Gas used for batch votes");
        emit log_uint(gasUsedBatch); // Log gas used for batch votes

        // Log the difference in gas usage
        emit log_string("gas saved");
        emit log_int(int(gasUsedIndividual) - int(gasUsedBatch)); // This will log the saved gas

        //assert that batch voting is cheaper
        assertTrue(gasUsedBatch < gasUsedIndividual, "Batch voting should be cheaper");
    }

    /**
     * @dev Test case to validate the "one vote per address" rule
     *
     * We create a new art piece and cast a vote for it.
     * Then we try to vote again and expect it to fail.
     */
    function testCannotVoteTwice() public {
        uint256 newPieceId = createArtPiece(
            "Mona Lisa",
            "A masterpiece",
            ICultureIndex.MediaType.IMAGE,
            "ipfs://legends",
            "",
            "",
            address(0x1),
            10000
        );

        // Mint some tokens to the voter
        vm.stopPrank();
        vm.startPrank(address(erc20TokenEmitter));
        erc20Token.mint(address(this), 100);
        vm.roll(block.number + 1); // Roll forward to ensure votes are snapshotted

        // Cast a vote
        vm.startPrank(address(this));
        cultureIndex.vote(newPieceId);

        // Try to vote again and expect to fail
        try cultureIndex.vote(newPieceId) {
            fail("Should not be able to vote twice");
        } catch Error(string memory reason) {
            assertEq(reason, "Already voted");
        }
    }

    /**
     * @dev Test case to validate that an address with no tokens cannot vote
     *
     * We create a new art piece and try to cast a vote without any tokens.
     * We expect the vote to fail.
     */
    function testCannotVoteWithoutTokens() public {
        uint256 newPieceId = createArtPiece(
            "Starry Night",
            "A masterpiece",
            ICultureIndex.MediaType.IMAGE,
            "ipfs://legends",
            "",
            "",
            address(0x1),
            10000
        );

        vm.roll(block.number + 1); // Roll forward to ensure votes are snapshotted

        // Try to vote and expect to fail
        try cultureIndex.vote(newPieceId) {
            fail("Should not be able to vote without tokens");
        } catch Error(string memory reason) {
            assertEq(reason, "Weight must be greater than minVoteWeight");
        }
    }

    /**
     * @dev Test case to validate that a single address cannot vote twice on multiple pieces
     *
     * We create two new art pieces and cast a vote for each.
     * Then we try to vote again for both and expect both to fail.
     */
    function testCannotVoteOnMultiplePiecesTwice() public {
        uint256 firstPieceId = createArtPiece(
            "Mona Lisa",
            "A masterpiece",
            ICultureIndex.MediaType.IMAGE,
            "ipfs://legends",
            "",
            "",
            address(0x1),
            10000
        );

        uint256 secondPieceId = createArtPiece(
            "Starry Night",
            "Another masterpiece",
            ICultureIndex.MediaType.IMAGE,
            "ipfs://starrynight",
            "",
            "",
            address(0x2),
            10000
        );

        // Mint some tokens to the voter
        vm.stopPrank();
        vm.startPrank(address(erc20TokenEmitter));
        erc20Token.mint(address(this), 200);
        vm.roll(block.number + 1); // Roll forward to ensure votes are snapshotted

        // Cast a vote for the first piece

        vm.startPrank(address(this));
        cultureIndex.vote(firstPieceId);

        // Cast a vote for the second piece
        cultureIndex.vote(secondPieceId);

        // Try to vote again for the first piece and expect to fail
        try cultureIndex.vote(firstPieceId) {
            fail("Should not be able to vote twice on the first piece");
        } catch Error(string memory reason) {
            assertEq(reason, "Already voted");
        }

        // Try to vote again for the second piece and expect to fail
        try cultureIndex.vote(secondPieceId) {
            fail("Should not be able to vote twice on the second piece");
        } catch Error(string memory reason) {
            assertEq(reason, "Already voted");
        }
    }

    /**
     * @dev Test case to validate that an address with no tokens cannot vote on multiple pieces
     *
     * We create two new art pieces and try to cast a vote for each without any tokens.
     * We expect both votes to fail.
     */
    function testCannotVoteWithoutTokensMultiplePieces() public {
        uint256 firstPieceId = createArtPiece(
            "Mona Lisa",
            "A masterpiece",
            ICultureIndex.MediaType.IMAGE,
            "ipfs://legends",
            "",
            "",
            address(0x1),
            10000
        );

        uint256 secondPieceId = createArtPiece(
            "Starry Night",
            "Another masterpiece",
            ICultureIndex.MediaType.IMAGE,
            "ipfs://starrynight",
            "",
            "",
            address(0x2),
            10000
        );
        vm.roll(block.number + 1); // Roll forward to ensure votes are snapshotted

        // Try to vote for the first piece and expect to fail
        try cultureIndex.vote(firstPieceId) {
            fail("Should not be able to vote without tokens on the first piece");
        } catch Error(string memory reason) {
            assertEq(reason, "Weight must be greater than minVoteWeight");
        }

        // Try to vote for the second piece and expect to fail
        try cultureIndex.vote(secondPieceId) {
            fail("Should not be able to vote without tokens on the second piece");
        } catch Error(string memory reason) {
            assertEq(reason, "Weight must be greater than minVoteWeight");
        }
    }

    function testVoteAfterTransferringTokens() public {
        uint256 newPieceId = createDefaultArtPiece();

        // Mint tokens and vote
        vm.stopPrank();
        vm.startPrank(address(erc20TokenEmitter));
        erc20Token.mint(address(this), 100);
        vm.roll(block.number + 1); // Roll forward to ensure votes are snapshotted

        vm.startPrank(address(this));
        cultureIndex.vote(newPieceId);

        // Transfer all tokens to another account
        address anotherAccount = address(0x4);
        vm.expectRevert(abi.encodeWithSignature("TRANSFER_NOT_ALLOWED()"));
        erc20Token.transfer(anotherAccount, 100);

        vm.startPrank(anotherAccount);

        // Try to vote again and expect to fail
        try cultureIndex.vote(newPieceId) {
            fail("Should not be able to vote without tokens");
        } catch Error(string memory reason) {
            emit log_string(reason);
            assertEq(reason, "Weight must be greater than minVoteWeight");
        }
    }

    function testInvalidPieceID() public {
        // Mint some tokens to the voter
        vm.stopPrank();
        vm.startPrank(address(erc20TokenEmitter));
        erc20Token.mint(address(this), 100);
        vm.roll(block.number + 1); // Roll forward to ensure votes are snapshotted

        vm.startPrank(address(this));
        // Attempt to vote for an invalid piece ID
        try cultureIndex.vote(9999) {
            // Assuming 9999 is an invalid ID
            fail("Should not be able to vote for an invalid piece ID");
        } catch Error(string memory reason) {
            assertEq(reason, "Invalid piece ID");
        }
    }

    /**
     * @dev Test case to validate that voting on a dropped piece fails.
     *
     * We create a new art piece, drop it, and then try to cast a vote for it.
     * We expect the vote to fail since the piece has been dropped.
     */
    function testCannotVoteOnDroppedPiece() public {
        uint256 newPieceId = createDefaultArtPiece();
        vm.stopPrank();
        vm.startPrank(address(erc20TokenEmitter));
        vm.stopPrank();
        vm.startPrank(address(erc20TokenEmitter));
        erc20Token.mint(address(this), 100);
        vm.roll(block.number + 1); // Roll forward to ensure votes are snapshotted

        // Drop the top-voted piece (which should be the new piece)
        vm.startPrank(address(erc721Token));
        cultureIndex.dropTopVotedPiece();

        // Try to vote for the dropped piece and expect to fail
        try cultureIndex.vote(newPieceId) {
            fail("Should not be able to vote on a dropped piece");
        } catch Error(string memory reason) {
            assertEq(reason, "Piece has already been dropped");
        }
    }

    function testCalculateVoteWeights(uint200 erc20Balance, uint40 erc721Balance) public {
        vm.assume(erc20Balance > 0);
        vm.assume(erc721Balance < 1_000);
        vm.stopPrank();
        vm.startPrank(address(erc20TokenEmitter));
        erc20Token.mint(address(auction), erc20Balance);

        vm.startPrank(address(this));

        // Create art pieces and drop them
        for (uint256 i; i < erc721Balance; i++) {
            createDefaultArtPiece();
            vm.roll(block.number + (i + 1) * 2);
            vm.startPrank(address(auction));
            cultureIndex.vote(i);
            erc721Token.mint();
        }

        vm.roll(block.number + 3);

        // Calculate expected vote weight
        uint256 expectedVoteWeight = erc20Balance + (erc721Balance * cultureIndex.erc721VotingTokenWeight() * 1e18);

        // Get the actual vote weight from the contract
        uint256 actualVoteWeight = cultureIndex.getVotes(address(auction));

        // Assert that the actual vote weight matches the expected value
        assertEq(actualVoteWeight, expectedVoteWeight, "Vote weight calculation does not match expected value");
    }

    function testQuorumVotesCalculation(uint200 erc20TotalSupply, uint256 erc721TotalSupply) public {
        vm.assume(erc20TotalSupply > 0);
        vm.assume(erc721TotalSupply < 1_000);
        // Initial settings
        uint256 quorumBPS = cultureIndex.quorumVotesBPS(); // Example quorum BPS (20%)

        // Set the quorum BPS
        cultureIndex._setQuorumVotesBPS(quorumBPS);

        // Set the ERC20 and ERC721 total supplies
        vm.startPrank(address(erc20TokenEmitter));
        erc20Token.mint(address(this), erc20TotalSupply);

        vm.roll(block.number + 1);

        //for desired erc721 supply, loop create art pieces and drop them
        for (uint256 i = 0; i < erc721TotalSupply; i++) {
            createDefaultArtPiece();
            vm.roll(block.number + 1);
            vm.startPrank(address(this));
            cultureIndex.vote(i);

            vm.startPrank(address(auction));
            erc721Token.mint();

            //transfer to voter
            erc721Token.transferFrom(address(auction), address(this), i);
        }

        // Calculate expected quorum votes
        uint256 expectedQuorumVotes = (quorumBPS *
            (erc20TotalSupply + erc721TotalSupply * 1e18 * cultureIndex.erc721VotingTokenWeight())) / 10_000;
        // Get the quorum votes from the contract
        uint256 actualQuorumVotes = cultureIndex.quorumVotes();

        // Assert that the actual quorum votes match the expected value
        assertEq(actualQuorumVotes, expectedQuorumVotes, "Quorum votes calculation does not match expected value");
    }
}
