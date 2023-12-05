// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.22;

import { ERC20Votes } from "./base/erc20/ERC20Votes.sol";
import { MaxHeap } from "./MaxHeap.sol";
import { ICultureIndex } from "./interfaces/ICultureIndex.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import { ERC721Checkpointable } from "./base/ERC721Checkpointable.sol";

contract CultureIndex is ICultureIndex, Ownable, ReentrancyGuard {
    // The MaxHeap data structure used to keep track of the top-voted piece
    MaxHeap public immutable maxHeap;

    // The ERC20 token used for voting
    ERC20Votes public immutable erc20VotingToken;

    // The ERC721 token used for voting
    ERC721Checkpointable public erc721VotingToken;

    // Whether the 721 voting token can be updated
    bool public isERC721VotingTokenLocked;

    // The weight of the 721 voting token
    uint256 public immutable erc721VotingTokenWeight;

    /// @notice The minimum setable quorum votes basis points
    uint256 public constant MIN_QUORUM_VOTES_BPS = 200; // 200 basis points or 2%

    /// @notice The maximum setable quorum votes basis points
    uint256 public constant MAX_QUORUM_VOTES_BPS = 4_000; // 4,000 basis points or 40%

    /// @notice The basis point number of votes in support of a art piece required in order for a quorum to be reached and for an art piece to be dropped.
    uint256 public quorumVotesBPS;

    string public name;

    string public description;

    // The list of all pieces
    mapping(uint256 => ArtPiece) public pieces;

    // The internal piece ID tracker
    uint256 public _currentPieceId;

    // The mapping of all votes for a piece
    mapping(uint256 => mapping(address => Vote)) public votes;

    // The total voting weight for a piece
    mapping(uint256 => uint256) public totalVoteWeights;

    /**
     * @notice Constructor
     * @param name_ The name of the culture index
     * @param description_ A description for the culture index, can include rules for uploads etc.
     * @param erc20VotingToken_ The address of the ERC20 voting token, commonly referred to as "points"
     * @param erc721VotingToken_ The address of the ERC721 voting token, commonly the dropped art pieces
     * @param initialOwner_ The owner of the contract, allowed to drop pieces. Commonly updated to the AuctionHouse
     * @param erc721VotingTokenWeight_ The voting weight of the individual ERC721 tokens. Normally a large multiple to match up with daily emission of ERC20 points
     * @param quorumVotesBPS_ The initial quorum votes threshold in basis points
     */
    constructor(
        string memory name_,
        string memory description_,
        address erc20VotingToken_,
        address erc721VotingToken_,
        address initialOwner_,
        uint256 erc721VotingTokenWeight_,
        uint256 quorumVotesBPS_
    ) Ownable(initialOwner_) {
        require(quorumVotesBPS_ >= MIN_QUORUM_VOTES_BPS && quorumVotesBPS_ <= MAX_QUORUM_VOTES_BPS, "CultureIndex::constructor: invalid quorum bps");
        require(erc721VotingTokenWeight_ > 0, "CultureIndex::constructor: invalid erc721 voting token weight");
        require(erc721VotingToken_ != address(0), "CultureIndex::constructor: invalid erc721 voting token");
        require(erc20VotingToken_ != address(0), "CultureIndex::constructor: invalid erc20 voting token");

        erc20VotingToken = ERC20Votes(erc20VotingToken_);
        erc721VotingToken = ERC721Checkpointable(erc721VotingToken_);
        erc721VotingTokenWeight = erc721VotingTokenWeight_;
        name = name_;
        description = description_;
        quorumVotesBPS = quorumVotesBPS_;

        emit QuorumVotesBPSSet(quorumVotesBPS, quorumVotesBPS_);

        maxHeap = new MaxHeap(address(this));
    }

    /**
     * @notice Require that the 721VotingToken has not been locked.
     */
    modifier whenERC721VotingTokenNotLocked() {
        require(!isERC721VotingTokenLocked, "ERC721VotingToken is locked");
        _;
    }

    /**
     * @notice Set the ERC721 voting token.
     * @dev Only callable by the owner when not locked.
     */
    function setERC721VotingToken(ERC721Checkpointable _ERC721VotingToken) external override onlyOwner nonReentrant whenERC721VotingTokenNotLocked {
        erc721VotingToken = _ERC721VotingToken;

        emit ERC721VotingTokenUpdated(_ERC721VotingToken);
    }

    /**
     * @notice Lock the ERC721 voting token.
     * @dev This cannot be reversed and is only callable by the owner when not locked.
     */
    function lockERC721VotingToken() external override onlyOwner whenERC721VotingTokenNotLocked {
        isERC721VotingTokenLocked = true;

        emit ERC721VotingTokenLocked();
    }

    /**
     *  Validates the media type and associated data.
     * @param metadata The metadata associated with the art piece.
     *
     * Requirements:
     * - The media type must be one of the defined types in the MediaType enum.
     * - The corresponding media data must not be empty.
     */
    function validateMediaType(ArtPieceMetadata memory metadata) internal pure {
        require(uint8(metadata.mediaType) > 0 && uint8(metadata.mediaType) <= 5, "Invalid media type");

        if (metadata.mediaType == MediaType.IMAGE) {
            require(bytes(metadata.image).length > 0, "Image URL must be provided");
        } else if (metadata.mediaType == MediaType.ANIMATION) {
            require(bytes(metadata.animationUrl).length > 0, "Animation URL must be provided");
        } else if (metadata.mediaType == MediaType.TEXT) {
            require(bytes(metadata.text).length > 0, "Text must be provided");
        }
    }

    /**
     * @notice Gets the total basis points from an array of creators.
     * @param creatorArray An array of Creator structs containing address and basis points.
     * @return Returns the total basis points calculated from the array of creators.
     *
     * Requirements:
     * - The `creatorArray` must not contain any zero addresses.
     * - The function will return the total basis points which must be checked to be exactly 10,000.
     */
    function getTotalBpsFromCreators(CreatorBps[] memory creatorArray) internal pure returns (uint256) {
        //Require that creatorArray is not more than 100 to prevent gas limit issues
        require(creatorArray.length <= 100, "Creator array must not be > 100");

        uint256 totalBps = 0;
        for (uint i = 0; i < creatorArray.length; i++) {
            require(creatorArray[i].creator != address(0), "Invalid creator address");
            totalBps += creatorArray[i].bps;
        }
        return totalBps;
    }

    /**
     * @notice Creates a new piece of art with associated metadata and creators.
     * @param metadata The metadata associated with the art piece, including name, description, image, and optional animation URL.
     * @param creatorArray An array of creators who contributed to the piece, along with their respective basis points that must sum up to 10,000.
     * @return Returns the unique ID of the newly created art piece.
     *
     * Emits a {PieceCreated} event for the newly created piece.
     * Emits a {PieceCreatorAdded} event for each creator added to the piece.
     *
     * Requirements:
     * - `metadata` must include name, description, and image. Animation URL is optional.
     * - `creatorArray` must not contain any zero addresses.
     * - The sum of basis points in `creatorArray` must be exactly 10,000.
     */
    function createPiece(ArtPieceMetadata memory metadata, CreatorBps[] memory creatorArray) public returns (uint256) {
        uint256 totalBps = getTotalBpsFromCreators(creatorArray);
        require(totalBps == 10_000, "Total BPS must sum up to 10,000");

        // Validate the media type and associated data
        validateMediaType(metadata);

        uint256 pieceId = _currentPieceId++;

        /// @dev Insert the new piece into the max heap
        maxHeap.insert(pieceId, 0);

        ArtPiece storage newPiece = pieces[pieceId];

        newPiece.pieceId = pieceId;
        newPiece.totalVotesSupply = _calculateVoteWeight(erc20VotingToken.totalSupply(), erc721VotingToken.totalSupply());
        newPiece.totalERC20Supply = erc20VotingToken.totalSupply();
        newPiece.metadata = metadata;
        newPiece.dropper = msg.sender;
        newPiece.creationBlock = block.number;
        newPiece.quorumVotes = (quorumVotesBPS * newPiece.totalVotesSupply) / 10_000;

        for (uint i = 0; i < creatorArray.length; i++) {
            newPiece.creators.push(creatorArray[i]);
        }

        emit PieceCreated(
            pieceId,
            msg.sender,
            metadata.name,
            metadata.description,
            metadata.image,
            metadata.animationUrl,
            metadata.text,
            uint8(metadata.mediaType),
            newPiece.quorumVotes,
            newPiece.totalVotesSupply
        );

        // Emit an event for each creator
        for (uint i = 0; i < creatorArray.length; i++) {
            emit PieceCreatorAdded(pieceId, creatorArray[i].creator, msg.sender, creatorArray[i].bps);
        }
        return newPiece.pieceId;
    }

    /**
     * @notice Checks if a specific voter has already voted for a given art piece.
     * @param pieceId The ID of the art piece.
     * @param voter The address of the voter.
     * @return A boolean indicating if the voter has voted for the art piece.
     */
    function hasVoted(uint256 pieceId, address voter) external view returns (bool) {
        return votes[pieceId][voter].voterAddress != address(0);
    }

    /**
     * @notice Returns the voting power of a voter at the current block.
     * @param account The address of the voter.
     * @return The voting power of the voter.
     */
    function getCurrentVotes(address account) external view override returns (uint256) {
        return _getCurrentVotes(account);
    }

    /**
     * @notice Returns the voting power of a voter at the current block.
     * @param account The address of the voter.
     * @return The voting power of the voter.
     */
    function getPriorVotes(address account, uint256 blockNumber) external view override returns (uint256) {
        return _getPriorVotes(account, blockNumber);
    }

    /**
     * @notice Calculates the vote weight of a voter.
     * @param erc20Balance The ERC20 balance of the voter.
     * @param erc721Balance The ERC721 balance of the voter.
     * @return The vote weight of the voter.
     */
    function _calculateVoteWeight(uint256 erc20Balance, uint256 erc721Balance) internal view returns (uint256) {
        return erc20Balance + (erc721Balance * erc721VotingTokenWeight * 1e18);
    }

    function _getCurrentVotes(address account) internal view returns (uint256) {
        return _calculateVoteWeight(erc20VotingToken.getVotes(account), erc721VotingToken.getCurrentVotes(account));
    }

    function _getPriorVotes(address account, uint256 blockNumber) internal view returns (uint256) {
        return _calculateVoteWeight(erc20VotingToken.getPastVotes(account, blockNumber), erc721VotingToken.getPriorVotes(account, blockNumber));
    }

    /**
     * @notice Cast a vote for a specific ArtPiece.
     * @param pieceId The ID of the ArtPiece to vote for.
     * @param voter The address of the voter.
     * @param weight The weight of the vote.
     * @dev Requires that the pieceId is valid, the voter has not already voted on this piece, and the weight is greater than zero.
     * Emits a VoteCast event upon successful execution.
     */
    function _vote(uint256 pieceId, address voter, uint256 weight) internal {
        require(weight > 0, "Weight must be greater than zero");
        require(!(votes[pieceId][msg.sender].voterAddress != address(0)), "Already voted");
        require(!pieces[pieceId].isDropped, "Piece has already been dropped");
        require(pieceId < _currentPieceId, "Invalid piece ID");

        votes[pieceId][voter] = Vote(voter, weight);
        totalVoteWeights[pieceId] += weight;

        uint256 totalWeight = totalVoteWeights[pieceId];

        // TODO add security consideration here based on block created to prevent flash attacks on drops?
        maxHeap.updateValue(pieceId, totalWeight);
        emit VoteCast(pieceId, voter, weight, totalWeight);
    }

    /**
     * @notice Cast a vote for a specific ArtPiece.
     * @param pieceId The ID of the ArtPiece to vote for.
     * @dev Requires that the pieceId is valid, the voter has not already voted on this piece, and the weight is greater than zero.
     * Emits a VoteCast event upon successful execution.
     */
    function vote(uint256 pieceId) public nonReentrant {
        require(pieceId < _currentPieceId, "Invalid piece ID");
        uint256 weight = _getPriorVotes(msg.sender, pieces[pieceId].creationBlock);

        _vote(pieceId, msg.sender, weight);
    }

    /**
     * @notice Cast a vote for a list of ArtPieces.
     * @param pieceIds The IDs of the ArtPieces to vote for.
     * @dev Requires that the pieceIds are valid, the voter has not already voted on this piece, and the weight is greater than zero.
     * Emits a series of VoteCast event upon successful execution.
     */
    function batchVote(uint256[] memory pieceIds) public nonReentrant {
        for (uint256 i = 0; i < pieceIds.length; ++i) {
            require(pieceIds[i] < _currentPieceId, "Invalid piece ID");
            _vote(pieceIds[i], msg.sender, _getPriorVotes(msg.sender, pieces[pieceIds[i]].creationBlock));
        }
    }

    /**
     * @notice Fetch an art piece by its ID.
     * @param pieceId The ID of the art piece.
     * @return The ArtPiece struct associated with the given ID.
     */
    function getPieceById(uint256 pieceId) public view returns (ArtPiece memory) {
        require(pieceId < _currentPieceId, "Invalid piece ID");
        return pieces[pieceId];
    }

    /**
     * @notice Fetch the list of votes for a given art piece.
     * @param pieceId The ID of the art piece.
     * @return An array of Vote structs for the given art piece ID.
     */
    function getVote(uint256 pieceId, address voter) public view returns (Vote memory) {
        require(pieceId < _currentPieceId, "Invalid piece ID");
        return votes[pieceId][voter];
    }

    /**
     * @notice Fetch the top-voted art piece.
     * @return The ArtPiece struct of the top-voted art piece.
     */
    function getTopVotedPiece() public view returns (ArtPiece memory) {
        //slither-disable-next-line unused-return
        (uint256 pieceId, ) = maxHeap.getMax();
        return pieces[pieceId];
    }

    /**
     * @notice Fetch the number of pieces
     * @return The number of pieces
     */
    function pieceCount() external view returns (uint256) {
        return _currentPieceId;
    }

    /**
     * @notice Fetch the top-voted pieceId
     * @return The top-voted pieceId
     */
    function topVotedPieceId() public view returns (uint256) {
        //slither-disable-next-line unused-return
        (uint256 pieceId, ) = maxHeap.getMax();
        return pieceId;
    }

    /**
     * @notice Admin function for setting the quorum votes basis points
     * @dev newQuorumVotesBPS must be greater than the hardcoded min
     * @param newQuorumVotesBPS new art piece drop threshold
     */
    function _setQuorumVotesBPS(uint256 newQuorumVotesBPS) external onlyOwner {
        require(
            newQuorumVotesBPS >= MIN_QUORUM_VOTES_BPS && newQuorumVotesBPS <= MAX_QUORUM_VOTES_BPS,
            "CultureIndex::_setQuorumVotesBPS: invalid quorum bps"
        );
        uint256 oldQuorumVotesBPS = quorumVotesBPS;
        quorumVotesBPS = newQuorumVotesBPS;

        emit QuorumVotesBPSSet(oldQuorumVotesBPS, quorumVotesBPS);
    }

    /**
     * @notice Current quorum votes using ERC721 Total Supply, ERC721 Vote Weight, and ERC20 Total Supply
     * Differs from `GovernerBravo` which uses fixed amount
     */
    function quorumVotes() public view returns (uint256) {
        return (quorumVotesBPS * _calculateVoteWeight(erc20VotingToken.totalSupply(), erc721VotingToken.totalSupply())) / 10_000;
    }

    /**
     * @notice Pulls and drops the top-voted piece.
     * @return The top voted piece
     */
    function dropTopVotedPiece() public nonReentrant onlyOwner returns (ArtPiece memory) {
        uint256 pieceId = topVotedPieceId();
        require(totalVoteWeights[pieceId] >= pieces[pieceId].quorumVotes, "Piece must have quorum votes in order to be dropped.");
        pieces[pieceId].isDropped = true;

        //slither-disable-next-line unused-return
        try maxHeap.extractMax() {
            emit PieceDropped(pieceId, msg.sender);

            //for each creator, emit an event
            for (uint i = 0; i < pieces[pieceId].creators.length; i++) {
                emit PieceDroppedCreator(pieceId, pieces[pieceId].creators[i].creator, pieces[pieceId].dropper, pieces[pieceId].creators[i].bps);
            }

            return pieces[pieceId];
        } catch Error(
            string memory reason // Catch known revert reason
        ) {
            if (keccak256(abi.encodePacked(reason)) == keccak256(abi.encodePacked("Heap is empty"))) {
                revert("No pieces available to drop");
            }
            revert(reason); // Revert with the original error if not matched
        } catch (
            bytes memory /*lowLevelData*/ // Catch any other low-level failures
        ) {
            revert("Unknown error extracting top piece");
        }
    }
}
