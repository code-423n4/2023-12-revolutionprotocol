// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import { Test } from "forge-std/Test.sol";
import { CultureIndex } from "../../src/CultureIndex.sol";
import { MockERC20 } from "../mock/MockERC20.sol";
import { ICultureIndex } from "../../src/interfaces/ICultureIndex.sol";
import { NontransferableERC20Votes } from "../../src/NontransferableERC20Votes.sol";
import { VerbsToken } from "../../src/VerbsToken.sol";
import { IVerbsDescriptorMinimal } from "../../src/interfaces/IVerbsDescriptorMinimal.sol";
import { IProxyRegistry } from "../../src/external/opensea/IProxyRegistry.sol";

/**
 * @title CultureIndexTest
 * @dev Test contract for CultureIndex
 */
contract CultureIndexTestSuite is Test {
    CultureIndex public cultureIndex;
    NontransferableERC20Votes public govToken;
    CultureIndexVotingTest public voter1Test;
    CultureIndexVotingTest public voter2Test;
    VerbsToken public verbs;

    /**
     * @dev Setup function for each test case
     */
    function setUp() public {
        govToken = new NontransferableERC20Votes(address(this), "Revolution Governance", "GOV");
        ProxyRegistry _proxyRegistry = new ProxyRegistry();

        // Initialize VerbsToken with additional parameters
        verbs = new VerbsToken(
            address(this), // Address of the minter (and initial owner)
            address(this), // Address of the owner
            IVerbsDescriptorMinimal(address(0)),
            _proxyRegistry,
            ICultureIndex(address(0)),
            "Vrbs",
            "VRBS"
        );

        // Initialize your CultureIndex contract
        cultureIndex = new CultureIndex("Vrbs", "Our community Vrbs. Must be 32x32.", address(govToken), address(verbs), address(this), 10, 200);

        verbs.setCultureIndex(cultureIndex);

        // Create new test instances acting as different voters
        voter1Test = new CultureIndexVotingTest(address(cultureIndex), address(govToken));
        voter2Test = new CultureIndexVotingTest(address(cultureIndex), address(govToken));
    }

    //returns metadata and creators in a tuple
    function createArtPieceTuple(
        string memory name,
        string memory description,
        ICultureIndex.MediaType mediaType,
        string memory image,
        string memory text,
        string memory animationUrl,
        address creatorAddress,
        uint256 creatorBps
    ) public pure returns (CultureIndex.ArtPieceMetadata memory, ICultureIndex.CreatorBps[] memory) {
        // <-- Change here
        ICultureIndex.ArtPieceMetadata memory metadata = createArtPieceMetadata(name, description, mediaType, image, text, animationUrl);
        ICultureIndex.CreatorBps[] memory creators = createArtPieceCreators(creatorAddress, creatorBps);
        return (metadata, creators);
    }

    // Utility function to create a new art piece and return its ID
    function createArtPiece(
        string memory name,
        string memory description,
        ICultureIndex.MediaType mediaType,
        string memory image,
        string memory text,
        string memory animationUrl,
        address creatorAddress,
        uint256 creatorBps
    ) internal returns (uint256) {
        ICultureIndex.ArtPieceMetadata memory metadata = ICultureIndex.ArtPieceMetadata({
            name: name,
            description: description,
            mediaType: mediaType,
            image: image,
            text: text,
            animationUrl: animationUrl
        });

        ICultureIndex.CreatorBps[] memory creators = new ICultureIndex.CreatorBps[](1);
        creators[0] = ICultureIndex.CreatorBps({ creator: creatorAddress, bps: creatorBps });

        return cultureIndex.createPiece(metadata, creators);
    }

    // Function to create ArtPieceMetadata
    function createArtPieceMetadata(
        string memory name,
        string memory description,
        ICultureIndex.MediaType mediaType,
        string memory image,
        string memory text,
        string memory animationUrl
    ) public pure returns (CultureIndex.ArtPieceMetadata memory) {
        // <-- Change visibility and mutability as needed
        ICultureIndex.ArtPieceMetadata memory metadata = ICultureIndex.ArtPieceMetadata({
            name: name,
            description: description,
            mediaType: mediaType,
            image: image,
            text: text,
            animationUrl: animationUrl
        });
        return metadata;
    }

    // Function to create CreatorBps array
    function createArtPieceCreators(address creatorAddress, uint256 creatorBps) public pure returns (CultureIndex.CreatorBps[] memory) {
        // <-- Change visibility and mutability as needed
        ICultureIndex.CreatorBps[] memory creators = new ICultureIndex.CreatorBps[](1);
        creators[0] = ICultureIndex.CreatorBps({ creator: creatorAddress, bps: creatorBps });
        return creators;
    }

    //Utility function to create default art piece
    function createDefaultArtPiece() public returns (uint256) {
        return createArtPiece("Mona Lisa", "A masterpiece", ICultureIndex.MediaType.IMAGE, "ipfs://legends", "", "", address(0x1), 10000);
    }

    function voteForPiece(uint256 pieceId) public {
        cultureIndex.vote(pieceId);
    }
}

contract CultureIndexVotingTest is Test {
    CultureIndex public cultureIndex;
    NontransferableERC20Votes public govToken;

    constructor(address _cultureIndex, address _votingToken) {
        cultureIndex = CultureIndex(_cultureIndex);
        govToken = NontransferableERC20Votes(_votingToken);
    }

    // Utility function to create a new art piece and return its ID
    function createArtPiece(
        string memory name,
        string memory description,
        ICultureIndex.MediaType mediaType,
        string memory image,
        string memory text,
        string memory animationUrl,
        address creatorAddress,
        uint256 creatorBps
    ) internal returns (uint256) {
        ICultureIndex.ArtPieceMetadata memory metadata = ICultureIndex.ArtPieceMetadata({
            name: name,
            description: description,
            mediaType: mediaType,
            image: image,
            text: text,
            animationUrl: animationUrl
        });

        ICultureIndex.CreatorBps[] memory creators = new ICultureIndex.CreatorBps[](1);
        creators[0] = ICultureIndex.CreatorBps({ creator: creatorAddress, bps: creatorBps });

        return cultureIndex.createPiece(metadata, creators);
    }

    //Utility function to create default art piece
    function createDefaultArtPiece() public returns (uint256) {
        return createArtPiece("Mona Lisa", "A masterpiece", ICultureIndex.MediaType.IMAGE, "ipfs://legends", "", "", address(0x1), 10000);
    }

    function voteForPiece(uint256 pieceId) public {
        cultureIndex.vote(pieceId);
    }
}

contract ProxyRegistry is IProxyRegistry {
    mapping(address => address) public proxies;
}
