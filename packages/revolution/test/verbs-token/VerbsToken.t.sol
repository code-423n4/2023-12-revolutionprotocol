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
import "../utils/Base64Decode.sol";
import "../utils/JsmnSolLib.sol";
import { NontransferableERC20Votes } from "../../src/NontransferableERC20Votes.sol";
import { RevolutionBuilderTest } from "../RevolutionBuilder.t.sol";

/// @title VerbsTokenTestSuite
/// @dev The base test suite for the VerbsToken contract
contract VerbsTokenTestSuite is RevolutionBuilderTest {
    string public tokenNamePrefix = "Vrb";
    string public tokenName = "Vrbs";
    string public tokenSymbol = "VRBS";

    /// @dev Sets up a new VerbsToken instance before each test
    function setUp() public override {
        super.setUp();
        super.setMockParams();

        super.setERC721TokenParams(tokenName, tokenSymbol, "https://example.com/token/", tokenNamePrefix);

        super.setCultureIndexParams("Vrbs", "Our community Vrbs. Must be 32x32.", 10, 200, 0);

        super.deployMock();

        vm.startPrank(address(auction));

        // // Create a new mock ERC20 token for voting
        // govToken = new NontransferableERC20Votes(address(this), "Revolution Governance", "GOV");

        // // Create a new VerbsToken contract, passing address(this) as both the minter and the initial owner
        // verbsToken = new VerbsToken(
        //     address(this),
        //     address(this),
        //     IDescriptorMinimal(address(0)),
        //     ICultureIndex(address(0)),
        //     tokenName,
        //     tokenSymbol,
        //     "QmQzDwaZ7yQxHHs7sQQenJVB89riTSacSGcJRv9jtHPuz5"
        // );

        // // Deploy CultureIndex with the VerbsToken's address as the initial owner
        // cultureIndex = new CultureIndex(
        //     "Vrbs",
        //     "Our community Vrbs. Must be 32x32.",
        //     address(erc20Token),
        //     address(erc721Token),
        //     address(erc721Token),
        //     10,
        //     200,
        //     0
        // );
        // ICultureIndex _cultureIndex = cultureIndex;

        // // Now that CultureIndex is deployed, set it in VerbsToken
        // erc721Token.setCultureIndex(_cultureIndex);

        // // Deploy a new Descriptor, which will be used by VerbsToken
        // descriptor = new Descriptor(address(erc721Token), tokenNamePrefix);
        // IDescriptorMinimal _descriptor = descriptor;

        // // Now that Descriptor is deployed, set it in VerbsToken
        // erc721Token.setDescriptor(_descriptor);
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
        return
            createArtPiece(
                "Mona Lisa",
                "A masterpiece",
                ICultureIndex.MediaType.IMAGE,
                "ipfs://legends",
                "",
                "",
                address(0x1),
                10000
            );
    }

    //function to create basic metadata
    function createDefaultMetadata() internal pure returns (ICultureIndex.ArtPieceMetadata memory) {
        return
            ICultureIndex.ArtPieceMetadata({
                name: "Mona Lisa",
                description: "A masterpiece",
                mediaType: ICultureIndex.MediaType.IMAGE,
                image: "ipfs://legends",
                text: "",
                animationUrl: ""
            });
    }
}
