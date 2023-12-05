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
import "../utils/Base64Decode.sol";
import "../utils/JsmnSolLib.sol";
import { NontransferableERC20Votes } from "../../src/NontransferableERC20Votes.sol";

/// @title VerbsTokenTestSuite
/// @dev The base test suite for the VerbsToken contract
contract VerbsTokenTestSuite is Test {
    VerbsToken public verbsToken;
    CultureIndex public cultureIndex;
    NontransferableERC20Votes public govToken;
    VerbsDescriptor public descriptor;

    string public tokenNamePrefix = "Vrb";
    string public tokenName = "Vrbs";
    string public tokenSymbol = "VRBS";

    /// @dev Sets up a new VerbsToken instance before each test
    function setUp() public {
        // Create a new mock ERC20 token for voting
        govToken = new NontransferableERC20Votes(address(this), "Revolution Governance", "GOV");

        // Deploy a new proxy registry for OpenSea
        ProxyRegistry _proxyRegistry = new ProxyRegistry();

        // Create a new VerbsToken contract, passing address(this) as both the minter and the initial owner
        verbsToken = new VerbsToken(address(this), address(this), IVerbsDescriptorMinimal(address(0)), _proxyRegistry, ICultureIndex(address(0)), tokenName, tokenSymbol);

        // Deploy CultureIndex with the VerbsToken's address as the initial owner
        cultureIndex = new CultureIndex("Vrbs", "Our community Vrbs. Must be 32x32.", address(govToken), address(verbsToken), address(verbsToken), 10, 200);
        ICultureIndex _cultureIndex = cultureIndex;

        // Now that CultureIndex is deployed, set it in VerbsToken
        verbsToken.setCultureIndex(_cultureIndex);

        // Deploy a new VerbsDescriptor, which will be used by VerbsToken
        descriptor = new VerbsDescriptor(address(verbsToken), tokenNamePrefix);
        IVerbsDescriptorMinimal _descriptor = descriptor;

        // Now that VerbsDescriptor is deployed, set it in VerbsToken
        verbsToken.setDescriptor(_descriptor);
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

contract ProxyRegistry is IProxyRegistry {
    mapping(address => address) public proxies;
}
