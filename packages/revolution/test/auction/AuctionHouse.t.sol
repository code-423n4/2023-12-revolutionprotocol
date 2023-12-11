// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import { Test } from "forge-std/Test.sol";
import { AuctionHouse } from "../../src/AuctionHouse.sol";
import { MockERC20 } from "../mock/MockERC20.sol";
import { VerbsToken } from "../../src/VerbsToken.sol";
import { IVerbsToken } from "../../src/interfaces/IVerbsToken.sol";
import { Descriptor } from "../../src/Descriptor.sol";
import { CultureIndex } from "../../src/CultureIndex.sol";
import { IDescriptorMinimal } from "../../src/interfaces/IDescriptorMinimal.sol";
import { ICultureIndex, ICultureIndexEvents } from "../../src/interfaces/ICultureIndex.sol";
import { IAuctionHouse } from "../../src/interfaces/IAuctionHouse.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { NontransferableERC20Votes } from "../../src/NontransferableERC20Votes.sol";
import { ERC20TokenEmitter } from "../../src/ERC20TokenEmitter.sol";
import { IERC20TokenEmitter } from "../../src/interfaces/IERC20TokenEmitter.sol";
import { wadMul, wadDiv } from "../../src/libs/SignedWadMath.sol";
import { RevolutionProtocolRewards } from "@collectivexyz/protocol-rewards/src/RevolutionProtocolRewards.sol";
import { TokenEmitterRewards } from "@collectivexyz/protocol-rewards/src/abstract/TokenEmitter/TokenEmitterRewards.sol";
import { ERC721CheckpointableUpgradeable } from "../../src/base/ERC721CheckpointableUpgradeable.sol";
import { RevolutionBuilderTest } from "../RevolutionBuilder.t.sol";

contract AuctionHouseTest is RevolutionBuilderTest {
    function setUp() public override {
        super.setUp();
        super.setMockParams();

        super.setERC20TokenParams("Revolution Governance", "GOV");

        super.setCultureIndexParams("Vrbs", "Our community Vrbs. Must be 32x32.", 10, 200, 0);

        super.setERC721TokenParams("Vrbs", "VRBS", "QmQzDwaZ7yQxHHs7sQQenJVB89riTSacSGcJRv9jtHPuz5", "Vrb");

        super.setAuctionParams(
            15 minutes, // timeBuffer
            1 ether, // reservePrice
            24 hours, // duration
            5, // minBidIncrementPercentage
            2_000, // creatorRateBps
            5_000, //entropyRateBps
            1_000 //minCreatorRateBps
        );

        super.deployMock();

        vm.startPrank(address(dao));

        // governanceToken = new NontransferableERC20Votes(address(this), "Revolution Governance", "GOV");
        // RevolutionProtocolRewards protocolRewards = new RevolutionProtocolRewards();

        // CultureIndex _cultureIndex = new CultureIndex(
        //     "Vrbs",
        //     "Our community Vrbs. Must be 32x32.",
        //     address(governanceToken),
        //     address(this),
        //     address(this),
        //     10,
        //     200,
        //     0
        // );
        // cultureIndex = _cultureIndex;

        // //20% - how much the price decays per unit of time with no sales
        // int256 priceDecayPercent = 1e18 / 10;
        // // 1e11 or 0.0000001 is 2 cents per token even at $200k eth price
        // int256 tokenTargetPrice = 1e11;

        // address protocolFeeRecipient = address(0x42069);

        // ERC20TokenEmitter = new ERC20TokenEmitter(
        //     address(this),
        //     governanceToken,
        //     address(protocolRewards),
        //     protocolFeeRecipient,
        //     address(this),
        //     tokenTargetPrice,
        //     priceDecayPercent,
        //     int256(1e18 * 1e4 * tokensPerTimeUnit)
        // );
        // erc20Token.transferOwnership(address(tokenEmitter));

        // // Initialize VerbsToken with additional parameters
        // verbs = new VerbsToken(
        //     address(this), // Address of the minter (and initial owner)
        //     address(this), // Address of the owner
        //     IDescriptorMinimal(address(0)),
        //     ICultureIndex(address(_cultureIndex)),
        //     "Vrbs",
        //     "VRBS",
        //     "QmQzDwaZ7yQxHHs7sQQenJVB89riTSacSGcJRv9jtHPuz5"
        // );

        // cultureIndex.transferOwnership(address(erc721Token));

        // // Deploy a new Descriptor, which will be used by VerbsToken
        // descriptor = new Descriptor(address(erc721Token), "Verb");

        // // Set the culture index and descriptor in VerbsToken
        // erc721Token.setCultureIndex(ICultureIndex(address(_cultureIndex)));

        // auctionHouse = new AuctionHouse();

        // // Initialize the auction house with mock contracts and parameters
        // auctionHouse.initialize(
        //     IVerbsToken(address(erc721Token)),
        //     IERC20TokenEmitter(address(tokenEmitter)),
        //     address(weth),
        //     address(this), // Owner of the auction house
        //     15 minutes, // timeBuffer
        //     1 ether, // reservePrice
        //     5, // minBidIncrementPercentage
        //     24 hours, // duration
        //     2_000, // creatorRateBps
        //     5_000, //entropyRateBps
        //     1_000 //minCreatorRateBps
        // );

        // //set minter of verbstoken to be auction house
        // erc721Token.setMinter(address(auction));
        // erc721Token.lockMinter();
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
        address[] memory creatorAddresses = new address[](1);
        creatorAddresses[0] = creatorAddress;

        uint256[] memory creatorBpsArray = new uint256[](1);
        creatorBpsArray[0] = creatorBps;

        return
            createArtPieceMultiCreator(
                name,
                description,
                mediaType,
                image,
                text,
                animationUrl,
                creatorAddresses,
                creatorBpsArray
            );
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

    // Utility function to create a new art piece with multiple creators and return its ID
    function createArtPieceMultiCreator(
        string memory name,
        string memory description,
        ICultureIndex.MediaType mediaType,
        string memory image,
        string memory text,
        string memory animationUrl,
        address[] memory creatorAddresses,
        uint256[] memory creatorBps
    ) internal returns (uint256) {
        ICultureIndex.ArtPieceMetadata memory metadata = ICultureIndex.ArtPieceMetadata({
            name: name,
            description: description,
            mediaType: mediaType,
            image: image,
            text: text,
            animationUrl: animationUrl
        });

        ICultureIndex.CreatorBps[] memory creators = new ICultureIndex.CreatorBps[](creatorAddresses.length);
        for (uint256 i = 0; i < creatorAddresses.length; i++) {
            creators[i] = ICultureIndex.CreatorBps({ creator: creatorAddresses[i], bps: creatorBps[i] });
        }

        return cultureIndex.createPiece(metadata, creators);
    }
}
