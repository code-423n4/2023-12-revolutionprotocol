// SPDX-License-Identifier: GPL-3.0

/// @title The Verbs NFT descriptor

/*********************************
 * ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ *
 * ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ *
 * ░░░░░░█████████░░█████████░░░ *
 * ░░░░░░██░░░████░░██░░░████░░░ *
 * ░░██████░░░████████░░░████░░░ *
 * ░░██░░██░░░████░░██░░░████░░░ *
 * ░░██░░██░░░████░░██░░░████░░░ *
 * ░░░░░░█████████░░█████████░░░ *
 * ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ *
 * ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ *
 *********************************/

pragma solidity ^0.8.22;

import { Ownable2StepUpgradeable } from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

import { UUPS } from "./libs/proxy/UUPS.sol";
import { VersionedContract } from "./version/VersionedContract.sol";

import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";
import { IDescriptor } from "./interfaces/IDescriptor.sol";
import { Base64 } from "@openzeppelin/contracts/utils/Base64.sol";
import { ICultureIndex } from "./interfaces/ICultureIndex.sol";
import { IRevolutionBuilder } from "./interfaces/IRevolutionBuilder.sol";

contract Descriptor is IDescriptor, VersionedContract, UUPS, Ownable2StepUpgradeable {
    using Strings for uint256;

    // Whether or not `tokenURI` should be returned as a data URI (Default: true)
    bool public override isDataURIEnabled;

    // Base URI
    string public override baseURI;

    // Token name prefix
    string public tokenNamePrefix;

    // Token URI params for constructing metadata
    struct TokenURIParams {
        string name;
        string description;
        string image;
        string animation_url;
    }

    ///                                                          ///
    ///                         IMMUTABLES                       ///
    ///                                                          ///

    // prettier-ignore
    // https://creativecommons.org/publicdomain/zero/1.0/legalcode.txt
    bytes32 constant COPYRIGHT_CC0_1_0_UNIVERSAL_LICENSE = 0xa2010f343487d3f7618affe54f789f5487602331c0a8d03f49e9a7c547cf0499;

    /// @notice The contract upgrade manager
    IRevolutionBuilder private immutable manager;

    ///                                                          ///
    ///                         CONSTRUCTOR                      ///
    ///                                                          ///

    /// @param _manager The contract upgrade manager address
    constructor(address _manager) payable initializer {
        manager = IRevolutionBuilder(_manager);
    }

    ///                                                          ///
    ///                         INITIALIZER                      ///
    ///                                                          ///

    /// @notice Initializes a token's metadata descriptor
    /// @param _initialOwner The address of the initial owner
    /// @param _tokenNamePrefix The prefix for the token name eg: "Vrb" -> Vrb 1
    function initialize(address _initialOwner, string calldata _tokenNamePrefix) external initializer {
        require(msg.sender == address(manager), "Only manager can initialize");

        // Ensure the caller is the contract manager
        require(msg.sender == address(manager), "Only manager can initialize");

        require(_initialOwner != address(0), "Initial owner cannot be zero address");

        // Setup ownable
        __Ownable_init(_initialOwner);

        tokenNamePrefix = _tokenNamePrefix;

        isDataURIEnabled = true;
    }

    /**
     * @notice Construct an ERC721 token URI.
     */
    function constructTokenURI(TokenURIParams memory params) public pure returns (string memory) {
        string memory json = string(
            abi.encodePacked(
                '{"name":"',
                params.name,
                '", "description":"',
                params.description,
                '", "image": "',
                params.image,
                '", "animation_url": "',
                params.animation_url,
                '"}'
            )
        );
        return string(abi.encodePacked("data:application/json;base64,", Base64.encode(bytes(json))));
    }

    /**
     * @notice Toggle a boolean value which determines if `tokenURI` returns a data URI
     * or an HTTP URL.
     * @dev This can only be called by the owner.
     */
    function toggleDataURIEnabled() external override onlyOwner {
        bool enabled = !isDataURIEnabled;

        isDataURIEnabled = enabled;
        emit DataURIToggled(enabled);
    }

    /**
     * @notice Set the base URI for all token IDs. It is automatically
     * added as a prefix to the value returned in {tokenURI}, or to the
     * token ID if {tokenURI} is empty.
     * @dev This can only be called by the owner.
     */
    function setBaseURI(string calldata _baseURI) external override onlyOwner {
        baseURI = _baseURI;

        emit BaseURIUpdated(_baseURI);
    }

    /**
     * @notice Given a token ID, construct a token URI for an official Vrbs DAO verb.
     * @dev The returned value may be a base64 encoded data URI or an API URL.
     */
    //slither-disable-next-line encode-packed-collision
    function tokenURI(
        uint256 tokenId,
        ICultureIndex.ArtPieceMetadata memory metadata
    ) external view returns (string memory) {
        if (isDataURIEnabled) return dataURI(tokenId, metadata);

        return string(abi.encodePacked(baseURI, tokenId.toString()));
    }

    /**
     * @notice Given a token ID, construct a base64 encoded data URI for an official Vrbs DAO verb.
     */
    function dataURI(
        uint256 tokenId,
        ICultureIndex.ArtPieceMetadata memory metadata
    ) public view returns (string memory) {
        return genericDataURI(string(abi.encodePacked(tokenNamePrefix, " ", tokenId.toString())), metadata);
    }

    /**
     * @notice Given a name, and metadata, construct a base64 encoded data URI.
     */
    function genericDataURI(
        string memory name,
        ICultureIndex.ArtPieceMetadata memory metadata
    ) public pure returns (string memory) {
        /// @dev Get name description image and animation_url from CultureIndex

        TokenURIParams memory params = TokenURIParams({
            name: name,
            description: string(abi.encodePacked(metadata.name, ". ", metadata.description)),
            image: metadata.image,
            animation_url: metadata.animationUrl
        });
        return constructTokenURI(params);
    }

    ///                                                          ///
    ///                      DESCRIPTOR UPGRADE                  ///
    ///                                                          ///

    /// @notice Ensures the caller is authorized to upgrade the contract to a valid implementation
    /// @dev This function is called in UUPS `upgradeTo` & `upgradeToAndCall`
    /// @param _impl The address of the new implementation
    function _authorizeUpgrade(address _impl) internal view override onlyOwner {
        if (!manager.isRegisteredUpgrade(_getImplementation(), _impl)) revert INVALID_UPGRADE(_impl);
    }
}
