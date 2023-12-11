// SPDX-License-Identifier: GPL-3.0

/// @title Interface for VerbsToken

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

import { IERC721 } from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import { IDescriptorMinimal } from "./IDescriptorMinimal.sol";
import { ICultureIndex } from "./ICultureIndex.sol";
import { IRevolutionBuilder } from "./IRevolutionBuilder.sol";

interface IVerbsToken is IERC721 {
    event VerbCreated(uint256 indexed tokenId, ICultureIndex.ArtPiece artPiece);

    event VerbBurned(uint256 indexed tokenId);

    event MinterUpdated(address minter);

    event MinterLocked();

    event DescriptorUpdated(IDescriptorMinimal descriptor);

    event DescriptorLocked();

    event CultureIndexUpdated(ICultureIndex cultureIndex);

    event CultureIndexLocked();

    function mint() external returns (uint256);

    function burn(uint256 tokenId) external;

    function dataURI(uint256 tokenId) external returns (string memory);

    function setMinter(address minter) external;

    function lockMinter() external;

    function setDescriptor(IDescriptorMinimal descriptor) external;

    function lockDescriptor() external;

    function lockCultureIndex() external;

    function getArtPieceById(uint256 tokenId) external view returns (ICultureIndex.ArtPiece memory);

    /// @notice Initializes a DAO's ERC-721 token contract
    /// @param minter The address of the minter
    /// @param initialOwner The address of the initial owner
    /// @param descriptor The address of the token URI descriptor
    /// @param cultureIndex The address of the CultureIndex contract
    /// @param erc721TokenParams The name, symbol, and contract metadata of the token
    function initialize(
        address minter,
        address initialOwner,
        address descriptor,
        address cultureIndex,
        IRevolutionBuilder.ERC721TokenParams memory erc721TokenParams
    ) external;
}
