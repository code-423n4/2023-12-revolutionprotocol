// SPDX-License-Identifier: GPL-3.0

/// @title Interface for Descriptor

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

import { IDescriptorMinimal } from "./IDescriptorMinimal.sol";
import { ICultureIndex } from "./ICultureIndex.sol";

interface IDescriptor is IDescriptorMinimal {
    event DataURIToggled(bool enabled);

    event BaseURIUpdated(string baseURI);

    function isDataURIEnabled() external returns (bool);

    function baseURI() external returns (string memory);

    function toggleDataURIEnabled() external;

    function setBaseURI(string calldata baseURI) external;

    function tokenURI(uint256 tokenId, ICultureIndex.ArtPieceMetadata memory) external view returns (string memory);

    function dataURI(uint256 tokenId, ICultureIndex.ArtPieceMetadata memory) external view returns (string memory);

    function genericDataURI(
        string calldata name,
        ICultureIndex.ArtPieceMetadata memory
    ) external view returns (string memory);

    /// @notice Initializes a token's metadata descriptor
    /// @param initialOwner The address of the initial owner
    /// @param tokenNamePrefix The prefix for the token name eg: "Vrb" -> Vrb 1
    function initialize(address initialOwner, string calldata tokenNamePrefix) external;
}
