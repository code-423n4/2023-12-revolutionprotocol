// SPDX-License-Identifier: GPL-3.0

/// @title Interface for VerbsDescriptor

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

import { IVerbsDescriptorMinimal } from "./IVerbsDescriptorMinimal.sol";
import { ICultureIndex } from "./ICultureIndex.sol";

interface IVerbsDescriptor is IVerbsDescriptorMinimal {
    event PartsLocked();

    event DataURIToggled(bool enabled);

    event BaseURIUpdated(string baseURI);

    function isDataURIEnabled() external returns (bool);

    function baseURI() external returns (string memory);

    function toggleDataURIEnabled() external;

    function setBaseURI(string calldata baseURI) external;

    function tokenURI(uint256 tokenId, ICultureIndex.ArtPieceMetadata memory) external view returns (string memory);

    function dataURI(uint256 tokenId, ICultureIndex.ArtPieceMetadata memory) external view returns (string memory);

    function genericDataURI(string calldata name, ICultureIndex.ArtPieceMetadata memory) external view returns (string memory);
}
