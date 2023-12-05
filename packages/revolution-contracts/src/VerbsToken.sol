// SPDX-License-Identifier: GPL-3.0

/// @title The Verbs ERC-721 token

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

import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { ERC721Checkpointable } from "./base/ERC721Checkpointable.sol";
import { IVerbsDescriptorMinimal } from "./interfaces/IVerbsDescriptorMinimal.sol";
import { ICultureIndex } from "./interfaces/ICultureIndex.sol";
import { IVerbsToken } from "./interfaces/IVerbsToken.sol";
import { ERC721 } from "./base/ERC721.sol";
import { IERC721 } from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import { IProxyRegistry } from "./external/opensea/IProxyRegistry.sol";
import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

contract VerbsToken is IVerbsToken, Ownable, ERC721Checkpointable, ReentrancyGuard {
    // An address who has permissions to mint Verbs
    address public minter;

    // The Verbs token URI descriptor
    IVerbsDescriptorMinimal public descriptor;

    // The CultureIndex contract
    ICultureIndex public cultureIndex;

    // Whether the minter can be updated
    bool public isMinterLocked;

    // Whether the CultureIndex can be updated
    bool public isCultureIndexLocked;

    // Whether the descriptor can be updated
    bool public isDescriptorLocked;

    // The internal verb ID tracker
    uint256 private _currentVerbId;

    // IPFS content hash of contract-level metadata
    string private _contractURIHash = "QmQzDwaZ7yQxHHs7sQQenJVB89riTSacSGcJRv9jtHPuz5";

    // OpenSea's Proxy Registry
    IProxyRegistry public immutable proxyRegistry;

    // The Verb art pieces
    mapping(uint256 => ICultureIndex.ArtPiece) public artPieces;

    /**
     * @notice Require that the minter has not been locked.
     */
    modifier whenMinterNotLocked() {
        require(!isMinterLocked, "Minter is locked");
        _;
    }

    /**
     * @notice Require that the CultureIndex has not been locked.
     */
    modifier whenCultureIndexNotLocked() {
        require(!isCultureIndexLocked, "CultureIndex is locked");
        _;
    }

    /**
     * @notice Require that the descriptor has not been locked.
     */
    modifier whenDescriptorNotLocked() {
        require(!isDescriptorLocked, "Descriptor is locked");
        _;
    }

    /**
     * @notice Require that the sender is the minter.
     */
    modifier onlyMinter() {
        require(msg.sender == minter, "Sender is not the minter");
        _;
    }

    constructor(
        address _minter,
        address _initialOwner,
        IVerbsDescriptorMinimal _descriptor,
        IProxyRegistry _proxyRegistry,
        ICultureIndex _cultureIndex,
        string memory _tokenName,
        string memory _tokenSymbol
    ) ERC721(_tokenName, _tokenSymbol) Ownable(_initialOwner) {
        require(_minter != address(0), "Minter cannot be zero address");
        minter = _minter;
        descriptor = _descriptor;
        cultureIndex = _cultureIndex;
        proxyRegistry = _proxyRegistry;
    }

    /**
     * @notice The IPFS URI of contract-level metadata.
     */
    function contractURI() public view returns (string memory) {
        return string(abi.encodePacked("ipfs://", _contractURIHash));
    }

    /**
     * @notice Set the _contractURIHash.
     * @dev Only callable by the owner.
     */
    function setContractURIHash(string memory newContractURIHash) external onlyOwner {
        _contractURIHash = newContractURIHash;
    }

    /**
     * @notice Override isApprovedForAll to whitelist user's OpenSea proxy accounts to enable gas-less listings.
     */
    function isApprovedForAll(address owner, address operator) public view override(IERC721, ERC721) returns (bool) {
        // Whitelist OpenSea proxy contract for easy trading.
        if (proxyRegistry.proxies(owner) == operator) {
            return true;
        }
        return super.isApprovedForAll(owner, operator);
    }

    /**
     * @notice Mint a Verb to the minter.
     * @dev Call _mintTo with the to address(es).
     */
    function mint() public override onlyMinter nonReentrant returns (uint256) {
        return _mintTo(minter);
    }

    /**
     * @notice Burn a verb.
     */
    function burn(uint256 verbId) public override onlyMinter nonReentrant {
        _burn(verbId);
        emit VerbBurned(verbId);
    }

    /**
     * @notice A distinct Uniform Resource Identifier (URI) for a given asset.
     * @dev See {IERC721Metadata-tokenURI}.
     */
    function tokenURI(uint256 tokenId) public view override returns (string memory) {
        require(_exists(tokenId), "VerbsToken: URI query for nonexistent token");
        return descriptor.tokenURI(tokenId, artPieces[tokenId].metadata);
    }

    /**
     * @notice Similar to `tokenURI`, but always serves a base64 encoded data URI
     * with the JSON contents directly inlined.
     */
    function dataURI(uint256 tokenId) public view override returns (string memory) {
        require(_exists(tokenId), "VerbsToken: URI query for nonexistent token");
        return descriptor.dataURI(tokenId, artPieces[tokenId].metadata);
    }

    /**
     * @notice Set the token minter.
     * @dev Only callable by the owner when not locked.
     */
    function setMinter(address _minter) external override onlyOwner nonReentrant whenMinterNotLocked {
        require(_minter != address(0), "Minter cannot be zero address");
        minter = _minter;

        emit MinterUpdated(_minter);
    }

    /**
     * @notice Lock the minter.
     * @dev This cannot be reversed and is only callable by the owner when not locked.
     */
    function lockMinter() external override onlyOwner whenMinterNotLocked {
        isMinterLocked = true;

        emit MinterLocked();
    }

    /**
     * @notice Set the token URI descriptor.
     * @dev Only callable by the owner when not locked.
     */
    function setDescriptor(IVerbsDescriptorMinimal _descriptor) external override onlyOwner nonReentrant whenDescriptorNotLocked {
        descriptor = _descriptor;

        emit DescriptorUpdated(_descriptor);
    }

    /**
     * @notice Lock the descriptor.
     * @dev This cannot be reversed and is only callable by the owner when not locked.
     */
    function lockDescriptor() external override onlyOwner whenDescriptorNotLocked {
        isDescriptorLocked = true;

        emit DescriptorLocked();
    }

    /**
     * @notice Set the token CultureIndex.
     * @dev Only callable by the owner when not locked.
     */
    function setCultureIndex(ICultureIndex _cultureIndex) external onlyOwner whenCultureIndexNotLocked nonReentrant {
        cultureIndex = _cultureIndex;

        emit CultureIndexUpdated(_cultureIndex);
    }

    /**
     * @notice Lock the CultureIndex
     * @dev This cannot be reversed and is only callable by the owner when not locked.
     */
    function lockCultureIndex() external override onlyOwner whenCultureIndexNotLocked {
        isCultureIndexLocked = true;

        emit CultureIndexLocked();
    }

    /**
     * @notice Fetch an art piece by its ID.
     * @param verbId The ID of the art piece.
     * @return The ArtPiece struct associated with the given ID.
     */
    function getArtPieceById(uint256 verbId) public view returns (ICultureIndex.ArtPiece memory) {
        require(verbId <= _currentVerbId, "Invalid piece ID");
        return artPieces[verbId];
    }

    /**
     * @notice Mint a Verb with `verbId` to the provided `to` address.
     */
    function _mintTo(address to) internal returns (uint256) {
        ICultureIndex.ArtPiece memory artPiece = cultureIndex.getTopVotedPiece();

        // Check-Effects-Interactions Pattern
        // Perform all checks
        require(artPiece.creators.length <= 100, "Creator array must not be > 100");

        // Use try/catch to handle potential failure
        try cultureIndex.dropTopVotedPiece() returns (ICultureIndex.ArtPiece memory _artPiece) {
            artPiece = _artPiece;
            uint256 verbId = _currentVerbId++;

            ICultureIndex.ArtPiece storage newPiece = artPieces[verbId];

            newPiece.pieceId = artPiece.pieceId;
            newPiece.metadata = artPiece.metadata;
            newPiece.isDropped = artPiece.isDropped;
            newPiece.dropper = artPiece.dropper;

            for (uint i = 0; i < artPiece.creators.length; i++) {
                newPiece.creators.push(artPiece.creators[i]);
            }

            _mint(owner(), to, verbId);

            emit VerbCreated(verbId, artPiece);

            return verbId;
        } catch {
            // Handle failure (e.g., revert, emit an event, set a flag, etc.)
            revert("dropTopVotedPiece failed");
        }
    }
}
