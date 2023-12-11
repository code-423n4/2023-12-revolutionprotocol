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

import { Ownable2StepUpgradeable } from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import { ReentrancyGuardUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import { IERC721 } from "@openzeppelin/contracts/token/ERC721/IERC721.sol";

import { UUPS } from "./libs/proxy/UUPS.sol";
import { VersionedContract } from "./version/VersionedContract.sol";

import { ERC721CheckpointableUpgradeable } from "./base/ERC721CheckpointableUpgradeable.sol";
import { IDescriptorMinimal } from "./interfaces/IDescriptorMinimal.sol";
import { ICultureIndex } from "./interfaces/ICultureIndex.sol";
import { IVerbsToken } from "./interfaces/IVerbsToken.sol";
import { IRevolutionBuilder } from "./interfaces/IRevolutionBuilder.sol";

contract VerbsToken is
    IVerbsToken,
    VersionedContract,
    UUPS,
    Ownable2StepUpgradeable,
    ReentrancyGuardUpgradeable,
    ERC721CheckpointableUpgradeable
{
    // An address who has permissions to mint Verbs
    address public minter;

    // The Verbs token URI descriptor
    IDescriptorMinimal public descriptor;

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

    // The Verb art pieces
    mapping(uint256 => ICultureIndex.ArtPiece) public artPieces;

    ///                                                          ///
    ///                          MODIFIERS                       ///
    ///                                                          ///

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

    ///                                                          ///
    ///                         IMMUTABLES                       ///
    ///                                                          ///

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

    /// @notice Initializes a DAO's ERC-721 token contract
    /// @param _minter The address of the minter
    /// @param _initialOwner The address of the initial owner
    /// @param _descriptor The address of the token URI descriptor
    /// @param _cultureIndex The address of the CultureIndex contract
    /// @param _erc721TokenParams The name, symbol, and contract metadata of the token
    function initialize(
        address _minter,
        address _initialOwner,
        address _descriptor,
        address _cultureIndex,
        IRevolutionBuilder.ERC721TokenParams memory _erc721TokenParams
    ) external initializer {
        require(msg.sender == address(manager), "Only manager can initialize");

        require(_minter != address(0), "Minter cannot be zero address");
        require(_initialOwner != address(0), "Initial owner cannot be zero address");

        // Initialize the reentrancy guard
        __ReentrancyGuard_init();

        // Setup ownable
        __Ownable_init(_initialOwner);

        // Initialize the ERC-721 token
        __ERC721_init(_erc721TokenParams.name, _erc721TokenParams.symbol);
        _contractURIHash = _erc721TokenParams.contractURIHash;

        // Set the contracts
        minter = _minter;
        descriptor = IDescriptorMinimal(_descriptor);
        cultureIndex = ICultureIndex(_cultureIndex);
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
        return descriptor.tokenURI(tokenId, artPieces[tokenId].metadata);
    }

    /**
     * @notice Similar to `tokenURI`, but always serves a base64 encoded data URI
     * with the JSON contents directly inlined.
     */
    function dataURI(uint256 tokenId) public view override returns (string memory) {
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
    function setDescriptor(
        IDescriptorMinimal _descriptor
    ) external override onlyOwner nonReentrant whenDescriptorNotLocked {
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
     * @notice Mint a Verb with `verbId` to the provided `to` address. Pulls the top voted art piece from the CultureIndex.
     */
    function _mintTo(address to) internal returns (uint256) {
        ICultureIndex.ArtPiece memory artPiece = cultureIndex.getTopVotedPiece();

        // Check-Effects-Interactions Pattern
        // Perform all checks
        require(
            artPiece.creators.length <= cultureIndex.MAX_NUM_CREATORS(),
            "Creator array must not be > MAX_NUM_CREATORS"
        );

        // Use try/catch to handle potential failure
        try cultureIndex.dropTopVotedPiece() returns (ICultureIndex.ArtPiece memory _artPiece) {
            artPiece = _artPiece;
            uint256 verbId = _currentVerbId++;

            ICultureIndex.ArtPiece storage newPiece = artPieces[verbId];

            newPiece.pieceId = artPiece.pieceId;
            newPiece.metadata = artPiece.metadata;
            newPiece.isDropped = artPiece.isDropped;
            newPiece.sponsor = artPiece.sponsor;
            newPiece.totalERC20Supply = artPiece.totalERC20Supply;
            newPiece.quorumVotes = artPiece.quorumVotes;
            newPiece.totalVotesSupply = artPiece.totalVotesSupply;

            for (uint i = 0; i < artPiece.creators.length; i++) {
                newPiece.creators.push(artPiece.creators[i]);
            }

            _mint(to, verbId);

            emit VerbCreated(verbId, artPiece);

            return verbId;
        } catch {
            // Handle failure (e.g., revert, emit an event, set a flag, etc.)
            revert("dropTopVotedPiece failed");
        }
    }

    ///                                                          ///
    ///                         TOKEN UPGRADE                    ///
    ///                                                          ///

    // /// @notice Ensures the caller is authorized to upgrade the contract and that the new implementation is valid
    // /// @dev This function is called in `upgradeTo` & `upgradeToAndCall`
    // /// @param _newImpl The new implementation address
    function _authorizeUpgrade(address _newImpl) internal view override onlyOwner {
        // Ensure the implementation is valid
        require(manager.isRegisteredUpgrade(_getImplementation(), _newImpl), "Invalid upgrade");
    }
}
