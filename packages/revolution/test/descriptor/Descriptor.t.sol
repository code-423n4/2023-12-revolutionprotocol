// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import "forge-std/Test.sol";
import "../../src/Descriptor.sol";
import { IDescriptor } from "../../src/interfaces/IDescriptor.sol";
import "../utils/Base64Decode.sol";
import "../utils/JsmnSolLib.sol";
import { ICultureIndex } from "../../src/interfaces/ICultureIndex.sol";
import { RevolutionBuilderTest } from "../RevolutionBuilder.t.sol";

contract DescriptorTest is RevolutionBuilderTest {
    string tokenNamePrefix = "Vrb";

    function setUp() public override {
        super.setUp();
        super.setMockParams();

        super.setERC721TokenParams("Mock", "MOCK", "https://example.com/token/", tokenNamePrefix);

        super.deployMock();

        vm.startPrank(address(dao));
    }

    /// @notice Test that toggling `isDataURIEnabled` changes state correctly
    function testToggleDataURIEnabled() public {
        bool originalState = descriptor.isDataURIEnabled();
        descriptor.toggleDataURIEnabled();
        bool newState = descriptor.isDataURIEnabled();

        assertEq(newState, !originalState, "isDataURIEnabled should be toggled");
    }

    /// @notice Test that only owner can toggle `isDataURIEnabled`
    function testToggleDataURIEnabledAccessControl() public {
        vm.stopPrank();
        address nonOwner = address(0x123);
        vm.startPrank(nonOwner);
        vm.expectRevert();
        descriptor.toggleDataURIEnabled();
        vm.stopPrank();
    }

    /// @notice Test `setBaseURI` updates `baseURI` correctly
    function testSetBaseURI() public {
        string memory newBaseURI = "https://example.com/";
        descriptor.setBaseURI(newBaseURI);
        string memory currentBaseURI = descriptor.baseURI();

        assertEq(currentBaseURI, newBaseURI, "baseURI should be updated");
    }

    /// @notice Test that only the owner can update `baseURI`
    function testSetBaseURI_AccessControl() public {
        vm.stopPrank();
        string memory newBaseURI = "https://newexample.com/";
        address nonOwner = address(0x456);

        vm.startPrank(nonOwner);
        vm.expectRevert();
        descriptor.setBaseURI(newBaseURI);
        vm.stopPrank();

        // The baseURI should remain unchanged since the non-owner could not update it
        string memory currentBaseURI = descriptor.baseURI();
        assertEq(currentBaseURI, "", "baseURI should not have changed");
    }

    /// @notice Test `tokenURI` returns correct data URI when `isDataURIEnabled` is true
    function testTokenURIWithDataURIEnabled() public {
        // Enable data URI
        descriptor.toggleDataURIEnabled();
        assertFalse(descriptor.isDataURIEnabled(), "Data URI should be enabled");

        // Set up a token ID and dummy metadata
        uint256 tokenId = 1;
        ICultureIndex.ArtPieceMetadata memory metadata = ICultureIndex.ArtPieceMetadata({
            name: "Test Art",
            description: "A description",
            mediaType: ICultureIndex.MediaType.IMAGE,
            image: "https://example.com/image.png",
            text: "",
            animationUrl: ""
        });

        // Call tokenURI and check the return value is a data URI
        string memory uri = descriptor.tokenURI(tokenId, metadata);
        assertTrue(bytes(uri).length > 0, "URI should not be empty");
        emit log_string(uri);
        // Further data URI validation can be done here if necessary

        //tokenURI should just be 1
        assertEq(uri, "1", "URI should just be the token ID");
    }

    /// @notice Test `tokenURI` returns correct HTTP URL when `isDataURIEnabled` is false
    function testTokenURIWithHTTPURL() public {
        // Make sure data URI is disabled
        descriptor.toggleDataURIEnabled();
        assertFalse(descriptor.isDataURIEnabled(), "Data URI should be disabled");

        // Set base URI
        string memory baseURI = "https://api.example.com/token/";
        descriptor.setBaseURI(baseURI);

        // Set up token ID
        uint256 tokenId = 1;

        // Create dummy metadata
        ICultureIndex.ArtPieceMetadata memory metadata = ICultureIndex.ArtPieceMetadata({
            name: "Test Art",
            description: "A description",
            mediaType: ICultureIndex.MediaType.IMAGE,
            image: "https://example.com/image.png",
            text: "",
            animationUrl: ""
        });

        // Call tokenURI and check it returns the correct HTTP URL
        string memory expectedURI = string(abi.encodePacked(baseURI, Strings.toString(tokenId)));
        string memory actualURI = descriptor.tokenURI(tokenId, metadata);
        assertEq(actualURI, expectedURI, "The URI should be a concatenation of the baseURI and token ID");
    }

    /// @notice Test `dataURI` returns valid base64 encoded data URI
    function testDataURI() public {
        uint256 tokenId = 1;
        ICultureIndex.ArtPieceMetadata memory metadata = ICultureIndex.ArtPieceMetadata({
            name: "Test Art",
            description: "A piece of art",
            mediaType: ICultureIndex.MediaType.IMAGE,
            image: "https://example.com/image.png",
            text: "",
            animationUrl: ""
        });

        string memory uri = descriptor.dataURI(tokenId, metadata);
        assertTrue(bytes(uri).length > 0, "dataURI should not be empty");
        // Check if the string contains the base64 identifier which indicates a base64 encoded data URI
        assertEq(
            substring(bytes(uri), 0, 29),
            "data:application/json;base64,",
            "dataURI should start with 'data:application/json;base64,'"
        );
    }

    /// @notice Test `genericDataURI` returns valid base64 encoded data URI
    function testGenericDataURI() public {
        ICultureIndex.ArtPieceMetadata memory metadata = ICultureIndex.ArtPieceMetadata({
            name: "Test Art",
            description: "A generic art piece",
            mediaType: ICultureIndex.MediaType.IMAGE,
            image: "https://example.com/image.png",
            text: "",
            animationUrl: ""
        });

        string memory uri = descriptor.genericDataURI(metadata.name, metadata);
        assertTrue(bytes(uri).length > 0, "genericDataURI should not be empty");
        assertEq(
            substring(bytes(uri), 0, 29),
            "data:application/json;base64,",
            "dataURI should start with 'data:application/json;base64,'"
        );
    }

    /// @notice Test `toggleDataURIEnabled` emits `DataURIToggled` event
    function testToggleDataURIEnabledEvent() public {
        bool expectedNewState = !descriptor.isDataURIEnabled();
        vm.expectEmit(true, true, false, true);
        emit IDescriptor.DataURIToggled(expectedNewState);
        descriptor.toggleDataURIEnabled();
    }

    /// @notice Test `setBaseURI` emits `BaseURIUpdated` event
    function testSetBaseURIEvent() public {
        string memory newBaseURI = "https://example.com/newbase";
        vm.expectEmit(true, true, false, true);
        emit IDescriptor.BaseURIUpdated(newBaseURI);
        descriptor.setBaseURI(newBaseURI);
    }

    /// @notice Test baseline `tokenURI` with `isDataURIEnabled` true by default
    function testBaselineTokenURIWithDataURIEnabled() public {
        // Since isDataURIEnabled is true by default, we don't need to toggle it
        assertTrue(descriptor.isDataURIEnabled(), "isDataURIEnabled should be true by default");

        uint256 tokenId = 1;
        ICultureIndex.ArtPieceMetadata memory metadata = ICultureIndex.ArtPieceMetadata({
            name: "Baseline Art",
            description: "The baseline piece",
            mediaType: ICultureIndex.MediaType.IMAGE,
            image: "https://example.com/baseline.png",
            text: "",
            animationUrl: ""
        });

        string memory uri = descriptor.tokenURI(tokenId, metadata);
        assertTrue(bytes(uri).length > 0, "URI should not be empty");
        assertEq(
            substring(bytes(uri), 0, 29),
            "data:application/json;base64,",
            "dataURI should start with 'data:application/json;base64,'"
        );
    }

    /// @notice Test owner can transfer ownership using `transferOwnership`
    function testTransferOwnership() public {
        address newOwner = address(0x456);

        // The current owner transfers ownership to the newOwner
        descriptor.transferOwnership(newOwner);

        vm.startPrank(address(newOwner));
        descriptor.acceptOwnership();

        // Verify that the new owner is indeed set
        assertEq(descriptor.owner(), newOwner, "Ownership should be transferred to newOwner");
    }

    /// @notice Ensure `transferOwnership` access control
    function testTransferOwnershipAccessControl() public {
        vm.stopPrank();
        address nonOwner = address(0x789);
        address newOwner = address(0x456);

        // Start prank as nonOwner, expect revert on ownership transfer attempt
        vm.startPrank(nonOwner);
        vm.expectRevert();
        descriptor.transferOwnership(newOwner);
        vm.stopPrank();

        // Verify ownership has not changed
        assertEq(descriptor.owner(), address(dao), "Ownership should not have changed");
    }

    /// @notice Test `tokenURI` with only image metadata set
    function testTokenURIWithOnlyImageMetadata() public {
        uint256 tokenId = 1;
        ICultureIndex.ArtPieceMetadata memory metadata = ICultureIndex.ArtPieceMetadata({
            name: "",
            description: "",
            mediaType: ICultureIndex.MediaType.IMAGE,
            image: "https://example.com/image.png",
            text: "",
            animationUrl: ""
        });

        string memory uri = descriptor.tokenURI(tokenId, metadata);

        // Check if the token URI contains the image URL
        assertUriContainsImage(uri, metadata.image, "Token URI should contain the image metadata");
    }

    /// @notice Test `tokenURI` with mixed media types in metadata
    function testTokenURIWithMixedMediaMetadata() public {
        uint256 tokenId = 3;
        ICultureIndex.ArtPieceMetadata memory metadata = ICultureIndex.ArtPieceMetadata({
            name: "Mixed Media Art",
            description: "Art with mixed media types",
            mediaType: ICultureIndex.MediaType.ANIMATION,
            image: "https://example.com/mixed-image.png",
            text: "",
            animationUrl: "https://example.com/mixed-animation.mp4"
        });

        string memory uri = descriptor.tokenURI(tokenId, metadata);

        // The token URI should reflect both image and animation URLs
        assertFullMetadataIntegrity(uri, metadata, tokenId, "Token URI should reflect mixed media types correctly");
    }

    /// @notice Test `tokenURI` with full metadata set
    function testTokenURIWithFullMetadata() public {
        uint256 tokenId = 2;
        ICultureIndex.ArtPieceMetadata memory metadata = ICultureIndex.ArtPieceMetadata({
            name: "Full Metadata Art",
            description: "Complete metadata for testing",
            mediaType: ICultureIndex.MediaType.IMAGE,
            image: "https://example.com/full-image.png",
            text: "This is a full metadata test.",
            animationUrl: "https://example.com/animation.mp4"
        });

        string memory uri = descriptor.tokenURI(tokenId, metadata);

        // Validate the token URI against the full metadata
        assertFullMetadataIntegrity(uri, metadata, tokenId, "Token URI should correctly represent the full metadata");
    }

    // Corrected use of startsWith in assertUriContainsImage function
    function assertUriContainsImage(
        string memory uri,
        string memory expectedImageUrl,
        string memory errorMessage
    ) internal {
        // Decode the URI if it's a data URI, else use as is
        string memory metadataJson = startsWith(uri, "data:") ? decodeMetadata(uri) : uri;
        (, , string memory imageUrl, ) = parseJson(metadataJson);

        assertEq(imageUrl, expectedImageUrl, errorMessage);
    }

    // Helper function to assert the integrity of the full metadata in the token URI
    function assertFullMetadataIntegrity(
        string memory uri,
        ICultureIndex.ArtPieceMetadata memory expectedMetadata,
        uint256 tokenId,
        string memory errorMessage
    ) internal {
        string memory metadataJson = decodeMetadata(uri);
        (string memory name, string memory description, string memory imageUrl, string memory animationUrl) = parseJson(
            metadataJson
        );

        //expected name should tokenNamePrefix + space + tokenId
        string memory expectedName = string(abi.encodePacked(tokenNamePrefix, " ", Strings.toString(tokenId)));

        assertEq(name, expectedName, string(abi.encodePacked(errorMessage, " - Name mismatch")));
        assertEq(
            description,
            string(abi.encodePacked(expectedMetadata.name, ". ", expectedMetadata.description)),
            string(abi.encodePacked(errorMessage, " - Description mismatch"))
        );
        assertEq(imageUrl, expectedMetadata.image, string(abi.encodePacked(errorMessage, " - Image URL mismatch")));
        assertEq(
            animationUrl,
            expectedMetadata.animationUrl,
            string(abi.encodePacked(errorMessage, " - Animation URL mismatch"))
        );
        // Additional assertions for text and animationUrl can be added here if required
    }

    // Helper function to decode base64 encoded metadata from a data URI
    function decodeMetadata(string memory uri) internal pure returns (string memory) {
        // Split the URI into its components and decode the base64 part
        (, string memory base64Part) = splitDataURI(uri);
        bytes memory decodedBytes = Base64Decode.decode(base64Part);
        return string(decodedBytes);
    }

    // Helper function to parse JSON strings into components
    function parseJson(
        string memory _json
    )
        internal
        returns (string memory name, string memory description, string memory image, string memory animationUrl)
    {
        uint returnValue;
        JsmnSolLib.Token[] memory tokens;
        uint actualNum;

        // Number of tokens to be parsed in the JSON (could be estimated or exactly known)
        uint256 numTokens = 20; // Increase if necessary to accommodate all fields in the JSON

        // Parse the JSON
        (returnValue, tokens, actualNum) = JsmnSolLib.parse(_json, numTokens);

        emit log_uint(returnValue);
        emit log_uint(actualNum);
        emit log_uint(tokens.length);

        // Extract values from JSON by token indices
        for (uint256 i = 0; i < actualNum; i++) {
            JsmnSolLib.Token memory t = tokens[i];

            // Check if the token is a key
            if (t.jsmnType == JsmnSolLib.JsmnType.STRING && (i + 1) < actualNum) {
                string memory key = JsmnSolLib.getBytes(_json, t.start, t.end);
                string memory value = JsmnSolLib.getBytes(_json, tokens[i + 1].start, tokens[i + 1].end);

                // Compare the key with expected fields
                if (keccak256(bytes(key)) == keccak256(bytes("name"))) {
                    name = value;
                } else if (keccak256(bytes(key)) == keccak256(bytes("description"))) {
                    description = value;
                } else if (keccak256(bytes(key)) == keccak256(bytes("image"))) {
                    image = value;
                } else if (keccak256(bytes(key)) == keccak256(bytes("animation_url"))) {
                    animationUrl = value;
                }
                // Skip the value token, as the key's value is always the next token
                i++;
            }
        }

        return (name, description, image, animationUrl);
    }

    // Helper function to check if the URI starts with a specific string
    function startsWith(string memory fullString, string memory searchString) internal pure returns (bool) {
        bytes memory fullStringBytes = bytes(fullString);
        bytes memory searchStringBytes = bytes(searchString);

        if (searchStringBytes.length > fullStringBytes.length) {
            return false;
        }

        for (uint i = 0; i < searchStringBytes.length; i++) {
            if (fullStringBytes[i] != searchStringBytes[i]) {
                return false;
            }
        }

        return true;
    }

    /// @notice Splits a data URI into its MIME type and base64 components.
    /// @param uri The data URI to split.
    /// @return mimeType The MIME type of the data.
    /// @return base64Data The base64 encoded data.
    function splitDataURI(string memory uri) internal pure returns (string memory mimeType, string memory base64Data) {
        // Find the comma that separates the MIME type from the base64 data
        bytes memory uriBytes = bytes(uri);
        uint256 commaIndex = findComma(uriBytes);

        // Extract the MIME type
        mimeType = string(substring(uriBytes, 5, commaIndex)); // Starting after 'data:'

        // Extract the base64 encoded data
        base64Data = string(substring(uriBytes, commaIndex + 1, uriBytes.length));

        return (mimeType, base64Data);
    }

    /// @notice Finds the index of the first comma in a bytes array.
    /// @param b The bytes array to search.
    /// @return The index of the first comma.
    function findComma(bytes memory b) internal pure returns (uint256) {
        for (uint256 i = 0; i < b.length; i++) {
            if (b[i] == ",") {
                return i;
            }
        }
        revert("Comma not found in data URI");
    }

    /// @notice Gets a substring from a bytes array, given the start and end index.
    /// @param b The bytes array to get a substring from.
    /// @param startIndex The start index of the substring.
    /// @param endIndex The end index of the substring.
    /// @return The substring.
    function substring(bytes memory b, uint256 startIndex, uint256 endIndex) internal pure returns (bytes memory) {
        bytes memory result = new bytes(endIndex - startIndex);
        for (uint256 i = startIndex; i < endIndex; i++) {
            result[i - startIndex] = b[i];
        }
        return result;
    }
}
