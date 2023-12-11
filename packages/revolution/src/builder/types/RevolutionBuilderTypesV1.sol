// SPDX-License-Identifier: MIT
pragma solidity 0.8.22;

/// @title RevolutionBuilderTypesV1
/// @author rocketman
/// @notice The external Base Metadata errors and functions
interface RevolutionBuilderTypesV1 {
    /// @notice Stores deployed addresses for a given token's DAO
    struct DAOAddresses {
        /// @notice Address for deployed metadata contract
        address descriptor;
        /// @notice Address for deployed auction contract
        address auction;
        /// @notice Address for deployed auction contract
        address erc20TokenEmitter;
        /// @notice Address for deployed auction contract
        address erc20Token;
        /// @notice Address for deployed cultureIndex contract
        address cultureIndex;
        /// @notice Address for deployed treasury contract
        address executor;
        /// @notice Address for deployed DAO contract
        address dao;
        /// @notice Address for deployed ERC-721 token contract
        address erc721Token;
        /// @notice Address for deployed MaxHeap contract
        address maxHeap;
    }
}
