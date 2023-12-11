// SPDX-License-Identifier: MIT
pragma solidity 0.8.22;

import { RevolutionBuilderTypesV1 } from "../types/RevolutionBuilderTypesV1.sol";

/// @notice RevolutionBuilder Storage V1
/// @author Rohan Kulkarni
/// @notice The Manager storage contract
contract RevolutionBuilderStorageV1 is RevolutionBuilderTypesV1 {
    /// @notice If a contract has been registered as an upgrade
    /// @dev Base impl => Upgrade impl
    mapping(address => mapping(address => bool)) internal isUpgrade;

    /// @notice Registers deployed addresses
    /// @dev Token deployed address => Struct of all other DAO addresses
    mapping(address => DAOAddresses) internal daoAddressesByToken;
}
