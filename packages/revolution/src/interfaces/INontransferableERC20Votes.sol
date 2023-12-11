// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import { IRevolutionBuilder } from "./IRevolutionBuilder.sol";

interface INontransferableERC20Votes {
    /// @notice Initializes a DAO's ERC-20 governance token contract
    /// @param initialOwner The address of the initial owner
    /// @param erc20TokenParams The params of the token
    function initialize(address initialOwner, IRevolutionBuilder.ERC20TokenParams calldata erc20TokenParams) external;
}
