// SPDX-License-Identifier: MIT

pragma solidity 0.8.22;

import "../governance/VerbsDAOInterfaces.sol";
import { IRevolutionBuilder } from "./IRevolutionBuilder.sol";

interface IVerbsDAO {
    /**
     * @notice Used to initialize the contract during delegator contructor
     * @param executor The address of the DAOExecutor
     * @param erc721Token The address of the ERC-721 token
     * @param erc20Token The address of the ERC-20 token
     * @param govParams The initial governance parameters
     */
    function initialize(
        address executor,
        address erc721Token,
        address erc20Token,
        IRevolutionBuilder.GovParams calldata govParams
    ) external;
}
