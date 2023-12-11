// SPDX-License-Identifier: MIT
pragma solidity 0.8.22;

interface IMaxHeap {
    /**
     * @notice Initializes the maxheap contract
     * @param initialOwner The initial owner of the contract
     * @param admin The contract that is allowed to update the data store
     */
    function initialize(address initialOwner, address admin) external;
}
