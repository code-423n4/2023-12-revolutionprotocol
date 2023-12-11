// SPDX-License-Identifier: MIT
pragma solidity 0.8.22;

interface IMaxHeap {
    /**
     * @notice Initializes the maxheap contract
     * @param _initialOwner The initial owner of the contract
     */
    function initialize(address _initialOwner) external;
}
