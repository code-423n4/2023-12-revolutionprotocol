// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.22;

import { Ownable2StepUpgradeable } from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import { ReentrancyGuardUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import { IRevolutionBuilder } from "./interfaces/IRevolutionBuilder.sol";

import { UUPS } from "./libs/proxy/UUPS.sol";
import { VersionedContract } from "./version/VersionedContract.sol";

/// @title MaxHeap implementation in Solidity
/// @dev This contract implements a Max Heap data structure with basic operations
/// @author Written by rocketman and gpt4
contract MaxHeap is VersionedContract, UUPS, Ownable2StepUpgradeable, ReentrancyGuardUpgradeable {
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

    /**
     * @notice Initializes the maxheap contract
     * @param _initialOwner The initial owner of the contract
     */
    function initialize(address _initialOwner) public initializer {
        require(msg.sender == address(manager), "Only manager can initialize");

        __Ownable_init(_initialOwner);
        __ReentrancyGuard_init();
    }

    /// @notice Struct to represent an item in the heap by it's ID
    mapping(uint256 => uint256) public heap;

    uint256 public size = 0;

    /// @notice Mapping to keep track of the value of an item in the heap
    mapping(uint256 => uint256) public valueMapping;

    /// @notice Mapping to keep track of the position of an item in the heap
    mapping(uint256 => uint256) public positionMapping;

    /// @notice Get the parent index of a given position
    /// @param pos The position for which to find the parent
    /// @return The index of the parent node
    function parent(uint256 pos) private pure returns (uint256) {
        require(pos != 0, "Position should not be zero");
        return (pos - 1) / 2;
    }

    /// @notice Swap two nodes in the heap
    /// @param fpos The position of the first node
    /// @param spos The position of the second node
    function swap(uint256 fpos, uint256 spos) private {
        (heap[fpos], heap[spos]) = (heap[spos], heap[fpos]);
        (positionMapping[heap[fpos]], positionMapping[heap[spos]]) = (fpos, spos);
    }

    /// @notice Reheapify the heap starting at a given position
    /// @dev This ensures that the heap property is maintained
    /// @param pos The starting position for the heapify operation
    function maxHeapify(uint256 pos) public onlyOwner {
        uint256 left = 2 * pos + 1;
        uint256 right = 2 * pos + 2;

        uint256 posValue = valueMapping[heap[pos]];
        uint256 leftValue = valueMapping[heap[left]];
        uint256 rightValue = valueMapping[heap[right]];

        if (pos >= (size / 2) && pos <= size) return;

        if (posValue < leftValue || posValue < rightValue) {
            if (leftValue > rightValue) {
                swap(pos, left);
                maxHeapify(left);
            } else {
                swap(pos, right);
                maxHeapify(right);
            }
        }
    }

    /// @notice Insert an element into the heap
    /// @dev The function will revert if the heap is full
    /// @param itemId The item ID to insert
    /// @param value The value to insert
    function insert(uint256 itemId, uint256 value) public onlyOwner {
        heap[size] = itemId;
        valueMapping[itemId] = value; // Update the value mapping
        positionMapping[itemId] = size; // Update the position mapping

        uint256 current = size;
        while (current != 0 && valueMapping[heap[current]] > valueMapping[heap[parent(current)]]) {
            swap(current, parent(current));
            current = parent(current);
        }
        size++;
    }

    /// @notice Update the value of an existing item in the heap
    /// @param itemId The item ID whose vote count needs to be updated
    /// @param newValue The new value for the item
    /// @dev This function adjusts the heap to maintain the max-heap property after updating the vote count
    function updateValue(uint256 itemId, uint256 newValue) public onlyOwner {
        uint256 position = positionMapping[itemId];
        uint256 oldValue = valueMapping[itemId];

        // Update the value in the valueMapping
        valueMapping[itemId] = newValue;

        // Decide whether to perform upwards or downwards heapify
        if (newValue > oldValue) {
            // Upwards heapify
            while (position != 0 && valueMapping[heap[position]] > valueMapping[heap[parent(position)]]) {
                swap(position, parent(position));
                position = parent(position);
            }
        } else if (newValue < oldValue) maxHeapify(position); // Downwards heapify
    }

    /// @notice Extract the maximum element from the heap
    /// @dev The function will revert if the heap is empty
    /// @return The maximum element from the heap
    function extractMax() external onlyOwner returns (uint256, uint256) {
        require(size > 0, "Heap is empty");

        uint256 popped = heap[0];
        heap[0] = heap[--size];
        maxHeapify(0);

        return (popped, valueMapping[popped]);
    }

    /// @notice Get the maximum element from the heap
    /// @dev The function will revert if the heap is empty
    /// @return The maximum element from the heap
    function getMax() public view returns (uint256, uint256) {
        require(size > 0, "Heap is empty");
        return (heap[0], valueMapping[heap[0]]);
    }

    ///                                                          ///
    ///                     MAX HEAP UPGRADE                     ///
    ///                                                          ///

    /// @notice Ensures the caller is authorized to upgrade the contract and that the new implementation is valid
    /// @dev This function is called in `upgradeTo` & `upgradeToAndCall`
    /// @param _newImpl The new implementation address
    function _authorizeUpgrade(address _newImpl) internal view override onlyOwner {
        // Ensure the new implementation is a registered upgrade
        if (!manager.isRegisteredUpgrade(_getImplementation(), _newImpl)) revert INVALID_UPGRADE(_newImpl);
    }
}
