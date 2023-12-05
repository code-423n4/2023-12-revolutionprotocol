// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import { Test } from "forge-std/Test.sol";
import { MaxHeapTest } from "./MaxHeap.t.sol"; // Assuming MaxHeap is in a separate file

contract MaxHeapUpdateTestSuite is Test {
    MaxHeapTest public heap;

    constructor() {
        heap = new MaxHeapTest(address(this)); // Create a heap with a max size of 10 for testing
    }

    function testInitialInsertAndMax() public {
        heap.insert(1, 5);
        heap.insert(2, 10);
        heap.insert(3, 15);

        (uint256 itemId, uint256 value) = heap.getMax();
        assertEq(itemId, 3, "Item ID should be 3 after initial insert");
        assertEq(value, 15, "Value should be 15 after initial insert");
    }

    function testUpdateValueIncrease() public {
        heap.insert(1, 10);
        heap.insert(2, 5);
        heap.insert(3, 3);

        heap.updateValue(1, 20); // Update the value of itemId 1 to 20, which should make it the max

        (uint256 itemId, uint256 value) = heap.getMax();
        assertEq(itemId, 1, "Item ID should be 1 after updating to a higher value");
        assertEq(value, 20, "Value should be 20 after updating to a higher value");
    }

    function testUpdateValueDecrease() public {
        heap.insert(1, 20);
        heap.insert(2, 10);
        heap.insert(3, 5);

        heap.updateValue(1, 7); // Update the value of itemId 1 to 7, which should no longer make it the max

        (uint256 itemId, uint256 value) = heap.getMax();
        assertEq(itemId, 2, "Item ID should be 2 after updating to a lower value");
        assertEq(value, 10, "Value should be 10 after updating to a lower value");
    }

    function testUpdateValueWithHeapify() public {
        heap.insert(1, 50);
        heap.insert(2, 40);
        heap.insert(3, 35);
        heap.insert(4, 20);
        heap.insert(5, 10);

        heap.updateValue(5, 60); // Update the value of itemId 5 to 60, making it the new max

        (uint256 itemId, uint256 value) = heap.getMax();
        assertEq(itemId, 5, "Item ID should be 5 after heapify");
        assertEq(value, 60, "Value should be 60 after heapify");
    }
}
