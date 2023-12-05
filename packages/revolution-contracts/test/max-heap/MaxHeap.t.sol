// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import { Test } from "forge-std/Test.sol";
import { MaxHeap } from "../../src/MaxHeap.sol";

/// @title MaxHeapTestSuite
/// @dev The test suite for the MaxHeap contract
contract MaxHeapTestSuite is Test {
    MaxHeapTest public maxHeap;

    /// @dev Sets up a new MaxHeap instance before each test
    function setUp() public {
        maxHeap = new MaxHeapTest(address(this));
    }

    /// @dev Tests that only the owner can call updateValue
    function testUpdateValueOnlyOwner() public {
        maxHeap.insert(1, 10); // Setup a state with an element

        address nonOwner = address(2);
        vm.prank(nonOwner);
        bool hasErrored = false;
        try maxHeap.updateValue(1, 20) {
            fail("updateValue should be callable only by the owner");
        } catch {
            hasErrored = true;
        }
        assertTrue(hasErrored, "updateValue should have errored");

        vm.prank(address(this));
        maxHeap.updateValue(1, 20); // No error expected
    }

    /// @dev Tests that only the owner can call insert
    function testInsertOnlyOwner() public {
        address nonOwner = address(3);
        vm.prank(nonOwner);
        bool hasErrored = false;
        try maxHeap.insert(2, 15) {
            fail("insert should be callable only by the owner");
        } catch {
            hasErrored = true;
        }
        assertTrue(hasErrored, "insert should have errored");

        vm.prank(address(this));
        maxHeap.insert(2, 15); // No error expected
    }

    /// @dev Tests that only the owner can call extractMax
    function testExtractMaxOnlyOwner() public {
        // Insert an element to ensure the heap is not empty
        maxHeap.insert(1, 10);

        // Try to call extractMax as a non-owner and expect it to fail
        address nonOwner = address(2); // assume this address is not the owner
        vm.prank(nonOwner); // this sets the next call to be from the address `nonOwner`
        bool hasErrored = false;
        try maxHeap.extractMax() {
            fail("extractMax should only be callable by the owner");
        } catch {
            hasErrored = true;
        }

        assertTrue(hasErrored, "extractMax should have errored");

        // Call extractMax as the owner and expect it to succeed
        vm.prank(address(this)); // set the owner to be the caller for the next transaction
        maxHeap.extractMax(); // this should succeed without reverting
    }

    /// @dev Tests the insert and getMax functions
    function testInsert() public {
        // Insert values into the max heap
        maxHeap.insert(1, 5);
        maxHeap.insert(2, 7);
        maxHeap.insert(3, 3);

        // Validate the max value
        (uint256 maxItemId, uint256 maxValue) = maxHeap.getMax();
        assertEq(maxValue, 7, "Max value should be 7");
        assertEq(maxItemId, 2, "Max piece ID should be 2");
    }

    /// @dev Tests the extractMax function and validates the new max value
    function testRemoveMax() public {
        // Insert and then remove max
        maxHeap.insert(1, 5);
        maxHeap.insert(2, 7);
        maxHeap.insert(3, 3);
        maxHeap.extractMax();

        // Validate the new max value
        (uint256 maxItemId, uint256 maxValue) = maxHeap.getMax();
        assertEq(maxValue, 5, "New max value should be 5");
        assertEq(maxItemId, 1, "New max piece ID should be 1");
    }

    /// @dev Tests the maxHeapify function to ensure it corrects the heap property
    function testHeapify() public {
        // Insert values and manually violate the heap property
        maxHeap.insert(1, 5);
        maxHeap.insert(2, 7);
        maxHeap.insert(3, 15);
        maxHeap.insert(4, 3);
        //set max to [10,2]
        maxHeap._set(0, 10, 2); // Assume a '_set' function for testing

        // Run heapify from the root
        maxHeap.maxHeapify(0);

        // Validate the max value
        (uint256 maxItemId, uint256 correctedMaxValue) = maxHeap.getMax();
        assertEq(correctedMaxValue, 7, "Max value should be 7");
        assertEq(maxItemId, 2, "Max piece ID should be 2");
    }

    /// @dev Tests inserting duplicate values into the heap
    function testInsertDuplicateValues() public {
        maxHeap.insert(1, 5);
        maxHeap.insert(2, 5);
        maxHeap.insert(3, 5);
        (uint256 maxItemId, uint256 maxValue) = maxHeap.getMax();
        assertEq(maxValue, 5, "Max value should still be 5");
        assertEq(maxItemId, 1, "Max piece ID should be 1");
        assertEq(maxHeap.size(), 3, "Size should be 3");
    }

    /// @dev Tests that the heap is empty after all elements are removed
    function testHeapEmptyAfterAllRemoved() public {
        maxHeap.insert(1, 5);
        maxHeap.insert(2, 7);
        maxHeap.extractMax();
        maxHeap.extractMax();
        assertEq(maxHeap.size(), 0, "Heap should be empty");
    }

    /// @dev Tests that the heap maintains its properties after multiple insertions and removals
    function testHeapProperty() public {
        uint256[] memory values = new uint256[](6);
        values[0] = 4;
        values[1] = 7;
        values[2] = 15;
        values[3] = 9;
        values[4] = 10;
        values[5] = 20;
        for (uint256 i = 0; i < values.length; i++) {
            maxHeap.insert(i, values[i]);
        }

        uint256 lastVal = type(uint256).max; // Start with the maximum uint256 value
        while (maxHeap.size() > 0) {
            (, uint256 voteCount) = maxHeap.extractMax();
            assertTrue(voteCount <= lastVal, "Heap property violated");
            lastVal = voteCount;
        }
    }

    /// @dev Tests the maxHeapify function on a non-root node
    function testHeapifyOnNonRoot() public {
        maxHeap.insert(1, 10);
        maxHeap.insert(2, 15);
        maxHeap.insert(3, 5);
        maxHeap.insert(4, 12);
        maxHeap._set(1, 200, 4); // Assume a '_set' function for testing
        maxHeap.maxHeapify(1);
        uint256 itemId = maxHeap.heap(1);
        uint256 val = maxHeap.valueMapping(itemId);
        assertEq(val, 10, "Value should be 10 after heapify");
        assertEq(itemId, 1, "Item ID should be 1 after heapify");
    }

    /// @dev Tests that the heap does not allow removal of max element when it's empty
    function testCannotRemoveMaxWhenEmpty() public {
        // Try to remove max and expect to fail
        try maxHeap.extractMax() {
            fail("Should not be able to remove max when heap is empty");
        } catch Error(string memory reason) {
            assertEq(reason, "Heap is empty");
        }
    }
}

contract MaxHeapTest is MaxHeap {
    constructor(address _owner) MaxHeap(address(_owner)) {}

    /// @notice Function to set a value in the heap (ONLY FOR TESTING)
    /// @param pos The position to set
    /// @param value The value to set at the given position
    function _set(uint256 pos, uint256 itemId, uint256 value) public {
        heap[pos] = itemId;
        valueMapping[itemId] = value;
    }
}
