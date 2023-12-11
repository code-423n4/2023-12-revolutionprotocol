// SPDX-License-Identifier: BSD-3-Clause

pragma solidity 0.8.22;

interface IDAOExecutor {
    function delay() external view returns (uint256);

    function GRACE_PERIOD() external view returns (uint256);

    function acceptAdmin() external;

    function queuedTransactions(bytes32 hash) external view returns (bool);

    function queueTransaction(
        address target,
        uint256 value,
        string calldata signature,
        bytes calldata data,
        uint256 eta
    ) external returns (bytes32);

    function cancelTransaction(
        address target,
        uint256 value,
        string calldata signature,
        bytes calldata data,
        uint256 eta
    ) external;

    function executeTransaction(
        address target,
        uint256 value,
        string calldata signature,
        bytes calldata data,
        uint256 eta
    ) external payable returns (bytes memory);

    /// @notice Initializes an instance of a DAO's treasury
    /// @param admin The DAO's address
    /// @param timelockDelay The time delay to execute a queued transaction
    function initialize(address admin, uint256 timelockDelay) external;
}
