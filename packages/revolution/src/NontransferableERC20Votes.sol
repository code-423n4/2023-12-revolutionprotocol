// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.8.0) (token/ERC20/ERC20.sol)

pragma solidity ^0.8.22;

/**
 * @dev Extension of ERC-20 to support Compound-like voting and delegation. This version is more generic than Compound's,
 * and supports token supply up to 2^208^ - 1, while COMP is limited to 2^96^ - 1. The token is also nontransferable.
 *
 * NOTE: This contract does not provide interface compatibility with Compound's COMP token.
 *
 * This extension keeps a history (checkpoints) of each account's vote power. Vote power can be delegated either
 * by calling the {delegate} function directly, or by providing a signature to be used with {delegateBySig}. Voting
 * power can be queried through the public accessors {getVotes} and {getPastVotes}.
 *
 * By default, token balance does not account for voting power. This makes transfers cheaper. The downside is that it
 * requires users to delegate to themselves in order to activate checkpoints and have their voting power tracked.
 */

import { Ownable2StepUpgradeable } from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import { PausableUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import { Initializable } from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

import { ERC20VotesUpgradeable } from "./base/erc20/ERC20VotesUpgradeable.sol";
import { EIP712Upgradeable } from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";

import { IRevolutionBuilder } from "./interfaces/IRevolutionBuilder.sol";

contract NontransferableERC20Votes is Initializable, ERC20VotesUpgradeable, Ownable2StepUpgradeable {
    error TRANSFER_NOT_ALLOWED();

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

    function __NontransferableERC20Votes_init(
        address _initialOwner,
        string calldata _name,
        string calldata _symbol
    ) internal onlyInitializing {
        __Ownable_init(_initialOwner);
        __ERC20_init(_name, _symbol);
        __EIP712_init(_name, "1");
    }

    /// @notice Initializes a DAO's ERC-20 governance token contract
    /// @param _initialOwner The address of the initial owner
    /// @param _erc20TokenParams The params of the token
    function initialize(
        address _initialOwner,
        IRevolutionBuilder.ERC20TokenParams calldata _erc20TokenParams
    ) external initializer {
        require(msg.sender == address(manager), "Only manager can initialize");

        __NontransferableERC20Votes_init(_initialOwner, _erc20TokenParams.name, _erc20TokenParams.symbol);
    }

    /**
     * @dev Returns the number of decimals used to get its user representation.
     * For example, if `decimals` equals `2`, a balance of `505` tokens should
     * be displayed to a user as `5.05` (`505 / 10 ** 2`).
     *
     * Tokens usually opt for a value of 18, imitating the relationship between
     * Ether and Wei. This is the default value returned by this function, unless
     * it's overridden.
     *
     * NOTE: This information is only used for _display_ purposes: it in
     * no way affects any of the arithmetic of the contract, including
     * {IERC20-balanceOf} and {IERC20-transfer}.
     */
    function decimals() public view virtual override returns (uint8) {
        return 18;
    }

    /**
     * @dev Not allowed
     */
    function transfer(address, uint256) public virtual override returns (bool) {
        revert TRANSFER_NOT_ALLOWED();
    }

    /**
     * @dev Not allowed
     */
    function _transfer(address from, address to, uint256 value) internal override {
        revert TRANSFER_NOT_ALLOWED();
    }

    /**
     * @dev Not allowed
     */
    function transferFrom(address, address, uint256) public virtual override returns (bool) {
        revert TRANSFER_NOT_ALLOWED();
    }

    /**
     * @dev Not allowed
     */
    function approve(address, uint256) public virtual override returns (bool) {
        revert TRANSFER_NOT_ALLOWED();
    }

    /**
     * @dev Creates a `value` amount of tokens and assigns them to `account`, by transferring it from address(0).
     * Relies on the `_update` mechanism
     *
     * Emits a {Transfer} event with `from` set to the zero address.
     *
     * NOTE: This function is not virtual, {_update} should be overridden instead.
     */
    function _mint(address account, uint256 value) internal override {
        if (account == address(0)) {
            revert ERC20InvalidReceiver(address(0));
        }
        _update(address(0), account, value);
    }

    function mint(address account, uint256 amount) public onlyOwner {
        _mint(account, amount);
    }

    /**
     * @dev Not allowed
     */
    function _approve(address owner, address spender, uint256 value) internal override {
        revert TRANSFER_NOT_ALLOWED();
    }

    /**
     * @dev Not allowed
     */
    function _approve(address owner, address spender, uint256 value, bool emitEvent) internal virtual override {
        revert TRANSFER_NOT_ALLOWED();
    }

    /**
     * @dev Not allowed
     */
    function _spendAllowance(address owner, address spender, uint256 value) internal virtual override {
        revert TRANSFER_NOT_ALLOWED();
    }
}
