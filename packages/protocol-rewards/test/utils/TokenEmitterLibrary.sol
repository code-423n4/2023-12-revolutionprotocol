// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";
import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import { TokenEmitterRewards } from "../../src/abstract/TokenEmitter/TokenEmitterRewards.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { Votes } from "@openzeppelin/contracts/governance/utils/Votes.sol";
import { Checkpoints } from "@openzeppelin/contracts/utils/structs/Checkpoints.sol";
import { Context } from "@openzeppelin/contracts/utils/Context.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { IERC20Metadata } from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";

/**
 * @dev Standard ERC-20 Errors
 * Interface of the https://eips.ethereum.org/EIPS/eip-6093[ERC-6093] custom errors for ERC-20 tokens.
 */
interface IERC20Errors {
    /**
     * @dev Indicates an error related to the current `balance` of a `sender`. Used in transfers.
     * @param sender Address whose tokens are being transferred.
     * @param balance Current balance for the interacting account.
     * @param needed Minimum amount required to perform a transfer.
     */
    error ERC20InsufficientBalance(address sender, uint256 balance, uint256 needed);

    /**
     * @dev Indicates a failure with the token `sender`. Used in transfers.
     * @param sender Address whose tokens are being transferred.
     */
    error ERC20InvalidSender(address sender);

    /**
     * @dev Indicates a failure with the token `receiver`. Used in transfers.
     * @param receiver Address to which tokens are being transferred.
     */
    error ERC20InvalidReceiver(address receiver);

    /**
     * @dev Indicates a failure with the `spender`’s `allowance`. Used in transfers.
     * @param spender Address that may be allowed to operate on tokens without being their owner.
     * @param allowance Amount of tokens a `spender` is allowed to operate with.
     * @param needed Minimum amount required to perform a transfer.
     */
    error ERC20InsufficientAllowance(address spender, uint256 allowance, uint256 needed);

    /**
     * @dev Indicates a failure with the `approver` of a token to be approved. Used in approvals.
     * @param approver Address initiating an approval operation.
     */
    error ERC20InvalidApprover(address approver);

    /**
     * @dev Indicates a failure with the `spender` to be approved. Used in approvals.
     * @param spender Address that may be allowed to operate on tokens without being their owner.
     */
    error ERC20InvalidSpender(address spender);
}

/**
 * @dev Standard ERC-721 Errors
 * Interface of the https://eips.ethereum.org/EIPS/eip-6093[ERC-6093] custom errors for ERC-721 tokens.
 */
interface IERC721Errors {
    /**
     * @dev Indicates that an address can't be an owner. For example, `address(0)` is a forbidden owner in ERC-20.
     * Used in balance queries.
     * @param owner Address of the current owner of a token.
     */
    error ERC721InvalidOwner(address owner);

    /**
     * @dev Indicates a `tokenId` whose `owner` is the zero address.
     * @param tokenId Identifier number of a token.
     */
    error ERC721NonexistentToken(uint256 tokenId);

    /**
     * @dev Indicates an error related to the ownership over a particular token. Used in transfers.
     * @param sender Address whose tokens are being transferred.
     * @param tokenId Identifier number of a token.
     * @param owner Address of the current owner of a token.
     */
    error ERC721IncorrectOwner(address sender, uint256 tokenId, address owner);

    /**
     * @dev Indicates a failure with the token `sender`. Used in transfers.
     * @param sender Address whose tokens are being transferred.
     */
    error ERC721InvalidSender(address sender);

    /**
     * @dev Indicates a failure with the token `receiver`. Used in transfers.
     * @param receiver Address to which tokens are being transferred.
     */
    error ERC721InvalidReceiver(address receiver);

    /**
     * @dev Indicates a failure with the `operator`’s approval. Used in transfers.
     * @param operator Address that may be allowed to operate on tokens without being their owner.
     * @param tokenId Identifier number of a token.
     */
    error ERC721InsufficientApproval(address operator, uint256 tokenId);

    /**
     * @dev Indicates a failure with the `approver` of a token to be approved. Used in approvals.
     * @param approver Address initiating an approval operation.
     */
    error ERC721InvalidApprover(address approver);

    /**
     * @dev Indicates a failure with the `operator` to be approved. Used in approvals.
     * @param operator Address that may be allowed to operate on tokens without being their owner.
     */
    error ERC721InvalidOperator(address operator);
}

/**
 * @dev Standard ERC-1155 Errors
 * Interface of the https://eips.ethereum.org/EIPS/eip-6093[ERC-6093] custom errors for ERC-1155 tokens.
 */
interface IERC1155Errors {
    /**
     * @dev Indicates an error related to the current `balance` of a `sender`. Used in transfers.
     * @param sender Address whose tokens are being transferred.
     * @param balance Current balance for the interacting account.
     * @param needed Minimum amount required to perform a transfer.
     * @param tokenId Identifier number of a token.
     */
    error ERC1155InsufficientBalance(address sender, uint256 balance, uint256 needed, uint256 tokenId);

    /**
     * @dev Indicates a failure with the token `sender`. Used in transfers.
     * @param sender Address whose tokens are being transferred.
     */
    error ERC1155InvalidSender(address sender);

    /**
     * @dev Indicates a failure with the token `receiver`. Used in transfers.
     * @param receiver Address to which tokens are being transferred.
     */
    error ERC1155InvalidReceiver(address receiver);

    /**
     * @dev Indicates a failure with the `operator`’s approval. Used in transfers.
     * @param operator Address that may be allowed to operate on tokens without being their owner.
     * @param owner Address of the current owner of a token.
     */
    error ERC1155MissingApprovalForAll(address operator, address owner);

    /**
     * @dev Indicates a failure with the `approver` of a token to be approved. Used in approvals.
     * @param approver Address initiating an approval operation.
     */
    error ERC1155InvalidApprover(address approver);

    /**
     * @dev Indicates a failure with the `operator` to be approved. Used in approvals.
     * @param operator Address that may be allowed to operate on tokens without being their owner.
     */
    error ERC1155InvalidOperator(address operator);

    /**
     * @dev Indicates an array length mismatch between ids and values in a safeBatchTransferFrom operation.
     * Used in batch transfers.
     * @param idsLength Length of the array of token identifiers
     * @param valuesLength Length of the array of token amounts
     */
    error ERC1155InvalidArrayLength(uint256 idsLength, uint256 valuesLength);
}

/**
 * @dev Implementation of the {IERC20} interface.
 *
 * This implementation is agnostic to the way tokens are created. This means
 * that a supply mechanism has to be added in a derived contract using {_mint}.
 *
 * TIP: For a detailed writeup see our guide
 * https://forum.openzeppelin.com/t/how-to-implement-erc20-supply-mechanisms/226[How
 * to implement supply mechanisms].
 *
 * The default value of {decimals} is 18. To change this, you should override
 * this function so it returns a different value.
 *
 * We have followed general OpenZeppelin Contracts guidelines: functions revert
 * instead returning `false` on failure. This behavior is nonetheless
 * conventional and does not conflict with the expectations of ERC-20
 * applications.
 *
 * Additionally, an {Approval} event is emitted on calls to {transferFrom}.
 * This allows applications to reconstruct the allowance for all accounts just
 * by listening to said events. Other implementations of the ERC may not emit
 * these events, as it isn't required by the specification.
 */
abstract contract ERC20 is Context, IERC20, IERC20Metadata, IERC20Errors {
    mapping(address account => uint256) private _balances;

    mapping(address account => mapping(address spender => uint256)) private _allowances;

    uint256 private _totalSupply;

    string private _name;
    string private _symbol;

    /**
     * @dev Sets the values for {name} and {symbol}.
     *
     * All two of these values are immutable: they can only be set once during
     * construction.
     */
    constructor(string memory name_, string memory symbol_) {
        _name = name_;
        _symbol = symbol_;
    }

    /**
     * @dev Returns the name of the token.
     */
    function name() public view virtual returns (string memory) {
        return _name;
    }

    /**
     * @dev Returns the symbol of the token, usually a shorter version of the
     * name.
     */
    function symbol() public view virtual returns (string memory) {
        return _symbol;
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
    function decimals() public view virtual returns (uint8) {
        return 18;
    }

    /**
     * @dev See {IERC20-totalSupply}.
     */
    function totalSupply() public view virtual returns (uint256) {
        return _totalSupply;
    }

    /**
     * @dev See {IERC20-balanceOf}.
     */
    function balanceOf(address account) public view virtual returns (uint256) {
        return _balances[account];
    }

    /**
     * @dev See {IERC20-transfer}.
     *
     * Requirements:
     *
     * - `to` cannot be the zero address.
     * - the caller must have a balance of at least `value`.
     */
    function transfer(address to, uint256 value) public virtual returns (bool) {
        address owner = _msgSender();
        _transfer(owner, to, value);
        return true;
    }

    /**
     * @dev See {IERC20-allowance}.
     */
    function allowance(address owner, address spender) public view virtual returns (uint256) {
        return _allowances[owner][spender];
    }

    /**
     * @dev See {IERC20-approve}.
     *
     * NOTE: If `value` is the maximum `uint256`, the allowance is not updated on
     * `transferFrom`. This is semantically equivalent to an infinite approval.
     *
     * Requirements:
     *
     * - `spender` cannot be the zero address.
     */
    function approve(address spender, uint256 value) public virtual returns (bool) {
        address owner = _msgSender();
        _approve(owner, spender, value);
        return true;
    }

    /**
     * @dev See {IERC20-transferFrom}.
     *
     * Emits an {Approval} event indicating the updated allowance. This is not
     * required by the ERC. See the note at the beginning of {ERC20}.
     *
     * NOTE: Does not update the allowance if the current allowance
     * is the maximum `uint256`.
     *
     * Requirements:
     *
     * - `from` and `to` cannot be the zero address.
     * - `from` must have a balance of at least `value`.
     * - the caller must have allowance for ``from``'s tokens of at least
     * `value`.
     */
    function transferFrom(address from, address to, uint256 value) public virtual returns (bool) {
        address spender = _msgSender();
        _spendAllowance(from, spender, value);
        _transfer(from, to, value);
        return true;
    }

    /**
     * @dev Moves a `value` amount of tokens from `from` to `to`.
     *
     * This internal function is equivalent to {transfer}, and can be used to
     * e.g. implement automatic token fees, slashing mechanisms, etc.
     *
     * Emits a {Transfer} event.
     *
     * NOTE: This function is not virtual, {_update} should be overridden instead.
     */
    function _transfer(address from, address to, uint256 value) internal virtual {
        if (from == address(0)) {
            revert ERC20InvalidSender(address(0));
        }
        if (to == address(0)) {
            revert ERC20InvalidReceiver(address(0));
        }
        _update(from, to, value);
    }

    /**
     * @dev Transfers a `value` amount of tokens from `from` to `to`, or alternatively mints (or burns) if `from`
     * (or `to`) is the zero address. All customizations to transfers, mints, and burns should be done by overriding
     * this function.
     *
     * Emits a {Transfer} event.
     */
    function _update(address from, address to, uint256 value) internal virtual {
        if (from == address(0)) {
            // Overflow check required: The rest of the code assumes that totalSupply never overflows
            _totalSupply += value;
        } else {
            uint256 fromBalance = _balances[from];
            if (fromBalance < value) {
                revert ERC20InsufficientBalance(from, fromBalance, value);
            }
            unchecked {
                // Overflow not possible: value <= fromBalance <= totalSupply.
                _balances[from] = fromBalance - value;
            }
        }

        if (to == address(0)) {
            unchecked {
                // Overflow not possible: value <= totalSupply or value <= fromBalance <= totalSupply.
                _totalSupply -= value;
            }
        } else {
            unchecked {
                // Overflow not possible: balance + value is at most totalSupply, which we know fits into a uint256.
                _balances[to] += value;
            }
        }

        emit Transfer(from, to, value);
    }

    /**
     * @dev Creates a `value` amount of tokens and assigns them to `account`, by transferring it from address(0).
     * Relies on the `_update` mechanism
     *
     * Emits a {Transfer} event with `from` set to the zero address.
     *
     * NOTE: This function is not virtual, {_update} should be overridden instead.
     */
    function _mint(address account, uint256 value) internal virtual {
        if (account == address(0)) {
            revert ERC20InvalidReceiver(address(0));
        }
        _update(address(0), account, value);
    }

    /**
     * @dev Destroys a `value` amount of tokens from `account`, lowering the total supply.
     * Relies on the `_update` mechanism.
     *
     * Emits a {Transfer} event with `to` set to the zero address.
     *
     * NOTE: This function is not virtual, {_update} should be overridden instead
     */
    function _burn(address account, uint256 value) internal {
        if (account == address(0)) {
            revert ERC20InvalidSender(address(0));
        }
        _update(account, address(0), value);
    }

    /**
     * @dev Sets `value` as the allowance of `spender` over the `owner` s tokens.
     *
     * This internal function is equivalent to `approve`, and can be used to
     * e.g. set automatic allowances for certain subsystems, etc.
     *
     * Emits an {Approval} event.
     *
     * Requirements:
     *
     * - `owner` cannot be the zero address.
     * - `spender` cannot be the zero address.
     *
     * Overrides to this logic should be done to the variant with an additional `bool emitEvent` argument.
     */
    function _approve(address owner, address spender, uint256 value) internal virtual {
        _approve(owner, spender, value, true);
    }

    /**
     * @dev Variant of {_approve} with an optional flag to enable or disable the {Approval} event.
     *
     * By default (when calling {_approve}) the flag is set to true. On the other hand, approval changes made by
     * `_spendAllowance` during the `transferFrom` operation set the flag to false. This saves gas by not emitting any
     * `Approval` event during `transferFrom` operations.
     *
     * Anyone who wishes to continue emitting `Approval` events on the`transferFrom` operation can force the flag to
     * true using the following override:
     * ```
     * function _approve(address owner, address spender, uint256 value, bool) internal virtual override {
     *     super._approve(owner, spender, value, true);
     * }
     * ```
     *
     * Requirements are the same as {_approve}.
     */
    function _approve(address owner, address spender, uint256 value, bool emitEvent) internal virtual {
        if (owner == address(0)) {
            revert ERC20InvalidApprover(address(0));
        }
        if (spender == address(0)) {
            revert ERC20InvalidSpender(address(0));
        }
        _allowances[owner][spender] = value;
        if (emitEvent) {
            emit Approval(owner, spender, value);
        }
    }

    /**
     * @dev Updates `owner` s allowance for `spender` based on spent `value`.
     *
     * Does not update the allowance value in case of infinite allowance.
     * Revert if not enough allowance is available.
     *
     * Does not emit an {Approval} event.
     */
    function _spendAllowance(address owner, address spender, uint256 value) internal virtual {
        uint256 currentAllowance = allowance(owner, spender);
        if (currentAllowance != type(uint256).max) {
            if (currentAllowance < value) {
                revert ERC20InsufficientAllowance(spender, currentAllowance, value);
            }
            unchecked {
                _approve(owner, spender, currentAllowance - value, false);
            }
        }
    }
}

/**
 * @dev Extension of ERC-20 to support Compound-like voting and delegation. This version is more generic than Compound's,
 * and supports token supply up to 2^208^ - 1, while COMP is limited to 2^96^ - 1.
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
abstract contract ERC20Votes is ERC20, Votes {
    /**
     * @dev Total supply cap has been exceeded, introducing a risk of votes overflowing.
     */
    error ERC20ExceededSafeSupply(uint256 increasedSupply, uint256 cap);

    /**
     * @dev Maximum token supply. Defaults to `type(uint208).max` (2^208^ - 1).
     *
     * This maximum is enforced in {_update}. It limits the total supply of the token, which is otherwise a uint256,
     * so that checkpoints can be stored in the Trace208 structure used by {{Votes}}. Increasing this value will not
     * remove the underlying limitation, and will cause {_update} to fail because of a math overflow in
     * {_transferVotingUnits}. An override could be used to further restrict the total supply (to a lower value) if
     * additional logic requires it. When resolving override conflicts on this function, the minimum should be
     * returned.
     */
    function _maxSupply() internal view virtual returns (uint256) {
        return type(uint208).max;
    }

    /**
     * @dev Move voting power when tokens are transferred.
     *
     * Emits a {IVotes-DelegateVotesChanged} event.
     */
    function _update(address from, address to, uint256 value) internal virtual override {
        super._update(from, to, value);
        if (from == address(0)) {
            uint256 supply = totalSupply();
            uint256 cap = _maxSupply();
            if (supply > cap) {
                revert ERC20ExceededSafeSupply(supply, cap);
            }
        }
        _transferVotingUnits(from, to, value);
    }

    /**
     * @dev Returns the voting units of an `account`.
     *
     * WARNING: Overriding this function may compromise the internal vote accounting.
     * `ERC20Votes` assumes tokens map to voting units 1:1 and this is not easy to change.
     */
    function _getVotingUnits(address account) internal view virtual override returns (uint256) {
        return balanceOf(account);
    }

    /**
     * @dev Get number of checkpoints for `account`.
     */
    function numCheckpoints(address account) public view virtual returns (uint32) {
        return _numCheckpoints(account);
    }

    /**
     * @dev Get the `pos`-th checkpoint for `account`.
     */
    function checkpoints(address account, uint32 pos) public view virtual returns (Checkpoints.Checkpoint208 memory) {
        return _checkpoints(account, pos);
    }
}

/// @notice Signed 18 decimal fixed point (wad) arithmetic library.
/// @author Solmate (https://github.com/transmissions11/solmate/blob/main/src/utils/SignedWadMath.sol)
/// @author Modified from Remco Bloemen (https://xn--2-umb.com/22/exp-ln/index.html)

/// @dev Will not revert on overflow, only use where overflow is not possible.
function toWadUnsafe(uint256 x) pure returns (int256 r) {
    /// @solidity memory-safe-assembly
    assembly {
        // Multiply x by 1e18.
        r := mul(x, 1000000000000000000)
    }
}

/// @dev Takes an integer amount of seconds and converts it to a wad amount of days.
/// @dev Will not revert on overflow, only use where overflow is not possible.
/// @dev Not meant for negative second amounts, it assumes x is positive.
function toDaysWadUnsafe(uint256 x) pure returns (int256 r) {
    /// @solidity memory-safe-assembly
    assembly {
        // Multiply x by 1e18 and then divide it by 86400.
        r := div(mul(x, 1000000000000000000), 86400)
    }
}

/// @dev Takes a wad amount of days and converts it to an integer amount of seconds.
/// @dev Will not revert on overflow, only use where overflow is not possible.
/// @dev Not meant for negative day amounts, it assumes x is positive.
function fromDaysWadUnsafe(int256 x) pure returns (uint256 r) {
    /// @solidity memory-safe-assembly
    assembly {
        // Multiply x by 86400 and then divide it by 1e18.
        r := div(mul(x, 86400), 1000000000000000000)
    }
}

/// @dev Will not revert on overflow, only use where overflow is not possible.
function unsafeWadMul(int256 x, int256 y) pure returns (int256 r) {
    /// @solidity memory-safe-assembly
    assembly {
        // Multiply x by y and divide by 1e18.
        r := sdiv(mul(x, y), 1000000000000000000)
    }
}

/// @dev Will return 0 instead of reverting if y is zero and will
/// not revert on overflow, only use where overflow is not possible.
function unsafeWadDiv(int256 x, int256 y) pure returns (int256 r) {
    /// @solidity memory-safe-assembly
    assembly {
        // Multiply x by 1e18 and divide it by y.
        r := sdiv(mul(x, 1000000000000000000), y)
    }
}

function wadMul(int256 x, int256 y) pure returns (int256 r) {
    /// @solidity memory-safe-assembly
    assembly {
        // Store x * y in r for now.
        r := mul(x, y)

        // Combined overflow check (`x == 0 || (x * y) / x == y`) and edge case check
        // where x == -1 and y == type(int256).min, for y == -1 and x == min int256,
        // the second overflow check will catch this.
        // See: https://secure-contracts.com/learn_evm/arithmetic-checks.html#arithmetic-checks-for-int256-multiplication
        // Combining into 1 expression saves gas as resulting bytecode will only have 1 `JUMPI`
        // rather than 2.
        if iszero(
            and(
                or(iszero(x), eq(sdiv(r, x), y)),
                or(lt(x, not(0)), sgt(y, 0x8000000000000000000000000000000000000000000000000000000000000000))
            )
        ) {
            revert(0, 0)
        }

        // Scale the result down by 1e18.
        r := sdiv(r, 1000000000000000000)
    }
}

function wadDiv(int256 x, int256 y) pure returns (int256 r) {
    /// @solidity memory-safe-assembly
    assembly {
        // Store x * 1e18 in r for now.
        r := mul(x, 1000000000000000000)

        // Equivalent to require(y != 0 && ((x * 1e18) / 1e18 == x))
        if iszero(and(iszero(iszero(y)), eq(sdiv(r, 1000000000000000000), x))) {
            revert(0, 0)
        }

        // Divide r by y.
        r := sdiv(r, y)
    }
}

/// @dev Will not work with negative bases, only use when x is positive.
function wadPow(int256 x, int256 y) pure returns (int256) {
    // Equivalent to x to the power of y because x ** y = (e ** ln(x)) ** y = e ** (ln(x) * y)
    return wadExp((wadLn(x) * y) / 1e18); // Using ln(x) means x must be greater than 0.
}

function wadExp(int256 x) pure returns (int256 r) {
    unchecked {
        // When the result is < 0.5 we return zero. This happens when
        // x <= floor(log(0.5e18) * 1e18) ~ -42e18
        if (x <= -42139678854452767551) return 0;

        // When the result is > (2**255 - 1) / 1e18 we can not represent it as an
        // int. This happens when x >= floor(log((2**255 - 1) / 1e18) * 1e18) ~ 135.
        if (x >= 135305999368893231589) revert("EXP_OVERFLOW");

        // x is now in the range (-42, 136) * 1e18. Convert to (-42, 136) * 2**96
        // for more intermediate precision and a binary basis. This base conversion
        // is a multiplication by 1e18 / 2**96 = 5**18 / 2**78.
        x = (x << 78) / 5 ** 18;

        // Reduce range of x to (-½ ln 2, ½ ln 2) * 2**96 by factoring out powers
        // of two such that exp(x) = exp(x') * 2**k, where k is an integer.
        // Solving this gives k = round(x / log(2)) and x' = x - k * log(2).
        int256 k = ((x << 96) / 54916777467707473351141471128 + 2 ** 95) >> 96;
        x = x - k * 54916777467707473351141471128;

        // k is in the range [-61, 195].

        // Evaluate using a (6, 7)-term rational approximation.
        // p is made monic, we'll multiply by a scale factor later.
        int256 y = x + 1346386616545796478920950773328;
        y = ((y * x) >> 96) + 57155421227552351082224309758442;
        int256 p = y + x - 94201549194550492254356042504812;
        p = ((p * y) >> 96) + 28719021644029726153956944680412240;
        p = p * x + (4385272521454847904659076985693276 << 96);

        // We leave p in 2**192 basis so we don't need to scale it back up for the division.
        int256 q = x - 2855989394907223263936484059900;
        q = ((q * x) >> 96) + 50020603652535783019961831881945;
        q = ((q * x) >> 96) - 533845033583426703283633433725380;
        q = ((q * x) >> 96) + 3604857256930695427073651918091429;
        q = ((q * x) >> 96) - 14423608567350463180887372962807573;
        q = ((q * x) >> 96) + 26449188498355588339934803723976023;

        /// @solidity memory-safe-assembly
        assembly {
            // Div in assembly because solidity adds a zero check despite the unchecked.
            // The q polynomial won't have zeros in the domain as all its roots are complex.
            // No scaling is necessary because p is already 2**96 too large.
            r := sdiv(p, q)
        }

        // r should be in the range (0.09, 0.25) * 2**96.

        // We now need to multiply r by:
        // * the scale factor s = ~6.031367120.
        // * the 2**k factor from the range reduction.
        // * the 1e18 / 2**96 factor for base conversion.
        // We do this all at once, with an intermediate result in 2**213
        // basis, so the final right shift is always by a positive amount.
        r = int256((uint256(r) * 3822833074963236453042738258902158003155416615667) >> uint256(195 - k));
    }
}

function wadLn(int256 x) pure returns (int256 r) {
    unchecked {
        require(x > 0, "UNDEFINED");

        // We want to convert x from 10**18 fixed point to 2**96 fixed point.
        // We do this by multiplying by 2**96 / 10**18. But since
        // ln(x * C) = ln(x) + ln(C), we can simply do nothing here
        // and add ln(2**96 / 10**18) at the end.

        /// @solidity memory-safe-assembly
        assembly {
            r := shl(7, lt(0xffffffffffffffffffffffffffffffff, x))
            r := or(r, shl(6, lt(0xffffffffffffffff, shr(r, x))))
            r := or(r, shl(5, lt(0xffffffff, shr(r, x))))
            r := or(r, shl(4, lt(0xffff, shr(r, x))))
            r := or(r, shl(3, lt(0xff, shr(r, x))))
            r := or(r, shl(2, lt(0xf, shr(r, x))))
            r := or(r, shl(1, lt(0x3, shr(r, x))))
            r := or(r, lt(0x1, shr(r, x)))
        }

        // Reduce range of x to (1, 2) * 2**96
        // ln(2^k * x) = k * ln(2) + ln(x)
        int256 k = r - 96;
        x <<= uint256(159 - k);
        x = int256(uint256(x) >> 159);

        // Evaluate using a (8, 8)-term rational approximation.
        // p is made monic, we will multiply by a scale factor later.
        int256 p = x + 3273285459638523848632254066296;
        p = ((p * x) >> 96) + 24828157081833163892658089445524;
        p = ((p * x) >> 96) + 43456485725739037958740375743393;
        p = ((p * x) >> 96) - 11111509109440967052023855526967;
        p = ((p * x) >> 96) - 45023709667254063763336534515857;
        p = ((p * x) >> 96) - 14706773417378608786704636184526;
        p = p * x - (795164235651350426258249787498 << 96);

        // We leave p in 2**192 basis so we don't need to scale it back up for the division.
        // q is monic by convention.
        int256 q = x + 5573035233440673466300451813936;
        q = ((q * x) >> 96) + 71694874799317883764090561454958;
        q = ((q * x) >> 96) + 283447036172924575727196451306956;
        q = ((q * x) >> 96) + 401686690394027663651624208769553;
        q = ((q * x) >> 96) + 204048457590392012362485061816622;
        q = ((q * x) >> 96) + 31853899698501571402653359427138;
        q = ((q * x) >> 96) + 909429971244387300277376558375;
        /// @solidity memory-safe-assembly
        assembly {
            // Div in assembly because solidity adds a zero check despite the unchecked.
            // The q polynomial is known not to have zeros in the domain.
            // No scaling required because p is already 2**96 too large.
            r := sdiv(p, q)
        }

        // r is in the range (0, 0.125) * 2**96

        // Finalization, we need to:
        // * multiply by the scale factor s = 5.549…
        // * add ln(2**96 / 10**18)
        // * add k * ln(2)
        // * multiply by 10**18 / 2**96 = 5**18 >> 78

        // mul s * 5e18 * 2**96, base is now 5**18 * 2**192
        r *= 1677202110996718588342820967067443963516166;
        // add ln(2) * k * 5e18 * 2**192
        r += 16597577552685614221487285958193947469193820559219878177908093499208371 * k;
        // add ln(2**96 / 10**18) * 5e18 * 2**192
        r += 600920179829731861736702779321621459595472258049074101567377883020018308;
        // base conversion: mul 2**18 / 2**192
        r >>= 174;
    }
}

/// @dev Will return 0 instead of reverting if y is zero.
function unsafeDiv(int256 x, int256 y) pure returns (int256 r) {
    /// @solidity memory-safe-assembly
    assembly {
        // Divide x by y.
        r := sdiv(x, y)
    }
}

/// @title Continuous Variable Rate Gradual Dutch Auction
/// @author transmissions11 <t11s@paradigm.xyz>
/// @author FrankieIsLost <frankie@paradigm.xyz>
/// @author Dan Robinson <dan@paradigm.xyz>
/// @notice Sell tokens roughly according to an issuance schedule.
contract VRGDAC {
    /*//////////////////////////////////////////////////////////////
                            VRGDA PARAMETERS
    //////////////////////////////////////////////////////////////*/

    int256 public immutable targetPrice;

    int256 public immutable perTimeUnit;

    int256 public immutable decayConstant;

    int256 public immutable priceDecayPercent;

    /// @notice Sets target price and per time unit price decay for the VRGDA.
    /// @param _targetPrice The target price for a token if sold on pace, scaled by 1e18.
    /// @param _priceDecayPercent The percent price decays per unit of time with no sales, scaled by 1e18.
    /// @param _perTimeUnit The number of tokens to target selling in 1 full unit of time, scaled by 1e18.
    constructor(int256 _targetPrice, int256 _priceDecayPercent, int256 _perTimeUnit) {
        targetPrice = _targetPrice;

        perTimeUnit = _perTimeUnit;

        priceDecayPercent = _priceDecayPercent;

        decayConstant = wadLn(1e18 - _priceDecayPercent);

        // The decay constant must be negative for VRGDAs to work.
        require(decayConstant < 0, "NON_NEGATIVE_DECAY_CONSTANT");
    }

    /*//////////////////////////////////////////////////////////////
                              PRICING LOGIC
    //////////////////////////////////////////////////////////////*/

    // y to pay
    // given # of tokens sold and # to buy, returns amount to pay
    function xToY(int256 timeSinceStart, int256 sold, int256 amount) public view virtual returns (int256) {
        unchecked {
            return pIntegral(timeSinceStart, sold + amount) - pIntegral(timeSinceStart, sold);
        }
    }

    // given amount to pay and amount sold so far, returns # of tokens to sell - raw form
    function yToX(int256 timeSinceStart, int256 sold, int256 amount) public view virtual returns (int256) {
        int256 soldDifference = wadMul(perTimeUnit, timeSinceStart) - sold;
        unchecked {
            return
                wadMul(
                    perTimeUnit,
                    wadDiv(
                        wadLn(
                            wadDiv(
                                wadMul(
                                    targetPrice,
                                    wadMul(
                                        perTimeUnit,
                                        wadExp(wadMul(soldDifference, wadDiv(decayConstant, perTimeUnit)))
                                    )
                                ),
                                wadMul(
                                    targetPrice,
                                    wadMul(
                                        perTimeUnit,
                                        wadPow(1e18 - priceDecayPercent, wadDiv(soldDifference, perTimeUnit))
                                    )
                                ) - wadMul(amount, decayConstant)
                            )
                        ),
                        decayConstant
                    )
                );
        }
    }

    // given # of tokens sold, returns integral of price p(x) = p0 * (1 - k)^(x/r)
    function pIntegral(int256 timeSinceStart, int256 sold) internal view returns (int256) {
        return
            wadDiv(
                -wadMul(
                    wadMul(targetPrice, perTimeUnit),
                    wadPow(1e18 - priceDecayPercent, timeSinceStart - unsafeWadDiv(sold, perTimeUnit)) -
                        wadPow(1e18 - priceDecayPercent, timeSinceStart)
                ),
                decayConstant
            );
    }

    // given # of tokens sold, returns price p(x) = p0 * (1 - k)^(t - (x/r)) - (x/r) makes it a linearvrgda issuance
    function p(int256 timeSinceStart, int256 sold) internal view returns (int256) {
        return wadMul(targetPrice, wadPow(1e18 - priceDecayPercent, timeSinceStart - unsafeWadDiv(sold, perTimeUnit)));
    }
}

contract NontransferableERC20Votes is Ownable, ERC20Votes {
    mapping(address account => uint256) private _balances;

    uint256 private _totalSupply;

    /**
     * @dev Sets the values for {name} and {symbol}.
     *
     * All two of these values are immutable: they can only be set once during
     * construction.
     */
    constructor(
        address _initialOwner,
        string memory name_,
        string memory symbol_
    ) Ownable(_initialOwner) ERC20(name_, symbol_) EIP712(name_, "1") {}

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
        return false;
    }

    /**
     * @dev Not allowed
     */
    function _transfer(address from, address to, uint256 value) internal override {
        return;
    }

    /**
     * @dev Not allowed
     */
    function transferFrom(address, address, uint256) public virtual override returns (bool) {
        return false;
    }

    /**
     * @dev Not allowed
     */
    function approve(address, uint256) public virtual override returns (bool) {
        return false;
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
        return;
    }

    /**
     * @dev Not allowed
     */
    function _approve(address owner, address spender, uint256 value, bool emitEvent) internal virtual override {
        return;
    }

    /**
     * @dev Not allowed
     */
    function _spendAllowance(address owner, address spender, uint256 value) internal virtual override {
        return;
    }
}

interface IERC20TokenEmitter {
    struct ProtocolRewardAddresses {
        address builder;
        address purchaseReferral;
        address deployer;
    }

    function buyToken(
        address[] calldata _addresses,
        uint[] calldata _bps,
        ProtocolRewardAddresses calldata protocolRewardsRecipients
    ) external payable returns (uint);

    function totalSupply() external view returns (uint);

    function balanceOf(address _owner) external view returns (uint);

    function setCreatorRateBps(uint256 _creatorRateBps) external;

    function setEntropyRateBps(uint256 _entropyRateBps) external;

    function getTokenQuoteForPayment(uint256 paymentAmount) external returns (int);

    function setCreatorsAddress(address creators) external;

    event CreatorsAddressUpdated(address creators);

    event CreatorRateBpsUpdated(uint256 rateBps);

    event EntropyRateBpsUpdated(uint256 rateBps);

    event PurchaseFinalized(
        address indexed buyer,
        uint256 payment,
        uint256 treasuryAmount,
        uint256 protocolRewardsAmount,
        uint256 buyerTokensEmitted,
        uint256 creatorTokensEmitted,
        uint256 creatorDirectPayment
    );
}

contract ERC20TokenEmitter is VRGDAC, IERC20TokenEmitter, ReentrancyGuard, TokenEmitterRewards, Ownable {
    // treasury address to pay funds to
    address public immutable treasury;

    // The token that is being emitted.
    NontransferableERC20Votes public immutable token;

    // solhint-disable-next-line not-rely-on-time
    uint public immutable startTime = block.timestamp;

    /**
     * @notice A running total of the amount of tokens emitted.
     */
    int256 public emittedTokenWad;

    // The split of the purchase that is reserved for the creator of the Verb in basis points
    uint256 public creatorRateBps;

    // The split of (purchase proceeds * creatorRate) that is sent to the creator as ether in basis points
    uint256 public entropyRateBps;

    // The account or contract to pay the creator reward to
    address public creatorsAddress;

    // approved contracts, owner, and a token contract address
    constructor(
        address _initialOwner,
        NontransferableERC20Votes _token,
        address _protocolRewards,
        address _protocolFeeRecipient,
        address _treasury,
        int _targetPrice, // The target price for a token if sold on pace, scaled by 1e18.
        int _priceDecayPercent, // The percent price decays per unit of time with no sales, scaled by 1e18.
        int _tokensPerTimeUnit // The number of tokens to target selling in 1 full unit of time, scaled by 1e18.
    )
        TokenEmitterRewards(_protocolRewards, _protocolFeeRecipient)
        VRGDAC(_targetPrice, _priceDecayPercent, _tokensPerTimeUnit)
        Ownable(_initialOwner)
    {
        require(_treasury != address(0), "Invalid treasury address");

        treasury = _treasury;

        token = _token;
    }

    function _mint(address _to, uint _amount) private {
        token.mint(_to, _amount);
    }

    function totalSupply() public view returns (uint) {
        // returns total supply issued so far
        return token.totalSupply();
    }

    function decimals() public view returns (uint8) {
        // returns decimals
        return token.decimals();
    }

    function balanceOf(address _owner) public view returns (uint) {
        // returns balance of address
        return token.balanceOf(_owner);
    }

    /**
     * @notice A payable function that allows a user to buy tokens for a list of addresses and a list of basis points to split the token purchase between.
     * @param addresses The addresses to send purchased tokens to.
     * @param bps The basis points of the purchase to send to each address.
     * @param protocolRewardsRecipients The addresses to pay the builder, purchaseRefferal, and deployer rewards to
     * @return tokensSoldWad The amount of tokens sold in wad units.
     */
    function buyToken(
        address[] calldata addresses,
        uint[] calldata bps,
        ProtocolRewardAddresses calldata protocolRewardsRecipients
    ) public payable nonReentrant returns (uint tokensSoldWad) {
        //prevent treasury from paying itself
        require(msg.sender != treasury && msg.sender != creatorsAddress, "Funds recipient cannot buy tokens");

        require(msg.value > 0, "Must send ether");
        // ensure the same number of addresses and bps
        require(addresses.length == bps.length, "Parallel arrays required");

        // Get value left after protocol rewards
        uint msgValueRemaining = _handleRewardsAndGetValueToSend(
            msg.value,
            protocolRewardsRecipients.builder,
            protocolRewardsRecipients.purchaseReferral,
            protocolRewardsRecipients.deployer
        );

        //Share of purchase amount to send to treasury
        uint256 toPayTreasury = (msgValueRemaining * (10_000 - creatorRateBps)) / 10_000;

        //Share of purchase amount to reserve for creators
        //Ether directly sent to creators
        uint256 creatorDirectPayment = ((msgValueRemaining - toPayTreasury) * entropyRateBps) / 10_000;
        //Tokens to emit to creators
        int totalTokensForCreators = ((msgValueRemaining - toPayTreasury) - creatorDirectPayment) > 0
            ? getTokenQuoteForEther((msgValueRemaining - toPayTreasury) - creatorDirectPayment)
            : int(0);

        // Tokens to emit to buyers
        int totalTokensForBuyers = toPayTreasury > 0 ? getTokenQuoteForEther(toPayTreasury) : int(0);

        //Transfer ETH to treasury and update emitted
        emittedTokenWad += totalTokensForBuyers;
        if (totalTokensForCreators > 0) emittedTokenWad += totalTokensForCreators;

        //Deposit funds to treasury
        (bool success, ) = treasury.call{ value: toPayTreasury }(new bytes(0));
        require(success, "Transfer failed.");

        //Transfer ETH to creators
        if (creatorDirectPayment > 0) {
            (success, ) = creatorsAddress.call{ value: creatorDirectPayment }(new bytes(0));
            require(success, "Transfer failed.");
        }

        //Mint tokens for creators
        if (totalTokensForCreators > 0 && creatorsAddress != address(0)) {
            _mint(creatorsAddress, uint(totalTokensForCreators));
        }

        uint bpsSum = 0;

        //Mint tokens to buyers
        if (totalTokensForBuyers > 0) {
            for (uint i = 0; i < addresses.length; ) {
                // transfer tokens to address
                _mint(addresses[i], uint((totalTokensForBuyers * int(bps[i])) / 10_000));
                bpsSum += bps[i];

                unchecked {
                    ++i;
                }
            }
        }

        require(bpsSum == 10_000, "bps must add up to 10_000");

        emit PurchaseFinalized(
            msg.sender,
            msg.value,
            toPayTreasury,
            msg.value - msgValueRemaining,
            uint(totalTokensForBuyers),
            uint(totalTokensForCreators),
            creatorDirectPayment
        );

        return uint(totalTokensForBuyers);
    }

    /**
     * @notice Returns the amount of wei that would be spent to buy an amount of tokens. Does not take into account the protocol rewards.
     * @param amount the amount of tokens to buy.
     * @return spentY The cost in wei of the token purchase.
     */
    function buyTokenQuote(uint amount) public view returns (int spentY) {
        require(amount > 0, "Amount must be greater than 0");
        // Note: By using toDaysWadUnsafe(block.timestamp - startTime) we are establishing that 1 "unit of time" is 1 day.
        // solhint-disable-next-line not-rely-on-time
        return
            xToY({
                timeSinceStart: toDaysWadUnsafe(block.timestamp - startTime),
                sold: emittedTokenWad,
                amount: int(amount)
            });
    }

    /**
     * @notice Returns the amount of tokens that would be emitted for an amount of wei. Does not take into account the protocol rewards.
     * @param etherAmount the payment amount in wei.
     * @return gainedX The amount of tokens that would be emitted for the payment amount.
     */
    function getTokenQuoteForEther(uint etherAmount) public view returns (int gainedX) {
        require(etherAmount > 0, "Ether amount must be greater than 0");
        // Note: By using toDaysWadUnsafe(block.timestamp - startTime) we are establishing that 1 "unit of time" is 1 day.
        // solhint-disable-next-line not-rely-on-time
        return
            yToX({
                timeSinceStart: toDaysWadUnsafe(block.timestamp - startTime),
                sold: emittedTokenWad,
                amount: int(etherAmount)
            });
    }

    /**
     * @notice Returns the amount of tokens that would be emitted for the payment amount, taking into account the protocol rewards.
     * @param paymentAmount the payment amount in wei.
     * @return gainedX The amount of tokens that would be emitted for the payment amount.
     */
    function getTokenQuoteForPayment(uint paymentAmount) external view returns (int gainedX) {
        require(paymentAmount > 0, "Payment amount must be greater than 0");
        // Note: By using toDaysWadUnsafe(block.timestamp - startTime) we are establishing that 1 "unit of time" is 1 day.
        // solhint-disable-next-line not-rely-on-time
        return
            yToX({
                timeSinceStart: toDaysWadUnsafe(block.timestamp - startTime),
                sold: emittedTokenWad,
                amount: int(((paymentAmount - computeTotalReward(paymentAmount)) * (10_000 - creatorRateBps)) / 10_000)
            });
    }

    /**
     * @notice Set the split of (purchase * creatorRate) that is sent to the creator as ether in basis points.
     * @dev Only callable by the owner.
     * @param _entropyRateBps New entropy rate in basis points.
     */
    function setEntropyRateBps(uint256 _entropyRateBps) external onlyOwner {
        require(_entropyRateBps <= 10_000, "Entropy rate must be less than or equal to 10_000");

        entropyRateBps = _entropyRateBps;
        emit EntropyRateBpsUpdated(_entropyRateBps);
    }

    /**
     * @notice Set the split of the payment that is reserved for creators in basis points.
     * @dev Only callable by the owner.
     * @param _creatorRateBps New creator rate in basis points.
     */
    function setCreatorRateBps(uint256 _creatorRateBps) external onlyOwner {
        require(_creatorRateBps <= 10_000, "Creator rate must be less than or equal to 10_000");
        creatorRateBps = _creatorRateBps;

        emit CreatorRateBpsUpdated(_creatorRateBps);
    }

    /**
     * @notice Set the creators address to pay the creatorRate to. Can be a contract.
     * @dev Only callable by the owner.
     */
    function setCreatorsAddress(address _creatorsAddress) external override onlyOwner nonReentrant {
        require(_creatorsAddress != address(0), "Invalid address");
        creatorsAddress = _creatorsAddress;

        emit CreatorsAddressUpdated(_creatorsAddress);
    }
}
