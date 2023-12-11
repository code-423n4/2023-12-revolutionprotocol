// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (token/ERC721/extensions/ERC721Votes.sol)

pragma solidity ^0.8.22;

import { ERC721EnumerableUpgradeable } from "./ERC721EnumerableUpgradeable.sol";
import { VotesUpgradeable } from "./VotesUpgradeable.sol";
import { Initializable } from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

/**
 * @dev Extension of ERC-721 to support voting and delegation as implemented by {Votes}, where each individual NFT counts
 * as 1 vote unit.
 *
 * Tokens do not count as votes until they are delegated, because votes must be tracked which incurs an additional cost
 * on every transfer. Token holders can either delegate to a trusted representative who will decide how to make use of
 * the votes in governance decisions, or they can delegate to themselves to be their own representative.
 */

/**
 * @dev MODIFICATIONS
 * Checkpointing logic from VotesUpgradeable.sol has been used with the following modifications:
 * - `delegates` is renamed to `_delegates` and is set to private
 * - `delegates` is a public function that uses the `_delegates` mapping look-up, but unlike
 *   VotesUpgradeable.sol, returns the delegator's own address if there is no delegate.
 *   This avoids the delegator needing to "delegate to self" with an additional transaction
 */

abstract contract ERC721CheckpointableUpgradeable is Initializable, ERC721EnumerableUpgradeable, VotesUpgradeable {
    function __ERC721Votes_init() internal onlyInitializing {}

    function __ERC721Votes_init_unchained() internal onlyInitializing {}

    /**
     * @dev See {ERC721-_update}. Adjusts votes when tokens are transferred.
     *
     * Emits a {IVotes-DelegateVotesChanged} event.
     */
    function _update(address to, uint256 tokenId, address auth) internal virtual override returns (address) {
        address previousOwner = super._update(to, tokenId, auth);

        _transferVotingUnits(previousOwner, to, 1);

        return previousOwner;
    }

    function getVotesStorage() private pure returns (VotesStorage storage $) {
        assembly {
            $.slot := VotesStorageLocation
        }
    }

    // /**
    //  * @notice Overrides the standard `VotesUpgradeable.sol` delegates mapping to return
    //  * the accounts's own address if they haven't delegated.
    //  * This avoids having to delegate to oneself.
    //  */
    function delegates(address account) public view override returns (address) {
        VotesStorage storage $ = getVotesStorage();
        return $._delegatee[account] == address(0) ? account : $._delegatee[account];
    }

    /**
     * @dev Returns the balance of `account`.
     *
     * WARNING: Overriding this function will likely result in incorrect vote tracking.
     */
    function _getVotingUnits(address account) internal view virtual override returns (uint256) {
        return balanceOf(account);
    }

    /**
     * @dev See {ERC721-_increaseBalance}. We need that to account tokens that were minted in batch.
     */
    function _increaseBalance(address account, uint128 amount) internal virtual override {
        super._increaseBalance(account, amount);
        _transferVotingUnits(address(0), account, amount);
    }
}
