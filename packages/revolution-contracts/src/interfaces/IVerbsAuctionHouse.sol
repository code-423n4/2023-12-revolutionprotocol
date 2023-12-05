// SPDX-License-Identifier: GPL-3.0

/// @title Interface for Verb Auction Houses

/*********************************
 * ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ *
 * ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ *
 * ░░░░░░█████████░░█████████░░░ *
 * ░░░░░░██░░░████░░██░░░████░░░ *
 * ░░██████░░░████████░░░████░░░ *
 * ░░██░░██░░░████░░██░░░████░░░ *
 * ░░██░░██░░░████░░██░░░████░░░ *
 * ░░░░░░█████████░░█████████░░░ *
 * ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ *
 * ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ *
 *********************************/

pragma solidity ^0.8.22;

interface IVerbsAuctionHouse {
    struct Auction {
        // ID for the Verb (ERC721 token ID)
        uint256 verbId;
        // The current highest bid amount
        uint256 amount;
        // The time that the auction started
        uint256 startTime;
        // The time that the auction is scheduled to end
        uint256 endTime;
        // The address of the current highest bid
        address payable bidder;
        // Whether or not the auction has been settled
        bool settled;
    }

    event AuctionCreated(uint256 indexed verbId, uint256 startTime, uint256 endTime);

    event AuctionBid(uint256 indexed verbId, address sender, uint256 value, bool extended);

    event AuctionExtended(uint256 indexed verbId, uint256 endTime);

    event AuctionSettled(uint256 indexed verbId, address winner, uint256 amount, uint256 creatorTokensEmitted);

    event AuctionTimeBufferUpdated(uint256 timeBuffer);

    event AuctionReservePriceUpdated(uint256 reservePrice);

    event AuctionMinBidIncrementPercentageUpdated(uint256 minBidIncrementPercentage);

    event CreatorRateBpsUpdated(uint256 rateBps);

    event MinCreatorRateBpsUpdated(uint256 rateBps);

    event EntropyRateBpsUpdated(uint256 rateBps);

    function settleAuction() external;

    function settleCurrentAndCreateNewAuction() external;

    function createBid(uint256 verbId) external payable;

    function pause() external;

    function unpause() external;

    function setTimeBuffer(uint256 timeBuffer) external;

    function setReservePrice(uint256 reservePrice) external;

    function setMinBidIncrementPercentage(uint8 minBidIncrementPercentage) external;

    function setCreatorRateBps(uint256 _creatorRateBps) external;

    function setMinCreatorRateBps(uint256 _minCreatorRateBps) external;

    function setEntropyRateBps(uint256 _entropyRateBps) external;
}
