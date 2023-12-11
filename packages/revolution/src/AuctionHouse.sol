// SPDX-License-Identifier: GPL-3.0

/// @title The Verbs DAO auction house

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

// LICENSE
// AuctionHouse.sol is a modified version of Zora's AuctionHouse.sol:
// https://github.com/ourzora/auction-house/blob/54a12ec1a6cf562e49f0a4917990474b11350a2d/contracts/AuctionHouse.sol
//
// AuctionHouse.sol source code Copyright Zora licensed under the GPL-3.0 license.

pragma solidity ^0.8.22;

import { PausableUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import { ReentrancyGuardUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import { IAuctionHouse } from "./interfaces/IAuctionHouse.sol";
import { IVerbsToken } from "./interfaces/IVerbsToken.sol";
import { IWETH } from "./interfaces/IWETH.sol";
import { IERC20TokenEmitter } from "./interfaces/IERC20TokenEmitter.sol";
import { ICultureIndex } from "./interfaces/ICultureIndex.sol";
import { IRevolutionBuilder } from "./interfaces/IRevolutionBuilder.sol";
import { Ownable2StepUpgradeable } from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

import { UUPS } from "./libs/proxy/UUPS.sol";
import { VersionedContract } from "./version/VersionedContract.sol";

contract AuctionHouse is
    IAuctionHouse,
    VersionedContract,
    UUPS,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable,
    Ownable2StepUpgradeable
{
    // The Verbs ERC721 token contract
    IVerbsToken public verbs;

    // The ERC20 governance token
    IERC20TokenEmitter public erc20TokenEmitter;

    // The address of the WETH contract
    address public WETH;

    // The minimum amount of time left in an auction after a new bid is created
    uint256 public timeBuffer;

    // The minimum price accepted in an auction
    uint256 public reservePrice;

    // The minimum percentage difference between the last bid amount and the current bid
    uint8 public minBidIncrementPercentage;

    // The split of the winning bid that is reserved for the creator of the Verb in basis points
    uint256 public creatorRateBps;

    // The all time minimum split of the winning bid that is reserved for the creator of the Verb in basis points
    uint256 public minCreatorRateBps;

    // The split of (auction proceeds * creatorRate) that is sent to the creator as ether in basis points
    uint256 public entropyRateBps;

    // The duration of a single auction
    uint256 public duration;

    // The active auction
    IAuctionHouse.Auction public auction;

    ///                                                          ///
    ///                         IMMUTABLES                       ///
    ///                                                          ///

    /// @notice The contract upgrade manager
    IRevolutionBuilder public immutable manager;

    // TODO investigate this - The minimum gas threshold for creating an auction (minting VerbsToken)
    uint32 public constant MIN_TOKEN_MINT_GAS_THRESHOLD = 750_000;

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
     * @notice Initialize the auction house and base contracts,
     * populate configuration values, and pause the contract.
     * @dev This function can only be called once.
     * @param _erc721Token The address of the Verbs ERC721 token contract.
     * @param _erc20TokenEmitter The address of the ERC-20 token emitter contract.
     * @param _initialOwner The address of the owner.
     * @param _weth The address of the WETH contract
     * @param _auctionParams The auction params for auctions.
     */
    function initialize(
        address _erc721Token,
        address _erc20TokenEmitter,
        address _initialOwner,
        address _weth,
        IRevolutionBuilder.AuctionParams calldata _auctionParams
    ) external initializer {
        require(msg.sender == address(manager), "Only manager can initialize");
        require(_weth != address(0), "WETH cannot be zero address");

        __Pausable_init();
        __ReentrancyGuard_init();
        __Ownable_init(_initialOwner);

        _pause();

        require(
            _auctionParams.creatorRateBps >= _auctionParams.minCreatorRateBps,
            "Creator rate must be greater than or equal to the creator rate"
        );

        verbs = IVerbsToken(_erc721Token);
        erc20TokenEmitter = IERC20TokenEmitter(_erc20TokenEmitter);
        timeBuffer = _auctionParams.timeBuffer;
        reservePrice = _auctionParams.reservePrice;
        minBidIncrementPercentage = _auctionParams.minBidIncrementPercentage;
        duration = _auctionParams.duration;
        creatorRateBps = _auctionParams.creatorRateBps;
        entropyRateBps = _auctionParams.entropyRateBps;
        minCreatorRateBps = _auctionParams.minCreatorRateBps;
        WETH = _weth;
    }

    /**
     * @notice Settle the current auction, mint a new Verb, and put it up for auction.
     */
    // Can technically reenter via cross function reentrancies in _createAuction, auction, and pause, but those are only callable by the owner.
    // @wardens if you can find an exploit here go for it - we might be wrong.
    // slither-disable-next-line reentrancy-eth
    function settleCurrentAndCreateNewAuction() external override nonReentrant whenNotPaused {
        _settleAuction();
        _createAuction();
    }

    /**
     * @notice Settle the current auction.
     * @dev This function can only be called when the contract is paused.
     */
    function settleAuction() external override whenPaused nonReentrant {
        _settleAuction();
    }

    /**
     * @notice Create a bid for a Verb, with a given amount.
     * @dev This contract only accepts payment in ETH.
     * @param verbId The ID of the Verb to bid on.
     * @param bidder The address of the bidder.
     */
    function createBid(uint256 verbId, address bidder) external payable override nonReentrant {
        IAuctionHouse.Auction memory _auction = auction;

        //require bidder is valid address
        require(bidder != address(0), "Bidder cannot be zero address");
        require(_auction.verbId == verbId, "Verb not up for auction");
        //slither-disable-next-line timestamp
        require(block.timestamp < _auction.endTime, "Auction expired");
        require(msg.value >= reservePrice, "Must send at least reservePrice");
        require(
            msg.value >= _auction.amount + ((_auction.amount * minBidIncrementPercentage) / 100),
            "Must send more than last bid by minBidIncrementPercentage amount"
        );

        address payable lastBidder = _auction.bidder;

        auction.amount = msg.value;
        auction.bidder = payable(bidder);

        // Extend the auction if the bid was received within `timeBuffer` of the auction end time
        bool extended = _auction.endTime - block.timestamp < timeBuffer;
        if (extended) auction.endTime = _auction.endTime = block.timestamp + timeBuffer;

        // Refund the last bidder, if applicable
        if (lastBidder != address(0)) _safeTransferETHWithFallback(lastBidder, _auction.amount);

        emit AuctionBid(_auction.verbId, bidder, msg.sender, msg.value, extended);

        if (extended) emit AuctionExtended(_auction.verbId, _auction.endTime);
    }

    /**
     * @notice Pause the Verbs auction house.
     * @dev This function can only be called by the owner when the
     * contract is unpaused. While no new auctions can be started when paused,
     * anyone can settle an ongoing auction.
     */
    function pause() external override onlyOwner {
        _pause();
    }

    /**
     * @notice Set the split of the winning bid that is reserved for the creator of the Verb in basis points.
     * @dev Only callable by the owner.
     * @param _creatorRateBps New creator rate in basis points.
     */
    function setCreatorRateBps(uint256 _creatorRateBps) external onlyOwner {
        require(
            _creatorRateBps >= minCreatorRateBps,
            "Creator rate must be greater than or equal to minCreatorRateBps"
        );
        require(_creatorRateBps <= 10_000, "Creator rate must be less than or equal to 10_000");
        creatorRateBps = _creatorRateBps;

        emit CreatorRateBpsUpdated(_creatorRateBps);
    }

    /**
     * @notice Set the minimum split of the winning bid that is reserved for the creator of the Verb in basis points.
     * @dev Only callable by the owner.
     * @param _minCreatorRateBps New minimum creator rate in basis points.
     */
    function setMinCreatorRateBps(uint256 _minCreatorRateBps) external onlyOwner {
        require(_minCreatorRateBps <= creatorRateBps, "Min creator rate must be less than or equal to creator rate");
        require(_minCreatorRateBps <= 10_000, "Min creator rate must be less than or equal to 10_000");

        //ensure new min rate cannot be lower than previous min rate
        require(
            _minCreatorRateBps > minCreatorRateBps,
            "Min creator rate must be greater than previous minCreatorRateBps"
        );

        minCreatorRateBps = _minCreatorRateBps;

        emit MinCreatorRateBpsUpdated(_minCreatorRateBps);
    }

    /**
     * @notice Set the split of (auction proceeds * creatorRate) that is sent to the creator as ether in basis points.
     * @dev Only callable by the owner.
     * @param _entropyRateBps New entropy rate in basis points.
     */
    function setEntropyRateBps(uint256 _entropyRateBps) external onlyOwner {
        require(_entropyRateBps <= 10_000, "Entropy rate must be less than or equal to 10_000");

        entropyRateBps = _entropyRateBps;
        emit EntropyRateBpsUpdated(_entropyRateBps);
    }

    /**
     * @notice Unpause the Verbs auction house.
     * @dev This function can only be called by the owner when the
     * contract is paused. If required, this function will start a new auction.
     */
    function unpause() external override onlyOwner {
        _unpause();

        if (auction.startTime == 0 || auction.settled) {
            _createAuction();
        }
    }

    /**
     * @notice Set the auction time buffer.
     * @dev Only callable by the owner.
     */
    function setTimeBuffer(uint256 _timeBuffer) external override onlyOwner {
        timeBuffer = _timeBuffer;

        emit AuctionTimeBufferUpdated(_timeBuffer);
    }

    /**
     * @notice Set the auction reserve price.
     * @dev Only callable by the owner.
     */
    function setReservePrice(uint256 _reservePrice) external override onlyOwner {
        reservePrice = _reservePrice;

        emit AuctionReservePriceUpdated(_reservePrice);
    }

    /**
     * @notice Set the auction minimum bid increment percentage.
     * @dev Only callable by the owner.
     */
    function setMinBidIncrementPercentage(uint8 _minBidIncrementPercentage) external override onlyOwner {
        minBidIncrementPercentage = _minBidIncrementPercentage;

        emit AuctionMinBidIncrementPercentageUpdated(_minBidIncrementPercentage);
    }

    /**
     * @notice Create an auction.
     * @dev Store the auction details in the `auction` state variable and emit an AuctionCreated event.
     * If the mint reverts, the minter was updated without pausing this contract first. To remedy this,
     * catch the revert and pause this contract.
     */
    function _createAuction() internal {
        // Check if there's enough gas to safely execute token.mint() and subsequent operations
        require(gasleft() >= MIN_TOKEN_MINT_GAS_THRESHOLD, "Insufficient gas for creating auction");

        try verbs.mint() returns (uint256 verbId) {
            uint256 startTime = block.timestamp;
            uint256 endTime = startTime + duration;

            auction = Auction({
                verbId: verbId,
                amount: 0,
                startTime: startTime,
                endTime: endTime,
                bidder: payable(0),
                settled: false
            });

            emit AuctionCreated(verbId, startTime, endTime);
        } catch {
            _pause();
        }
    }

    /**
     * @notice Settle an auction, finalizing the bid and paying out to the owner. Pays out to the creator and the owner based on the creatorRateBps and entropyRateBps.
     * @dev If there are no bids, the Verb is burned.
     */
    function _settleAuction() internal {
        IAuctionHouse.Auction memory _auction = auction;

        require(_auction.startTime != 0, "Auction hasn't begun");
        require(!_auction.settled, "Auction has already been settled");
        //slither-disable-next-line timestamp
        require(block.timestamp >= _auction.endTime, "Auction hasn't completed");

        auction.settled = true;

        uint256 creatorTokensEmitted = 0;
        // Check if contract balance is greater than reserve price
        if (address(this).balance < reservePrice) {
            // If contract balance is less than reserve price, refund to the last bidder
            if (_auction.bidder != address(0)) {
                _safeTransferETHWithFallback(_auction.bidder, _auction.amount);
            }

            // And then burn the Noun
            verbs.burn(_auction.verbId);
        } else {
            //If no one has bid, burn the Verb
            if (_auction.bidder == address(0))
                verbs.burn(_auction.verbId);
                //If someone has bid, transfer the Verb to the winning bidder
            else verbs.transferFrom(address(this), _auction.bidder, _auction.verbId);

            if (_auction.amount > 0) {
                // Ether going to owner of the auction
                uint256 auctioneerPayment = (_auction.amount * (10_000 - creatorRateBps)) / 10_000;

                //Total amount of ether going to creator
                uint256 creatorsShare = _auction.amount - auctioneerPayment;

                uint256 numCreators = verbs.getArtPieceById(_auction.verbId).creators.length;
                address deployer = verbs.getArtPieceById(_auction.verbId).sponsor;

                //Build arrays for erc20TokenEmitter.buyToken
                uint256[] memory vrgdaSplits = new uint256[](numCreators);
                address[] memory vrgdaReceivers = new address[](numCreators);

                //Transfer auction amount to the DAO treasury
                _safeTransferETHWithFallback(owner(), auctioneerPayment);

                uint256 ethPaidToCreators = 0;

                //Transfer creator's share to the creator, for each creator, and build arrays for erc20TokenEmitter.buyToken
                if (creatorsShare > 0 && entropyRateBps > 0) {
                    for (uint256 i = 0; i < numCreators; i++) {
                        ICultureIndex.CreatorBps memory creator = verbs.getArtPieceById(_auction.verbId).creators[i];
                        vrgdaReceivers[i] = creator.creator;
                        vrgdaSplits[i] = creator.bps;

                        //Calculate paymentAmount for specific creator based on BPS splits - same as multiplying by creatorDirectPayment
                        uint256 paymentAmount = (creatorsShare * entropyRateBps * creator.bps) / (10_000 * 10_000);
                        ethPaidToCreators += paymentAmount;

                        //Transfer creator's share to the creator
                        _safeTransferETHWithFallback(creator.creator, paymentAmount);
                    }
                }

                //Buy token from ERC20TokenEmitter for all the creators
                if (creatorsShare > ethPaidToCreators) {
                    creatorTokensEmitted = erc20TokenEmitter.buyToken{ value: creatorsShare - ethPaidToCreators }(
                        vrgdaReceivers,
                        vrgdaSplits,
                        IERC20TokenEmitter.ProtocolRewardAddresses({
                            builder: address(0),
                            purchaseReferral: address(0),
                            deployer: deployer
                        })
                    );
                }
            }
        }

        emit AuctionSettled(_auction.verbId, _auction.bidder, _auction.amount, creatorTokensEmitted);
    }

    /// @notice Transfer ETH/WETH from the contract
    /// @param _to The recipient address
    /// @param _amount The amount transferring
    function _safeTransferETHWithFallback(address _to, uint256 _amount) private {
        // Ensure the contract has enough ETH to transfer
        if (address(this).balance < _amount) revert("Insufficient balance");

        // Used to store if the transfer succeeded
        bool success;

        assembly {
            // Transfer ETH to the recipient
            // Limit the call to 50,000 gas
            success := call(50000, _to, _amount, 0, 0, 0, 0)
        }

        // If the transfer failed:
        if (!success) {
            // Wrap as WETH
            IWETH(WETH).deposit{ value: _amount }();

            // Transfer WETH instead
            bool wethSuccess = IWETH(WETH).transfer(_to, _amount);

            // Ensure successful transfer
            if (!wethSuccess) revert("WETH transfer failed");
        }
    }

    ///                                                          ///
    ///                        AUCTION UPGRADE                   ///
    ///                                                          ///

    /// @notice Ensures the caller is authorized to upgrade the contract and the new implementation is valid
    /// @dev This function is called in `upgradeTo` & `upgradeToAndCall`
    /// @param _newImpl The new implementation address
    function _authorizeUpgrade(address _newImpl) internal view override onlyOwner whenPaused {
        // Ensure the new implementation is registered by the Builder DAO
        if (!manager.isRegisteredUpgrade(_getImplementation(), _newImpl)) revert INVALID_UPGRADE(_newImpl);
    }
}
