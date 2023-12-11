// SPDX-License-Identifier: MIT
pragma solidity 0.8.22;

import { VerbsDAOStorageV1 } from "../governance/VerbsDAOInterfaces.sol";
import { IUUPS } from "./IUUPS.sol";
import { RevolutionBuilderTypesV1 } from "../builder/types/RevolutionBuilderTypesV1.sol";

/// @title IRevolutionBuilder
/// @notice The external RevolutionBuilder events, errors, structs and functions
interface IRevolutionBuilder is IUUPS {
    ///                                                          ///
    ///                            EVENTS                        ///
    ///                                                          ///

    /// @notice Emitted when a DAO is deployed
    /// @param erc721Token The ERC-721 token address
    /// @param descriptor The descriptor renderer address
    /// @param auction The auction address
    /// @param executor The executor address
    /// @param dao The dao address
    /// @param cultureIndex The cultureIndex address
    /// @param erc20TokenEmitter The ERC20TokenEmitter address
    /// @param erc20Token The dao address
    /// @param maxHeap The maxHeap address
    event DAODeployed(
        address erc721Token,
        address descriptor,
        address auction,
        address executor,
        address dao,
        address cultureIndex,
        address erc20TokenEmitter,
        address erc20Token,
        address maxHeap
    );

    /// @notice Emitted when an upgrade is registered by the Builder DAO
    /// @param baseImpl The base implementation address
    /// @param upgradeImpl The upgrade implementation address
    event UpgradeRegistered(address baseImpl, address upgradeImpl);

    /// @notice Emitted when an upgrade is unregistered by the Builder DAO
    /// @param baseImpl The base implementation address
    /// @param upgradeImpl The upgrade implementation address
    event UpgradeRemoved(address baseImpl, address upgradeImpl);

    ///                                                          ///
    ///                            STRUCTS                       ///
    ///                                                          ///

    /// @notice DAO Version Information information struct
    struct DAOVersionInfo {
        string erc721Token;
        string descriptor;
        string auction;
        string executor;
        string dao;
        string cultureIndex;
        string erc20Token;
        string erc20TokenEmitter;
        string maxHeap;
    }

    /// @notice The ERC-721 token parameters
    /// @param name The token name
    /// @param symbol The token symbol
    /// @param contractURIHash The IPFS content hash of the contract-level metadata
    struct ERC721TokenParams {
        string name;
        string symbol;
        string contractURIHash;
        string tokenNamePrefix;
    }

    /// @notice The auction parameters
    /// @param timeBuffer The time buffer of each auction
    /// @param reservePrice The reserve price of each auction
    /// @param duration The duration of each auction
    /// @param minBidIncrementPercentage The minimum bid increment percentage of each auction
    /// @param creatorRateBps The creator rate basis points of each auction
    /// @param entropyRateBps The entropy rate basis points of each auction
    /// @param minCreatorRateBps The minimum creator rate basis points of each auction
    struct AuctionParams {
        uint256 timeBuffer;
        uint256 reservePrice;
        uint256 duration;
        uint8 minBidIncrementPercentage;
        uint256 creatorRateBps;
        uint256 entropyRateBps;
        uint256 minCreatorRateBps;
    }

    /// @notice The governance parameters
    /// @param timelockDelay The time delay to execute a queued transaction
    /// @param votingDelay The time delay to vote on a created proposal
    /// @param votingPeriod The time period to vote on a proposal
    /// @param proposalThresholdBPS The basis points of the token supply required to create a proposal
    /// @param vetoer The address authorized to veto proposals (address(0) if none desired)
    /// @param erc721TokenVotingWeight The voting weight of the individual ERC721 tokens
    /// @param daoName The name of the DAO
    /// @param dynamicQuorumParams The dynamic quorum parameters
    struct GovParams {
        uint256 timelockDelay;
        uint256 votingDelay;
        uint256 votingPeriod;
        uint256 proposalThresholdBPS;
        address vetoer;
        uint256 erc721TokenVotingWeight;
        string daoName;
        VerbsDAOStorageV1.DynamicQuorumParams dynamicQuorumParams;
    }

    /// @notice The ERC-20 token parameters
    /// @param name The token name
    /// @param symbol The token symbol
    struct ERC20TokenParams {
        string name;
        string symbol;
    }

    /// @notice The ERC-20 token emitter VRGDA parameters
    /// @param targetPrice // The target price for a token if sold on pace, scaled by 1e18.
    /// @param priceDecayPercent // The percent the price decays per unit of time with no sales, scaled by 1e18.
    /// @param tokensPerTimeUnit // The number of tokens to target selling in 1 full unit of time, scaled by 1e18.
    /// @param creatorsAddress // The address to send creator payments to
    struct ERC20TokenEmitterParams {
        int256 targetPrice;
        int256 priceDecayPercent;
        int256 tokensPerTimeUnit;
        address creatorsAddress;
    }

    /// @notice The CultureIndex parameters
    /// @param name The name of the culture index
    /// @param description A description for the culture index, can include rules for uploads etc.
    /// @param erc721VotingTokenWeight The voting weight of the individual ERC721 tokens. Normally a large multiple to match up with daily emission of ERC20 points
    /// @param quorumVotesBPS The initial quorum votes threshold in basis points
    /// @param minVoteWeight The minimum vote weight in basis points that a voter must have to be able to vote.
    struct CultureIndexParams {
        string name;
        string description;
        uint256 erc721VotingTokenWeight;
        uint256 quorumVotesBPS;
        uint256 minVoteWeight;
    }

    ///                                                          ///
    ///                           FUNCTIONS                      ///
    ///                                                          ///

    /// @notice The token implementation address
    function erc721TokenImpl() external view returns (address);

    /// @notice The descriptor renderer implementation address
    function descriptorImpl() external view returns (address);

    /// @notice The auction house implementation address
    function auctionImpl() external view returns (address);

    /// @notice The executor implementation address
    function executorImpl() external view returns (address);

    /// @notice The dao implementation address
    function daoImpl() external view returns (address);

    /// @notice The erc20TokenEmitter implementation address
    function erc20TokenEmitterImpl() external view returns (address);

    /// @notice The cultureIndex implementation address
    function cultureIndexImpl() external view returns (address);

    /// @notice The erc20Token implementation address
    function erc20TokenImpl() external view returns (address);

    /// @notice The maxHeap implementation address
    function maxHeapImpl() external view returns (address);

    /// @notice Deploys a DAO with custom token, auction, and governance settings
    /// @param initialOwner The initial owner address
    /// @param weth The WETH address
    /// @param erc721TokenParams The ERC-721 token settings
    /// @param auctionParams The auction settings
    /// @param govParams The governance settings
    /// @param cultureIndexParams The CultureIndex settings
    /// @param erc20TokenParams The ERC-20 token settings
    /// @param erc20TokenEmitterParams The ERC-20 token emitter settings
    function deploy(
        address initialOwner,
        address weth,
        ERC721TokenParams calldata erc721TokenParams,
        AuctionParams calldata auctionParams,
        GovParams calldata govParams,
        CultureIndexParams calldata cultureIndexParams,
        ERC20TokenParams calldata erc20TokenParams,
        ERC20TokenEmitterParams calldata erc20TokenEmitterParams
    ) external returns (RevolutionBuilderTypesV1.DAOAddresses memory);

    /// @notice A DAO's remaining contract addresses from its token address
    /// @param token The ERC-721 token address
    function getAddresses(
        address token
    )
        external
        returns (
            address erc721Token,
            address descriptor,
            address auction,
            address executor,
            address dao,
            address cultureIndex,
            address erc20Token,
            address erc20TokenEmitter,
            address maxHeap
        );

    /// @notice If an implementation is registered by the Builder DAO as an optional upgrade
    /// @param baseImpl The base implementation address
    /// @param upgradeImpl The upgrade implementation address
    function isRegisteredUpgrade(address baseImpl, address upgradeImpl) external view returns (bool);

    /// @notice Called by the Builder DAO to offer opt-in implementation upgrades for all other DAOs
    /// @param baseImpl The base implementation address
    /// @param upgradeImpl The upgrade implementation address
    function registerUpgrade(address baseImpl, address upgradeImpl) external;

    /// @notice Called by the Builder DAO to remove an upgrade
    /// @param baseImpl The base implementation address
    /// @param upgradeImpl The upgrade implementation address
    function removeUpgrade(address baseImpl, address upgradeImpl) external;
}
