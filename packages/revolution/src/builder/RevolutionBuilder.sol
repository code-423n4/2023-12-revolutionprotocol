// SPDX-License-Identifier: MIT
pragma solidity 0.8.22;

/// @title The Revolution builder contract

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
// RevolutionBuilder.sol is a modified version of Nouns Builder's Manager.sol:
// https://github.com/ourzora/nouns-protocol/blob/82e00ed34dd9b7c9e1ac5eea29f7f713d1084e68/src/manager/Manager.sol
//
// Manager.sol source code under the MIT license.

import { Ownable2StepUpgradeable } from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

import { RevolutionBuilderStorageV1 } from "./storage/RevolutionBuilderStorageV1.sol";
import { IRevolutionBuilder } from "../interfaces/IRevolutionBuilder.sol";
import { IVerbsToken } from "../interfaces/IVerbsToken.sol";
import { IDescriptor } from "../interfaces/IDescriptor.sol";
import { IAuctionHouse } from "../interfaces/IAuctionHouse.sol";
import { IDAOExecutor } from "../interfaces/IDAOExecutor.sol";
import { IVerbsDAO } from "../interfaces/IVerbsDAO.sol";
import { ICultureIndex } from "../interfaces/ICultureIndex.sol";
import { IMaxHeap } from "../interfaces/IMaxHeap.sol";
import { IERC20TokenEmitter } from "../interfaces/IERC20TokenEmitter.sol";
import { INontransferableERC20Votes } from "../interfaces/INontransferableERC20Votes.sol";
import { VRGDAC } from "../libs/VRGDAC.sol";

import { ERC1967Proxy } from "../libs/proxy/ERC1967Proxy.sol";
import { UUPS } from "../libs/proxy/UUPS.sol";

import { VersionedContract } from "../version/VersionedContract.sol";
import { IVersionedContract } from "../interfaces/IVersionedContract.sol";

/// @title RevolutionBuilder
/// @notice The Revolution DAO deployer and upgrade manager
contract RevolutionBuilder is
    IRevolutionBuilder,
    VersionedContract,
    UUPS,
    Ownable2StepUpgradeable,
    RevolutionBuilderStorageV1
{
    ///                                                          ///
    ///                          IMMUTABLES                      ///
    ///                                                          ///

    /// @notice The token implementation address
    address public immutable erc721TokenImpl;

    /// @notice The descriptor implementation address
    address public immutable descriptorImpl;

    /// @notice The auction house implementation address
    address public immutable auctionImpl;

    /// @notice The executor implementation address
    address public immutable executorImpl;

    /// @notice The dao implementation address
    address public immutable daoImpl;

    /// @notice The erc20TokenEmitter implementation address
    address public immutable erc20TokenEmitterImpl;

    /// @notice The cultureIndex implementation address
    address public immutable cultureIndexImpl;

    /// @notice The erc20Token implementation address
    address public immutable erc20TokenImpl;

    /// @notice The maxHeap implementation address
    address public immutable maxHeapImpl;

    ///                                                          ///
    ///                          CONSTRUCTOR                     ///
    ///                                                          ///

    constructor(
        address _erc721TokenImpl,
        address _descriptorImpl,
        address _auctionImpl,
        address _executorImpl,
        address _daoImpl,
        address _cultureIndexImpl,
        address _erc20TokenImpl,
        address _erc20TokenEmitterImpl,
        address _maxHeapImpl
    ) payable initializer {
        erc721TokenImpl = _erc721TokenImpl;
        descriptorImpl = _descriptorImpl;
        auctionImpl = _auctionImpl;
        executorImpl = _executorImpl;
        daoImpl = _daoImpl;
        cultureIndexImpl = _cultureIndexImpl;
        erc20TokenImpl = _erc20TokenImpl;
        erc20TokenEmitterImpl = _erc20TokenEmitterImpl;
        maxHeapImpl = _maxHeapImpl;
    }

    ///                                                          ///
    ///                          INITIALIZER                     ///
    ///                                                          ///

    /// @notice Initializes ownership of the manager contract
    /// @param _newOwner The owner address to set (will be transferred to the Revolution DAO once its deployed)
    function initialize(address _newOwner) external initializer {
        // Ensure an owner is specified
        require(_newOwner != address(0), "Owner address cannot be 0x0");

        // Set the contract owner
        __Ownable_init(_newOwner);
    }

    ///                                                          ///
    ///                           DAO DEPLOY                     ///
    ///                                                          ///

    /// @notice Deploys a DAO with custom token, auction, emitter, erc20, and governance settings
    /// @param _initialOwner The initial owner address
    /// @param _weth The WETH address
    /// @param _erc721TokenParams The ERC-721 token settings
    /// @param _auctionParams The auction settings
    /// @param _govParams The governance settings
    /// @param _cultureIndexParams The culture index settings
    /// @param _erc20TokenParams The ERC-20 token settings
    /// @param _erc20TokenEmitterParams The ERC-20 token emitter settings
    function deploy(
        address _initialOwner,
        address _weth,
        ERC721TokenParams calldata _erc721TokenParams,
        AuctionParams calldata _auctionParams,
        GovParams calldata _govParams,
        CultureIndexParams calldata _cultureIndexParams,
        ERC20TokenParams calldata _erc20TokenParams,
        ERC20TokenEmitterParams calldata _erc20TokenEmitterParams
    ) external returns (DAOAddresses memory) {
        require(_initialOwner != address(0), "Initial owner cannot be 0x0");

        // Deploy the DAO's ERC-721 governance token
        address erc721Token = address(new ERC1967Proxy(erc721TokenImpl, ""));

        // Deploy the VRGDAC contract
        address vrgdac = address(
            new VRGDAC(
                _erc20TokenEmitterParams.targetPrice,
                _erc20TokenEmitterParams.priceDecayPercent,
                _erc20TokenEmitterParams.tokensPerTimeUnit
            )
        );

        // Use the token address to precompute the DAO's remaining addresses
        bytes32 salt = bytes32(uint256(uint160(erc721Token)) << 96);

        // Deploy the remaining DAO contracts
        daoAddressesByToken[erc721Token] = DAOAddresses({
            descriptor: address(new ERC1967Proxy{ salt: salt }(descriptorImpl, "")),
            auction: address(new ERC1967Proxy{ salt: salt }(auctionImpl, "")),
            executor: address(new ERC1967Proxy{ salt: salt }(executorImpl, "")),
            dao: address(new ERC1967Proxy{ salt: salt }(daoImpl, "")),
            erc20TokenEmitter: address(new ERC1967Proxy{ salt: salt }(erc20TokenEmitterImpl, "")),
            cultureIndex: address(new ERC1967Proxy{ salt: salt }(cultureIndexImpl, "")),
            erc20Token: address(new ERC1967Proxy{ salt: salt }(erc20TokenImpl, "")),
            erc721Token: erc721Token,
            maxHeap: address(new ERC1967Proxy{ salt: salt }(maxHeapImpl, ""))
        });

        // Initialize each instance with the provided settings
        IMaxHeap(daoAddressesByToken[erc721Token].maxHeap).initialize(daoAddressesByToken[erc721Token].cultureIndex);

        IVerbsToken(erc721Token).initialize({
            minter: daoAddressesByToken[erc721Token].auction,
            descriptor: daoAddressesByToken[erc721Token].descriptor,
            initialOwner: daoAddressesByToken[erc721Token].auction,
            cultureIndex: daoAddressesByToken[erc721Token].cultureIndex,
            erc721TokenParams: _erc721TokenParams
        });

        IDescriptor(daoAddressesByToken[erc721Token].descriptor).initialize({
            initialOwner: daoAddressesByToken[erc721Token].dao,
            tokenNamePrefix: _erc721TokenParams.tokenNamePrefix
        });

        ICultureIndex(daoAddressesByToken[erc721Token].cultureIndex).initialize({
            erc20VotingToken: daoAddressesByToken[erc721Token].erc20Token,
            erc721VotingToken: daoAddressesByToken[erc721Token].erc721Token,
            initialOwner: daoAddressesByToken[erc721Token].erc721Token,
            cultureIndexParams: _cultureIndexParams,
            maxHeap: daoAddressesByToken[erc721Token].maxHeap
        });

        IAuctionHouse(daoAddressesByToken[erc721Token].auction).initialize({
            erc721Token: daoAddressesByToken[erc721Token].erc721Token,
            erc20TokenEmitter: daoAddressesByToken[erc721Token].erc20TokenEmitter,
            initialOwner: daoAddressesByToken[erc721Token].dao,
            auctionParams: _auctionParams,
            weth: _weth
        });

        INontransferableERC20Votes(daoAddressesByToken[erc721Token].erc20Token).initialize({
            initialOwner: daoAddressesByToken[erc721Token].erc20TokenEmitter,
            erc20TokenParams: _erc20TokenParams
        });

        IERC20TokenEmitter(daoAddressesByToken[erc721Token].erc20TokenEmitter).initialize({
            erc20Token: daoAddressesByToken[erc721Token].erc20Token,
            initialOwner: daoAddressesByToken[erc721Token].dao,
            treasury: daoAddressesByToken[erc721Token].dao,
            vrgdac: vrgdac,
            creatorsAddress: _erc20TokenEmitterParams.creatorsAddress
        });

        IDAOExecutor(daoAddressesByToken[erc721Token].executor).initialize({
            admin: daoAddressesByToken[erc721Token].dao,
            timelockDelay: _govParams.timelockDelay
        });

        IVerbsDAO(daoAddressesByToken[erc721Token].dao).initialize({
            executor: daoAddressesByToken[erc721Token].executor,
            erc721Token: daoAddressesByToken[erc721Token].erc721Token,
            erc20Token: daoAddressesByToken[erc721Token].erc20Token,
            govParams: _govParams
        });

        emit DAODeployed({
            erc721Token: daoAddressesByToken[erc721Token].erc721Token,
            descriptor: daoAddressesByToken[erc721Token].descriptor,
            auction: daoAddressesByToken[erc721Token].auction,
            executor: daoAddressesByToken[erc721Token].executor,
            dao: daoAddressesByToken[erc721Token].dao,
            erc20TokenEmitter: daoAddressesByToken[erc721Token].erc20TokenEmitter,
            cultureIndex: daoAddressesByToken[erc721Token].cultureIndex,
            erc20Token: daoAddressesByToken[erc721Token].erc20Token,
            maxHeap: daoAddressesByToken[erc721Token].maxHeap
        });

        return daoAddressesByToken[erc721Token];
    }

    ///                                                          ///
    ///                         DAO ADDRESSES                    ///
    ///                                                          ///

    /// @notice A DAO's contract addresses from its token
    /// @param _token The ERC-721 token address
    /// @return erc721Token ERC-721 token deployed address
    /// @return descriptor Descriptor deployed address
    /// @return auction Auction deployed address
    /// @return executor Executor deployed address
    /// @return dao DAO deployed address
    /// @return cultureIndex CultureIndex deployed address
    /// @return erc20Token ERC-20 token deployed address
    /// @return erc20TokenEmitter ERC-20 token emitter deployed address
    /// @return maxHeap MaxHeap deployed address
    function getAddresses(
        address _token
    )
        public
        view
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
        )
    {
        DAOAddresses storage addresses = daoAddressesByToken[_token];

        descriptor = addresses.descriptor;
        auction = addresses.auction;
        executor = addresses.executor;
        dao = addresses.dao;

        cultureIndex = addresses.cultureIndex;
        erc20Token = addresses.erc20Token;
        erc20TokenEmitter = addresses.erc20TokenEmitter;
        maxHeap = addresses.maxHeap;
    }

    ///                                                          ///
    ///                          DAO UPGRADES                    ///
    ///                                                          ///

    /// @notice If an implementation is registered by the Revolution DAO as an optional upgrade
    /// @param _baseImpl The base implementation address
    /// @param _upgradeImpl The upgrade implementation address
    function isRegisteredUpgrade(address _baseImpl, address _upgradeImpl) external view returns (bool) {
        return isUpgrade[_baseImpl][_upgradeImpl];
    }

    /// @notice Called by the Revolution DAO to offer implementation upgrades for created DAOs
    /// @param _baseImpl The base implementation address
    /// @param _upgradeImpl The upgrade implementation address
    function registerUpgrade(address _baseImpl, address _upgradeImpl) external onlyOwner {
        isUpgrade[_baseImpl][_upgradeImpl] = true;

        emit UpgradeRegistered(_baseImpl, _upgradeImpl);
    }

    /// @notice Called by the Revolution DAO to remove an upgrade
    /// @param _baseImpl The base implementation address
    /// @param _upgradeImpl The upgrade implementation address
    function removeUpgrade(address _baseImpl, address _upgradeImpl) external onlyOwner {
        delete isUpgrade[_baseImpl][_upgradeImpl];

        emit UpgradeRemoved(_baseImpl, _upgradeImpl);
    }

    /// @notice Safely get the contract version of a target contract.
    /// @dev Assume `target` is a contract
    /// @return Contract version if found, empty string if not.
    function _safeGetVersion(address target) internal view returns (string memory) {
        try IVersionedContract(target).contractVersion() returns (string memory version) {
            return version;
        } catch {
            return "";
        }
    }

    function getDAOVersions(address token) external view returns (DAOVersionInfo memory) {
        (
            address erc721Token,
            address descriptor,
            address auction,
            address executor,
            address dao,
            address cultureIndex,
            address erc20Token,
            address erc20TokenEmitter,
            address maxHeap
        ) = getAddresses(token);
        return
            DAOVersionInfo({
                erc721Token: _safeGetVersion(erc721Token),
                descriptor: _safeGetVersion(descriptor),
                auction: _safeGetVersion(auction),
                executor: _safeGetVersion(executor),
                dao: _safeGetVersion(dao),
                erc20Token: _safeGetVersion(erc20Token),
                cultureIndex: _safeGetVersion(cultureIndex),
                erc20TokenEmitter: _safeGetVersion(erc20TokenEmitter),
                maxHeap: _safeGetVersion(maxHeap)
            });
    }

    function getLatestVersions() external view returns (DAOVersionInfo memory) {
        return
            DAOVersionInfo({
                erc721Token: _safeGetVersion(erc721TokenImpl),
                descriptor: _safeGetVersion(descriptorImpl),
                auction: _safeGetVersion(auctionImpl),
                executor: _safeGetVersion(executorImpl),
                dao: _safeGetVersion(daoImpl),
                cultureIndex: _safeGetVersion(cultureIndexImpl),
                erc20Token: _safeGetVersion(erc20TokenImpl),
                erc20TokenEmitter: _safeGetVersion(erc20TokenEmitterImpl),
                maxHeap: _safeGetVersion(maxHeapImpl)
            });
    }

    ///                                                          ///
    ///                         MANAGER UPGRADE                  ///
    ///                                                          ///

    /// @notice Ensures the caller is authorized to upgrade the contract
    /// @dev This function is called in `upgradeTo` & `upgradeToAndCall`
    /// @param _newImpl The new implementation address
    function _authorizeUpgrade(address _newImpl) internal override onlyOwner {}
}
