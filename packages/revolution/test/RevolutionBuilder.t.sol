// SPDX-License-Identifier: MIT
pragma solidity 0.8.22;

import { Test } from "forge-std/Test.sol";

import { IRevolutionBuilder } from "../src/interfaces/IRevolutionBuilder.sol";
import { RevolutionBuilder } from "../src/builder/RevolutionBuilder.sol";
import { VerbsToken, IVerbsToken } from "../src/VerbsToken.sol";
import { Descriptor } from "../src/Descriptor.sol";
import { IAuctionHouse, AuctionHouse } from "../src/AuctionHouse.sol";
import { VerbsDAOLogicV1 } from "../src/governance/VerbsDAOLogicV1.sol";
import { DAOExecutor } from "../src/governance/DAOExecutor.sol";
import { CultureIndex } from "../src/CultureIndex.sol";
import { NontransferableERC20Votes } from "../src/NontransferableERC20Votes.sol";
import { ERC20TokenEmitter } from "../src/ERC20TokenEmitter.sol";
import { MaxHeap } from "../src/MaxHeap.sol";
import { VerbsDAOStorageV1 } from "../src/governance/VerbsDAOInterfaces.sol";
import { RevolutionProtocolRewards } from "@collectivexyz/protocol-rewards/src/RevolutionProtocolRewards.sol";
import { RevolutionBuilderTypesV1 } from "../src/builder/types/RevolutionBuilderTypesV1.sol";

import { ERC1967Proxy } from "../src/libs/proxy/ERC1967Proxy.sol";
import { MockERC721 } from "./mock/MockERC721.sol";
import { MockERC1155 } from "./mock/MockERC1155.sol";
import { MockWETH } from "./mock/MockWETH.sol";

contract RevolutionBuilderTest is Test {
    ///                                                          ///
    ///                          BASE SETUP                      ///
    ///                                                          ///

    IRevolutionBuilder internal manager;

    address internal managerImpl0;
    address internal managerImpl;
    address internal erc721TokenImpl;
    address internal descriptorImpl;
    address internal auctionImpl;
    address internal executorImpl;
    address internal daoImpl;
    address internal erc20TokenImpl;
    address internal erc20TokenEmitterImpl;
    address internal cultureIndexImpl;
    address internal maxHeapImpl;

    address internal nounsDAO;
    address internal revolutionDAO;
    address internal creatorsAddress;
    address internal founder;
    address internal founder2;
    address internal weth;
    address internal protocolRewards;
    address internal vrgdac;

    MockERC721 internal mock721;
    MockERC1155 internal mock1155;

    function setUp() public virtual {
        weth = address(new MockWETH());

        mock721 = new MockERC721();
        mock1155 = new MockERC1155();

        nounsDAO = vm.addr(0xA11CE);
        revolutionDAO = vm.addr(0xB0B);

        protocolRewards = address(new RevolutionProtocolRewards());

        founder = vm.addr(0xCAB);
        founder2 = vm.addr(0xDAD);

        creatorsAddress = vm.addr(0xCAFEBABE);

        vm.label(revolutionDAO, "REVOLUTION_DAO");
        vm.label(nounsDAO, "NOUNS_DAO");

        vm.label(founder, "FOUNDER");
        vm.label(founder2, "FOUNDER_2");

        managerImpl0 = address(
            new RevolutionBuilder(
                address(0),
                address(0),
                address(0),
                address(0),
                address(0),
                address(0),
                address(0),
                address(0),
                address(0)
            )
        );
        manager = RevolutionBuilder(
            address(new ERC1967Proxy(managerImpl0, abi.encodeWithSignature("initialize(address)", revolutionDAO)))
        );

        erc721TokenImpl = address(new VerbsToken(address(manager)));
        descriptorImpl = address(new Descriptor(address(manager)));
        auctionImpl = address(new AuctionHouse(address(manager)));
        executorImpl = address(new DAOExecutor(address(manager)));
        daoImpl = address(new VerbsDAOLogicV1(address(manager)));
        erc20TokenImpl = address(new NontransferableERC20Votes(address(manager)));
        erc20TokenEmitterImpl = address(
            new ERC20TokenEmitter(address(manager), address(protocolRewards), revolutionDAO)
        );
        cultureIndexImpl = address(new CultureIndex(address(manager)));
        maxHeapImpl = address(new MaxHeap(address(manager)));

        managerImpl = address(
            new RevolutionBuilder(
                erc721TokenImpl,
                descriptorImpl,
                auctionImpl,
                executorImpl,
                daoImpl,
                cultureIndexImpl,
                erc20TokenImpl,
                erc20TokenEmitterImpl,
                maxHeapImpl
            )
        );

        vm.prank(revolutionDAO);
        manager.upgradeTo(managerImpl);
    }

    ///                                                          ///
    ///                     DAO CUSTOMIZATION UTILS              ///
    ///                                                          ///

    IRevolutionBuilder.ERC721TokenParams internal erc721TokenParams;
    IRevolutionBuilder.AuctionParams internal auctionParams;
    IRevolutionBuilder.GovParams internal govParams;
    IRevolutionBuilder.CultureIndexParams internal cultureIndexParams;
    IRevolutionBuilder.ERC20TokenParams internal erc20TokenParams;
    IRevolutionBuilder.ERC20TokenEmitterParams internal erc20TokenEmitterParams;

    function setMockERC721TokenParams() internal virtual {
        setERC721TokenParams("Mock Token", "MOCK", "Qmew7TdyGnj6YRUjQR68sUJN3239MYXRD8uxowxF6rGK8j", "Mock");
    }

    function setERC721TokenParams(
        string memory _name,
        string memory _symbol,
        string memory _contractURI,
        string memory _tokenNamePrefix
    ) internal virtual {
        erc721TokenParams = IRevolutionBuilder.ERC721TokenParams({
            name: _name,
            symbol: _symbol,
            contractURIHash: _contractURI,
            tokenNamePrefix: _tokenNamePrefix
        });
    }

    function setMockAuctionParams() internal virtual {
        setAuctionParams(15 minutes, 1 ether, 24 hours, 5, 1000, 1000, 1000);
    }

    function setAuctionParams(
        uint256 _timeBuffer,
        uint256 _reservePrice,
        uint256 _duration,
        uint8 _minBidIncrementPercentage,
        uint256 _creatorRateBps,
        uint256 _entropyRateBps,
        uint256 _minCreatorRateBps
    ) internal virtual {
        auctionParams = IRevolutionBuilder.AuctionParams({
            timeBuffer: _timeBuffer,
            reservePrice: _reservePrice,
            duration: _duration,
            minBidIncrementPercentage: _minBidIncrementPercentage,
            creatorRateBps: _creatorRateBps,
            entropyRateBps: _entropyRateBps,
            minCreatorRateBps: _minCreatorRateBps
        });
    }

    function setMockGovParams() internal virtual {
        setGovParams(2 days, 1 seconds, 1 weeks, 50, founder, 100, 1000, 0, 1000, "Vrbs DAO");
    }

    function setGovParams(
        uint256 _timelockDelay,
        uint256 _votingDelay,
        uint256 _votingPeriod,
        uint256 proposalThresholdBPS,
        address _vetoer,
        uint256 _erc721VotingTokenWeight,
        uint16 minQuorumVotesBPS,
        uint16 maxQuorumVotesBPS,
        uint16 quorumCoefficient,
        string memory _daoName
    ) internal virtual {
        govParams = IRevolutionBuilder.GovParams({
            timelockDelay: _timelockDelay,
            votingDelay: _votingDelay,
            votingPeriod: _votingPeriod,
            proposalThresholdBPS: proposalThresholdBPS,
            vetoer: _vetoer,
            erc721TokenVotingWeight: _erc721VotingTokenWeight,
            dynamicQuorumParams: VerbsDAOStorageV1.DynamicQuorumParams({
                minQuorumVotesBPS: minQuorumVotesBPS,
                maxQuorumVotesBPS: maxQuorumVotesBPS,
                quorumCoefficient: quorumCoefficient
            }),
            daoName: _daoName
        });
    }

    function setMockCultureIndexParams() internal virtual {
        setCultureIndexParams("Vrbs", "Our community Vrbs. Must be 32x32.", 100, 1000, 0);
    }

    function setCultureIndexParams(
        string memory _name,
        string memory _description,
        uint256 _erc721VotingTokenWeight,
        uint256 _quorumVotesBPS,
        uint256 _minVoteWeight
    ) internal virtual {
        cultureIndexParams = IRevolutionBuilder.CultureIndexParams({
            name: _name,
            description: _description,
            erc721VotingTokenWeight: _erc721VotingTokenWeight,
            quorumVotesBPS: _quorumVotesBPS,
            minVoteWeight: _minVoteWeight
        });
    }

    function setMockERC20TokenParams() internal virtual {
        setERC20TokenParams("Mock Token", "MOCK");
    }

    function setERC20TokenParams(string memory _name, string memory _symbol) internal virtual {
        erc20TokenParams = IRevolutionBuilder.ERC20TokenParams({ name: _name, symbol: _symbol });
    }

    function setMockERC20TokenEmitterParams() internal virtual {
        setERC20TokenEmitterParams(1 ether, 1e18 / 10, 1_000 * 1e18, creatorsAddress);
    }

    function setERC20TokenEmitterParams(
        int256 _targetPrice,
        int256 _priceDecayPercent,
        int256 _tokensPerTimeUnit,
        address _creatorsAddress
    ) internal virtual {
        erc20TokenEmitterParams = IRevolutionBuilder.ERC20TokenEmitterParams({
            targetPrice: _targetPrice,
            priceDecayPercent: _priceDecayPercent,
            tokensPerTimeUnit: _tokensPerTimeUnit,
            creatorsAddress: _creatorsAddress
        });
    }

    ///                                                          ///
    ///                       DAO DEPLOY UTILS                   ///
    ///                                                          ///

    VerbsToken internal erc721Token;
    Descriptor internal descriptor;
    AuctionHouse internal auction;
    DAOExecutor internal executor;
    VerbsDAOLogicV1 internal dao;
    CultureIndex internal cultureIndex;
    NontransferableERC20Votes internal erc20Token;
    ERC20TokenEmitter internal erc20TokenEmitter;
    MaxHeap internal maxHeap;

    function setMockParams() internal virtual {
        setMockERC721TokenParams();
        setMockAuctionParams();
        setMockGovParams();
        setMockCultureIndexParams();
        setMockERC20TokenParams();
        setMockERC20TokenEmitterParams();
    }

    function deployMock() internal virtual {
        deploy(
            founder,
            weth,
            erc721TokenParams,
            auctionParams,
            govParams,
            cultureIndexParams,
            erc20TokenParams,
            erc20TokenEmitterParams
        );
    }

    function deploy(
        address _initialOwner,
        address _weth,
        IRevolutionBuilder.ERC721TokenParams memory _ERC721TokenParams,
        IRevolutionBuilder.AuctionParams memory _auctionParams,
        IRevolutionBuilder.GovParams memory _govParams,
        IRevolutionBuilder.CultureIndexParams memory _cultureIndexParams,
        IRevolutionBuilder.ERC20TokenParams memory _ERC20TokenParams,
        IRevolutionBuilder.ERC20TokenEmitterParams memory _ERC20TokenEmitterParams
    ) internal virtual {
        RevolutionBuilderTypesV1.DAOAddresses memory _addresses = manager.deploy(
            _initialOwner,
            _weth,
            _ERC721TokenParams,
            _auctionParams,
            _govParams,
            _cultureIndexParams,
            _ERC20TokenParams,
            _ERC20TokenEmitterParams
        );

        erc721Token = VerbsToken(_addresses.erc721Token);
        descriptor = Descriptor(_addresses.descriptor);
        auction = AuctionHouse(_addresses.auction);
        executor = DAOExecutor(payable(_addresses.executor));
        dao = VerbsDAOLogicV1(payable(_addresses.dao));
        cultureIndex = CultureIndex(_addresses.cultureIndex);
        erc20Token = NontransferableERC20Votes(_addresses.erc20Token);
        erc20TokenEmitter = ERC20TokenEmitter(_addresses.erc20TokenEmitter);
        maxHeap = MaxHeap(_addresses.maxHeap);

        vm.label(address(erc721Token), "ERC721TOKEN");
        vm.label(address(descriptor), "DESCRIPTOR");
        vm.label(address(auction), "AUCTION");
        vm.label(address(executor), "EXECUTOR");
        vm.label(address(dao), "DAO");
        vm.label(address(cultureIndex), "CULTURE_INDEX");
        vm.label(address(erc20Token), "ERC20TOKEN");
        vm.label(address(erc20TokenEmitter), "ERC20TOKEN_EMITTER");
        vm.label(address(maxHeap), "MAX_HEAP");
    }

    ///                                                          ///
    ///                           USER UTILS                     ///
    ///                                                          ///

    function createUser(uint256 _privateKey) internal virtual returns (address) {
        return vm.addr(_privateKey);
    }

    address[] internal otherUsers;

    function createUsers(uint256 _numUsers, uint256 _balance) internal virtual {
        otherUsers = new address[](_numUsers);

        unchecked {
            for (uint256 i; i < _numUsers; ++i) {
                address user = vm.addr(i + 1);

                vm.deal(user, _balance);

                otherUsers[i] = user;
            }
        }
    }

    function createTokens(uint256 _numTokens) internal {
        uint256 reservePrice = auction.reservePrice();
        uint256 duration = auction.duration();

        unchecked {
            for (uint256 i; i < _numTokens; ++i) {
                (uint256 tokenId, , , , , ) = auction.auction();

                vm.prank(otherUsers[i]);
                auction.createBid{ value: reservePrice }(tokenId, otherUsers[i]);

                vm.warp(block.timestamp + duration);

                auction.settleCurrentAndCreateNewAuction();
            }
        }
    }

    function createVoters(uint256 _numVoters, uint256 _balance) internal {
        createUsers(_numVoters, _balance);

        createTokens(_numVoters);
    }
}
