// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

interface ITokenEmitter {
    function buyToken(address[] memory _addresses, uint[] memory _bps, address builder, address purchaseReferral, address deployer) external payable returns (uint);

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
