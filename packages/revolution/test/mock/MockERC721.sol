// SPDX-License-Identifier: MIT
pragma solidity 0.8.22;

import { ERC721 } from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract MockERC721 is ERC721, UUPSUpgradeable {
    constructor() ERC721("Mock NFT", "MOCK") {}

    function mint(address _to, uint256 _tokenId) public {
        _mint(_to, _tokenId);
    }

    function _authorizeUpgrade(address) internal virtual override {
        // no-op
    }
}
