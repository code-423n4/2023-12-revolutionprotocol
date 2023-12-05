// SPDX-License-Identifier: MIT
pragma solidity 0.8.22;

import { TokenEmitterRewards } from "../../src/abstract/TokenEmitter/TokenEmitterRewards.sol";
import { TokenEmitter, NontransferableERC20Votes } from "./TokenEmitterLibrary.sol";

contract MockTokenEmitter is TokenEmitter {
    constructor(
        address _initialOwner,
        NontransferableERC20Votes _token,
        address _treasury,
        address _protocolRewards,
        address _revolutionRewardRecipient
    ) TokenEmitter(_initialOwner, _token, _protocolRewards, _revolutionRewardRecipient, _treasury, 1e11, 1e17, 1e22) {
        treasury = _treasury;
    }
}
