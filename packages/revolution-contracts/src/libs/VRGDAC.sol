// SPDX-License-Identifier: MIT
pragma solidity 0.8.22;

import { wadExp, wadLn, wadMul, wadDiv, unsafeWadDiv, wadPow } from "./SignedWadMath.sol";

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
                                wadMul(targetPrice, wadMul(perTimeUnit, wadExp(wadMul(soldDifference, wadDiv(decayConstant, perTimeUnit))))),
                                wadMul(targetPrice, wadMul(perTimeUnit, wadPow(1e18 - priceDecayPercent, wadDiv(soldDifference, perTimeUnit)))) -
                                    wadMul(amount, decayConstant)
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
                    wadPow(1e18 - priceDecayPercent, timeSinceStart - unsafeWadDiv(sold, perTimeUnit)) - wadPow(1e18 - priceDecayPercent, timeSinceStart)
                ),
                decayConstant
            );
    }
}
