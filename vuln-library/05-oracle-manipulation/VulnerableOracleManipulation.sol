// SPDX-License-Identifier: MIT
// Vulnerability: OracleManipulation
// File: VULNERABLE version -- shows the bug clearly
// =============================================
// DO NOT USE IN PRODUCTION -- This contract is intentionally broken
// =============================================
pragma solidity ^0.8.28;

// ---------------------------------------------------------------------------
// THE BUG: a lending contract reads the spot price from an AMM to decide
// how much a borrower can take. Spot price = current reserve ratio.
// A flash loan gives an attacker unlimited capital for one transaction.
// They move the reserves, ask for a loan at the manipulated price, then
// unwind. The lender is left with an undercollateralized position.
//
// Real examples: bZx Feb 2020 ($350k), Harvest Oct 2020 ($34M),
//                Cream Finance Oct 2021 ($130M)
// ---------------------------------------------------------------------------

/// @notice Spot price AMM -- price = reserveB / reserveA
/// @dev x * y = k constant product, no fees for simplicity
contract SpotPriceAMM {

    uint256 public reserveETH;
    uint256 public reserveToken;

    constructor(uint256 _eth, uint256 _token) {
        reserveETH   = _eth;
        reserveToken = _token;
    }

    // ❌ BUG SOURCE: returns the live reserve ratio right now
    // this number changes with every trade -- manipulable in one tx
    function getPrice() public view returns (uint256 tokenPerETH) {
        return (reserveToken * 1e18) / reserveETH;
    }

    function swapETHforToken(uint256 ethIn) external returns (uint256 tokenOut) {
        uint256 k   = reserveETH * reserveToken;
        tokenOut    = reserveToken - k / (reserveETH + ethIn);
        reserveETH  += ethIn;
        reserveToken -= tokenOut;
    }

    function swapTokenforETH(uint256 tokenIn) external returns (uint256 ethOut) {
        uint256 k   = reserveETH * reserveToken;
        ethOut      = reserveETH - k / (reserveToken + tokenIn);
        reserveToken += tokenIn;
        reserveETH   -= ethOut;
    }

}

/// @notice Lending vault that trusts the AMM spot price for collateral valuation
contract VulnerableOracleManipulation {

    SpotPriceAMM public amm;

    // loan-to-value: borrow up to 75% of collateral value
    uint256 constant LTV = 75;

    struct Loan {
        uint256 collateralETH;
        uint256 borrowedTokens;
    }

    mapping(address => Loan) public loans;
    uint256 public tokenReserve;

    event Borrowed(address indexed who, uint256 collateral, uint256 tokens);
    event Repaid(address indexed who, uint256 tokens);

    constructor(address _amm, uint256 _tokenReserve) {
        amm          = SpotPriceAMM(_amm);
        tokenReserve = _tokenReserve;
    }

    function depositCollateral() external payable {
        loans[msg.sender].collateralETH += msg.value;
    }

    // ❌ BUG IS HERE
    // reads amm.getPrice() to value the borrower's ETH collateral in tokens
    // if the attacker pumped the token price UP before calling this,
    // their ETH appears worth more tokens than it really is
    // they borrow more than their real collateral can cover
    // when the price reverts, the loan is undercollateralized
    function borrow(uint256 tokenAmount) external {
        Loan storage loan = loans[msg.sender];
        require(loan.collateralETH > 0, "no collateral");
        require(tokenAmount <= tokenReserve, "insufficient reserves");

        // ❌ spot price read -- manipulable in the same transaction
        uint256 price = amm.getPrice(); // tokens per ETH (scaled 1e18)

        // collateral value in tokens at current (possibly manipulated) price
        uint256 collateralInTokens = (loan.collateralETH * price) / 1e18;

        // max borrow = collateral value * LTV / 100
        uint256 maxBorrow = (collateralInTokens * LTV) / 100;

        require(
            loan.borrowedTokens + tokenAmount <= maxBorrow,
            "undercollateralized"
        );

        loan.borrowedTokens += tokenAmount;
        tokenReserve        -= tokenAmount;

        emit Borrowed(msg.sender, loan.collateralETH, tokenAmount);
    }

    function isSolvent(address who) public view returns (bool) {
        Loan storage loan = loans[who];
        if (loan.borrowedTokens == 0) return true;
        uint256 price             = amm.getPrice();
        uint256 collateralInTokens = (loan.collateralETH * price) / 1e18;
        return loan.borrowedTokens <= (collateralInTokens * LTV) / 100;
    }

    function getReserve() public view returns (uint256) {
        return tokenReserve;
    }

    receive() external payable {}

}
