// SPDX-License-Identifier: MIT
// Vulnerability: OracleManipulation
// File: SAFE version -- shows the correct fix
// =============================================
// FIX: replace spot price with TWAP oracle
// A flash loan lasts one block (~12 seconds)
// A TWAP averages price over many blocks
// One block cannot move the average enough to matter
// =============================================
pragma solidity ^0.8.28;

import "./VulnerableOracleManipulation.sol";

/// @notice TWAP oracle -- accumulates price over time, not susceptible to
///         single-block manipulation
contract TWAPOracle {

    SpotPriceAMM public amm;

    uint256 public priceAccumulator;
    uint256 public lastPrice;
    uint256 public lastTimestamp;
    // Tracks when this oracle was deployed so getPrice() can measure total
    // elapsed time across the full accumulation window -- not just time since
    // the most recent update() call, which would revert to zero after every
    // snapshot and make the window check meaningless.
    uint256 public deployTimestamp;

    // 30 minutes -- a flash loan lasts one block (~12 seconds)
    // one block cannot move a 30-minute average significantly
    uint256 constant WINDOW = 30 minutes;

    constructor(address _amm) {
        amm             = SpotPriceAMM(_amm);
        lastTimestamp   = block.timestamp;
        deployTimestamp = block.timestamp;
        lastPrice       = amm.getPrice();
    }

    function update() external {
        uint256 elapsed = block.timestamp - lastTimestamp;
        priceAccumulator += lastPrice * elapsed;
        lastTimestamp     = block.timestamp;
        lastPrice         = amm.getPrice();
    }

    // ✅ FIX: returns time-weighted average -- single block cannot move it.
    //
    // The key fix vs the buggy version:
    //   WRONG: elapsed = block.timestamp - lastTimestamp
    //          After update() sets lastTimestamp = now, elapsed = 0, so
    //          getPrice() always reverts immediately after any update() call.
    //   RIGHT: totalElapsed = block.timestamp - deployTimestamp
    //          This measures the full window since oracle birth, regardless of
    //          when update() was last called. The pending slice (time since last
    //          update) is added on top of the already-accumulated data and the
    //          two together are divided by the full window length.
    function getPrice() external view returns (uint256) {
        uint256 totalElapsed = block.timestamp - deployTimestamp;
        require(totalElapsed >= WINDOW, "TWAP window not elapsed");
        uint256 pendingElapsed = block.timestamp - lastTimestamp;
        uint256 total = priceAccumulator + lastPrice * pendingElapsed;
        return total / totalElapsed;
    }

    function spotPrice() external view returns (uint256) {
        return amm.getPrice();
    }

}

/// @notice Safe lending vault -- uses TWAP instead of spot price
contract SafeOracleManipulation {

    TWAPOracle public oracle;

    uint256 constant LTV = 75;

    struct Loan {
        uint256 collateralETH;
        uint256 borrowedTokens;
    }

    mapping(address => Loan) public loans;
    uint256 public tokenReserve;

    event Borrowed(address indexed who, uint256 collateral, uint256 tokens);

    constructor(address _oracle, uint256 _tokenReserve) {
        oracle       = TWAPOracle(_oracle);
        tokenReserve = _tokenReserve;
    }

    function depositCollateral() external payable {
        loans[msg.sender].collateralETH += msg.value;
    }

    // ✅ FIX: reads TWAP -- cannot be moved by a single flash loan transaction
    function borrow(uint256 tokenAmount) external {
        Loan storage loan = loans[msg.sender];
        require(loan.collateralETH > 0, "no collateral");
        require(tokenAmount <= tokenReserve, "insufficient reserves");

        // ✅ TWAP price -- averaged over 30 minutes
        // a flash loan manipulates price for one block out of ~150 blocks
        // its effect on the TWAP is less than 1%
        uint256 price              = oracle.getPrice();
        uint256 collateralInTokens = (loan.collateralETH * price) / 1e18;
        uint256 maxBorrow          = (collateralInTokens * LTV) / 100;

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
        uint256 price              = oracle.getPrice();
        uint256 collateralInTokens = (loan.collateralETH * price) / 1e18;
        return loan.borrowedTokens <= (collateralInTokens * LTV) / 100;
    }

    function getReserve() public view returns (uint256) {
        return tokenReserve;
    }

    receive() external payable {}

}
