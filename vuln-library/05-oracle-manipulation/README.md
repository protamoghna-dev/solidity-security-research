# OracleManipulation

**Pattern:** Spot price oracle -- flash loan price attack

## The Bug

A lending protocol reads the current reserve ratio of an AMM to determine
how much a borrower can take against their collateral. Reserve ratio means
price. Price means reserveToken / reserveETH at this exact moment. That
number changes with every trade.

A flash loan gives an attacker unlimited capital for one transaction. If
they can spend that capital to shift the AMM reserves before calling the
lending function, the price the lender reads is wrong. The lender sees
inflated collateral value, allows an oversized loan, and the attacker
walks away with tokens that cost them nothing but a round-trip on the AMM.

```solidity
// WRONG -- reads live reserve ratio, manipulable in one tx
function borrow(uint256 tokenAmount) external {
    uint256 price = amm.getPrice(); // spot price -- moves with every trade
    uint256 collateralInTokens = (loan.collateralETH * price) / 1e18;
    uint256 maxBorrow = (collateralInTokens * LTV) / 100;
    require(loan.borrowedTokens + tokenAmount <= maxBorrow, "undercollateralized");
    // if price was pumped before this call, maxBorrow is wrong
}
```

The exact manipulation direction depends on what you want to achieve.
To make ETH collateral appear worth more tokens: sell tokens into the pool
(add tokens, remove ETH), which increases reserveToken and decreases
reserveETH, so price = reserveToken / reserveETH goes up. The lender now
thinks each ETH of collateral buys more tokens, so maxBorrow rises. The
attacker borrows more than their collateral can cover at the real price.

## The Fix

```solidity
// CORRECT -- TWAP averaged over 30 minutes, not the current moment
function getPrice() external view returns (uint256) {
    uint256 elapsed = block.timestamp - lastTimestamp;
    require(elapsed >= 30 minutes, "TWAP window not elapsed");
    uint256 total = priceAccumulator + lastPrice * elapsed;
    return total / elapsed;
}
```

A TWAP (Time-Weighted Average Price) accumulates price multiplied by time
elapsed. To read it, divide the total by the time window. A flash loan
lasts one block -- about 12 seconds. A 30-minute TWAP covers 1800 seconds.
The attacker's manipulation contributes 12 / 1800 = 0.67% of the window.
Even a 500% spot price move shifts the TWAP by less than 4%. That is not
enough to open a meaningfully oversized loan.

Uniswap v2 shipped on-chain TWAP accumulators in May 2020, three months
after the bZx attack proved why they were needed. Chainlink price feeds
are the other standard answer -- independent nodes with deviation checks
that require sustained real-market movement to shift the reported price.

## Proof

```bash
forge test --match-path 'vuln-library/05-oracle-manipulation/**' -vv
```

## Real-World Examples

- bZx February 2020 ($350k) -- studied on Day 10. Uniswap v1 spot price
  used to value collateral for a margin position. Flash loan pumped the
  price within the same transaction. First public flash loan attack.

- Harvest Finance October 2020 ($34M) -- Curve pool spot price used as
  oracle for USDC and USDT vaults. Attacker executed a seven-step sequence:
  flash loan, move Curve price, deposit into Harvest vault at inflated
  price, move price back, withdraw at real price. Repeated. $34M extracted.

- Cream Finance October 2021 ($130M) -- price oracle for yUSD manipulated
  via a flash loan. Largest oracle manipulation loss at the time.

- Mango Markets October 2022 ($114M on Solana) -- attacker held a large
  position, pumped the price of MNGO token on thin markets, borrowed
  against the inflated collateral value. Not an AMM spot price technically,
  but the same fundamental pattern: price is manipulable, lending trusts it.

## Lesson

> Spot price = manipulable in one transaction = never use as an oracle.
> The cost of manipulation is just the AMM spread plus flash loan fee.
> TWAP or Chainlink requires sustained real market movement across blocks.
> A flash loan cannot survive past the end of its transaction.
> The window for a TWAP must be longer than any single block -- 30 minutes
> is the standard minimum for lending protocols.