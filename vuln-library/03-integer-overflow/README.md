# Integer Overflow

**Pattern:** Pre-0.8.0 wrap-around — SafeMath history

## The Bug

Before Solidity 0.8.0, all arithmetic silently wrapped around. There were
no built-in overflow or underflow checks. The EVM operates on 256-bit
unsigned integers. If you add 1 to the maximum value (2^256 - 1), the
result wraps to 0. If you subtract 1 from 0, the result wraps to 2^256 - 1.
No error. No revert. The computation just continues with the wrong number.

The most dangerous version is the underflow on a balance mapping. If an
attacker can cause `balances[from] -= amount` to run when `balances[from]`
is 0, the storage slot becomes 2^256 - 1. That address now appears to hold
an astronomically large token balance. From nothing.

The real attack vector here is the unprotected `transferFrom`:

```solidity
// ❌ WRONG — no require check on from's balance
function transferFrom(address from, address to, uint256 amount) public {
    balances[from] -= amount;   // wraps to 2^256-1 when from has 0 balance
    balances[to]   += amount;
}
```

The attacker passes any zero-balance address as `from`. The subtraction
wraps. Their own balance gets credited the amount. They created tokens
from nothing. If a withdraw function exists, they drain the vault.

## The Fix

```solidity
// ✅ CORRECT — explicit check + Solidity 0.8.x handles the rest
function transferFrom(address from, address to, uint256 amount) public {
    require(balances[from] >= amount, "insufficient balance");
    require(allowances[from][msg.sender] >= amount, "not approved");
    allowances[from][msg.sender] -= amount;
    balances[from]               -= amount;
    balances[to]                 += amount;
}
```

There are two fixes layered here. First, upgrade to Solidity 0.8.x.
The compiler adds overflow checks to every arithmetic operation automatically.
Any underflow will revert before the storage is written. Second, add
explicit `require` statements even under 0.8.x — they document the
invariant clearly and give a readable error message instead of a raw revert.

The historical fix before 0.8.0 was OpenZeppelin's SafeMath library:

```solidity
using SafeMath for uint256;
balances[from] = balances[from].sub(amount); // reverts on underflow
```

SafeMath wrapped every arithmetic operation in a function that checked
the result and reverted if it was wrong. It was a gas overhead on every
operation. When 0.8.0 shipped those checks at the compiler level, SafeMath
became unnecessary and most projects dropped it.

## Proof

```bash
forge test --match-path 'vuln-library/03-integer-overflow/**' -vv
```

## Real-World Examples

- BatchOverflow / BEC token (April 2018) — batchTransfer() multiplied
  value by number of recipients without overflow check. value * 2 wrapped
  to 0, bypassing the balance check. Attackers received billions of tokens.
  Trading was halted on major exchanges within hours.

- SmartMesh (SMT) token — same month, same bug, different token.
  An attacker transferred 57896044618658097711785492504343953926634992332820282019728792003956564819968
  tokens to two addresses. That number is 2^255. It was minted from nothing.

- TokenWhale (Capture The Ether) — the classic CTF challenge built on
  this exact underflow pattern in the transferFrom function.

## Lesson

> Before 0.8.0: always use SafeMath or check subtraction results manually.
> After 0.8.0: upgrade your pragma. The compiler does it for you.
> Always add explicit require checks anyway — they are documentation.

## The SafeMath history

2016 — ConsenSys released SafeMath as part of Zeppelin (now OpenZeppelin).
       Every serious token contract started importing and using it.

2017-2019 — Every new token had `using SafeMath for uint256`. It was
            considered mandatory. It added gas cost to every arithmetic op.

2020 — Solidity 0.8.0 shipped. Built-in overflow checks at zero extra
       gas compared to the assembly Solidity itself uses. SafeMath became
       legacy overnight.

2021+ — New contracts use 0.8.x. Old contracts pre-0.8.0 are still live
        on mainnet with real value in them. Auditors check the pragma
        version immediately — if it is below 0.8.0, every arithmetic
        operation is a suspect.