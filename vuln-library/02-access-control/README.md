# AccessControl

**Pattern:** tx.origin vs msg.sender — ownership bypass

## The Bug

Show exactly what line causes the problem here.

```solidity
// ❌ WRONG — state updated AFTER external call
function withdraw() public {
    uint256 amount = balances[msg.sender];
    (bool ok,) = msg.sender.call{value: amount}(""); // call first
    balances[msg.sender] = 0; // update too late
}
```

## The Fix

```solidity
// ✅ CORRECT — CEI pattern
function withdraw() public {
    uint256 amount = balances[msg.sender];
    balances[msg.sender] = 0;                        // effect first
    (bool ok,) = msg.sender.call{value: amount}(""); // interact last
}
```

## Proof

```bash
forge test --match-path "vuln-library/02-access-control/AccessControl.t.sol" -vv
```

## Real-World Examples

- The DAO Hack 2016 — $60M lost to this exact pattern
- See: exploit-pocs/2016-the-dao/

## Lesson

> Always follow CEI: **C**hecks → **E**ffects → **I**nteractions.
> Update all state variables BEFORE making any external calls.
