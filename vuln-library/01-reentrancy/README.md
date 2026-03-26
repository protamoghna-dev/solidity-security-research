# Reentrancy

## The bug

withdraw() sends ETH to the caller before zeroing their balance.
The attacker's receive() function calls withdraw() again before
the first call finishes. The balance is still the original amount
so the require passes. This repeats until the vault is empty.

## The exact bad line

balances[msg.sender] = 0 is on line 14 — AFTER the external call.
It should be BEFORE.

## The fix

Zero the balance first. Then send ETH. State change before external call.
This is called CEI: Checks → Effects → Interactions.

## What I ran

forge test --match-path 'vuln-library/01-reentrancy/**' -vv
4 passed. Vault drained in test_AttackDrainsVulnerableVault.

## Mistake I made

test_SafeVaultResistsAttack checked alice.balance against a wrong
expected value. Alice was given 10 ETH by vm.deal in setUp() but
the safeVault test gave her another 5 ETH making the assertion
wrong. Always track balances carefully in tests — off-by-one ETH
errors in tests hide real bugs.


## Date completed