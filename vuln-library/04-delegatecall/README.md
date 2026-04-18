# Delegatecall

**Pattern:** Storage collision — proxy context abuse

## The Bug

`delegatecall` executes code from another contract but runs it in the
calling contract's storage. The EVM does not know variable names. It only
knows slot numbers. Slot 0 is slot 0 regardless of what the developer
called the variable that lives there.

The bug happens when a proxy contract and its logic contract have different
storage layouts. The proxy stores its owner at slot 0. The logic contract
stores a different variable — say logicOwner — also at slot 0. When the
proxy delegatecalls the logic contract and the logic contract writes to
logicOwner, it is actually writing to slot 0 in the proxy's storage. That
slot is owner. The attacker just became the owner.

```solidity
// ❌ WRONG — misaligned layouts

// Proxy:
address public owner;     // slot 0
address public logic;     // slot 1

// LogicContract:
address public logicOwner; // slot 0 ← collides with proxy.owner

// When proxy.delegatecall(logic.pwn(attacker)):
// logic writes slot 0 = attacker
// proxy.owner is now attacker
```

The variable names do not matter. The slot numbers are what the EVM reads
and writes. A developer can name their variable anything they like — if it
is the first declaration in the contract it occupies slot 0 and it will
collide with every other first-declaration in every other contract that
delegatecalls into it.

## The Fix

```solidity
// ✅ Fix 1 — EIP-1967: store implementation at a pseudorandom slot
bytes32 private constant IMPL_SLOT =
    0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
// keccak256("eip1967.proxy.implementation") - 1
// No variable a developer declares will ever land at this slot by accident

// ✅ Fix 2 — identical storage layout in proxy and logic
// Both contracts declare the same variables in the same order at the top
// slot 0 = owner in both → delegatecall writes to the right place
```

EIP-1967 is the production standard. All OpenZeppelin upgradeable proxies
use it. The implementation address is stored at a 32-byte hash value that
is essentially impossible to collide with. Logic variables start at slot 0
and the implementation pointer sits far away from them.

## Proof

```bash
forge test --match-path 'vuln-library/04-delegatecall/**' -vv
```

## Real-World Examples

- Parity Multisig November 2017 — a different wallet accidentally called
  initWallet on the shared WalletLibrary (which had no owner set). Then
  called kill() — selfdestruct. The delegatecall context meant the library
  itself was destroyed, freezing ~$150M across hundreds of wallets. The
  storage slots involved were the same class of problem: delegatecall
  running code in the wrong context.

- Audius 2022 ($6M) — a governance upgrade introduced a storage layout
  mismatch in the proxy. A variable that was supposed to be a governance
  delay was read from the wrong slot and returned zero. An attacker used
  the zero delay to pass a malicious governance proposal instantly.

- Ethernaut Level 6 (Delegation) — exact same pattern. The Delegate
  contract's owner at slot 0 collides with the Delegation proxy's owner
  at slot 0. Sending a pwn() call to the proxy via fallback() triggers
  the delegatecall and overwrites the proxy owner.

## Lesson

> Delegatecall executes someone else's code in your storage.
> Every storage write in that code hits your slots, not theirs.
> Slot numbers are what the EVM uses — not variable names.
> Use EIP-1967 slots for proxy admin variables. Always.
