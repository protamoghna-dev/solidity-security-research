// SPDX-License-Identifier: MIT
// Vulnerability: IntegerOverflow
// File: VULNERABLE version — shows the bug clearly
// ══════════════════════════════════════════════════
// ❌ DO NOT USE IN PRODUCTION — This contract is intentionally broken
// ══════════════════════════════════════════════════

// ─────────────────────────────────────────────────────────────────────────────
// COMPILER NOTE: we stay on 0.8.28 and use unchecked{} blocks to reproduce
// the pre-0.8.0 wrap-around behaviour exactly.
// In the real 2017-2018 vulnerable contracts there was no unchecked{} —
// the entire compiler operated without overflow checks.
// unchecked{} is the 0.8.x equivalent: it disables the checks for that block
// and produces identical EVM bytecode to what 0.7.x emitted everywhere.
// ─────────────────────────────────────────────────────────────────────────────
pragma solidity ^0.8.28;

/// @title VulnerableIntegerOverflow
/// @notice Demonstrates pre-0.8.0 integer underflow on a token balance
/// @dev This is the BROKEN version. See SafeIntegerOverflow.sol for the fix.
contract VulnerableIntegerOverflow {

    mapping(address => uint256) public balances;
    uint256 public totalDeposits;

    function deposit() public payable {
        unchecked {
            balances[msg.sender] += msg.value;
            totalDeposits        += msg.value;
        }
    }

    // ❌ BUG IS HERE — underflow wraps balances[msg.sender] to 2^256 - 1
    //
    // Scenario: attacker has 0 balance. Calls transfer(victim, 1).
    // Step 1: require(0 >= 1) — this PASSES in 0.7.x because the subtraction
    //         on the next line runs first in storage and the wrapped value
    //         is what gets written. The require sees the pre-wrap value but
    //         the storage mutation already happened.
    //
    // Actually: require DOES check 0 >= 1 and would revert here.
    // The real attack path is when attacker has a tiny balance > 0:
    //
    // Scenario: attacker deposits 1 wei. balance = 1.
    // Calls transfer(victim, 2). require(1 >= 2) fails.
    //
    // The classic CaptureTheEther / TokenWhale underflow path:
    // transferFrom() is called with a different from address.
    // balances[from] -= amount wraps because from has 0 balance.
    // The attacker's own balance is untouched — they used someone else's slot.
    //
    // We recreate that pattern below:
    function transfer(address to, uint256 amount) public {
        require(balances[msg.sender] >= amount, "insufficient balance");
        unchecked {
            balances[msg.sender] -= amount;
            balances[to]         += amount;
        }
    }

    // ❌ BUG: no allowance check on `from` — and no underflow protection
    // If `from` has 0 balance, balances[from] -= amount wraps to 2^256 - 1
    // The attacker's own balance is never touched.
    // They call approve(attacker, amount) on themselves, then call
    // transferFrom(zeroBalanceAddress, attacker, amount).
    // zeroBalanceAddress wraps to max uint256.
    // Attacker now has `amount` extra tokens from nothing.
    function transferFrom(address from, address to, uint256 amount) public {
        // ❌ missing: require(balances[from] >= amount)
        // ❌ missing: allowance check
        unchecked {
            balances[from] -= amount;  // wraps to 2^256 - 1 when from has 0 balance
            balances[to]   += amount;
        }
    }

    // ❌ overflow path: large multiplication wraps to a small number
    // points = 2^128, multiplier = 2^128 → result = 0
    // user expects a huge reward but gets nothing
    function claimReward(uint256 points, uint256 multiplier) public pure returns (uint256 result) {
        unchecked { result = points * multiplier; }
    }

    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }

    receive() external payable {}

}
