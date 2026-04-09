// SPDX-License-Identifier: MIT
// Vulnerability: AccessControl
// File: VULNERABLE version — shows the bug clearly
// ══════════════════════════════════════════════════
// ❌ DO NOT USE IN PRODUCTION — This contract is intentionally broken
// ══════════════════════════════════════════════════
pragma solidity ^0.8.28;

/// @title VulnerableAccessControl
/// @notice Demonstrates the AccessControl vulnerability pattern
/// @dev This is the BROKEN version. See SafeAccessControl.sol for the fix.
contract VulnerableAccessControl {

    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // ❌ BUG IS HERE — update this with the real vulnerability
    // TODO: Implement the specific AccessControl vulnerability
    function withdraw() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "Nothing to withdraw");

        // BUG: External call happens BEFORE state update
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "Transfer failed");

        balances[msg.sender] = 0; // too late — attacker already re-entered
    }

    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}
