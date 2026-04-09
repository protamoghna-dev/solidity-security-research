// SPDX-License-Identifier: MIT
// Vulnerability: AccessControl
// File: SAFE version — shows the correct fix
// ══════════════════════════════════════════════════
// ✅ This is the FIXED version using CEI pattern
// ══════════════════════════════════════════════════
pragma solidity ^0.8.28;

/// @title SafeAccessControl
/// @notice The fixed version of VulnerableAccessControl.sol
/// @dev Uses CEI (Checks-Effects-Interactions) pattern
contract SafeAccessControl {

    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // ✅ FIX: State updated BEFORE external call (CEI pattern)
    function withdraw() public {
        // 1. CHECKS
        uint256 amount = balances[msg.sender];
        require(amount > 0, "Nothing to withdraw");

        // 2. EFFECTS — update state FIRST
        balances[msg.sender] = 0;

        // 3. INTERACTIONS — external call LAST
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "Transfer failed");
    }

    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}
