// SPDX-License-Identifier: MIT
// Vulnerability: IntegerOverflow
// File: SAFE version — shows the correct fix
// ══════════════════════════════════════════════════
// ✅ Two fixes shown:
//    Fix 1 — upgrade to Solidity 0.8.x (built-in overflow checks)
//    Fix 2 — add explicit balance checks on transferFrom
// ══════════════════════════════════════════════════
pragma solidity ^0.8.28;

/// @title SafeIntegerOverflow
/// @notice The fixed version of VulnerableIntegerOverflow
/// @dev 0.8.x reverts on overflow/underflow automatically.
///      We also add the missing require check that transferFrom lacked.
contract SafeIntegerOverflow {

    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowances;
    uint256 public totalDeposits;

    function deposit() public payable {
        // ✅ 0.8.x: these additions revert automatically if they overflow
        balances[msg.sender] += msg.value;
        totalDeposits        += msg.value;
    }

    function transfer(address to, uint256 amount) public {
        // ✅ explicit check — also redundant under 0.8.x which would revert
        // on the subtraction anyway, but explicit checks are good documentation
        require(balances[msg.sender] >= amount, "insufficient balance");
        balances[msg.sender] -= amount;
        balances[to]         += amount;
    }

    function approve(address spender, uint256 amount) public {
        allowances[msg.sender][spender] = amount;
    }

    // ✅ FIX: explicit balance check AND allowance check before any mutation
    // Under 0.8.x the subtraction would revert anyway, but the require
    // gives a clear error message and documents the invariant for auditors
    function transferFrom(address from, address to, uint256 amount) public {
        // ✅ check 1: from must have enough balance
        require(balances[from] >= amount, "insufficient balance");
        // ✅ check 2: caller must be approved to move from's tokens
        require(allowances[from][msg.sender] >= amount, "not approved");

        allowances[from][msg.sender] -= amount;
        balances[from]               -= amount;
        balances[to]                 += amount;
    }

    // ✅ FIX: use SafeMath-style explicit check for multiplication
    // Under 0.8.x this reverts automatically — shown here for understanding
    function claimReward(uint256 points, uint256 multiplier) public pure returns (uint256) {
        // ✅ 0.8.x reverts if this overflows — no extra code needed
        return points * multiplier;
    }

    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }

    receive() external payable {}

}
