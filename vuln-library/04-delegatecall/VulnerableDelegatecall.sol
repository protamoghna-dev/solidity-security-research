// SPDX-License-Identifier: MIT
// Vulnerability: Delegatecall
// File: VULNERABLE version — shows the bug clearly
// ══════════════════════════════════════════════════
// ❌ DO NOT USE IN PRODUCTION — This contract is intentionally broken
// ══════════════════════════════════════════════════
pragma solidity ^0.8.28;

// ─────────────────────────────────────────────────────────────────────────────
// HOW DELEGATECALL WORKS
//
// ContractA.delegatecall(ContractB.foo()) executes ContractB's code
// but inside ContractA's storage. Storage slots are numbered by declaration
// order starting at zero. If ContractB.foo() writes to "its" slot 0,
// it actually writes to ContractA's slot 0. The variable names do not
// matter — only the slot numbers do.
//
// THE BUG — STORAGE COLLISION:
//
//   VulnerableProxy storage layout:
//     slot 0: address owner       ← who controls this vault
//     slot 1: address logic       ← which logic contract to delegatecall
//     slot 2: uint256 funds       ← ETH balance tracking
//
//   LogicContract storage layout (as the developer imagined it):
//     slot 0: address logicOwner  ← developer put a different variable here
//
//   When VulnerableProxy.delegatecall(LogicContract.setOwner(attacker)):
//     LogicContract writes slot 0 = attacker
//     Slot 0 in PROXY storage = owner   ← collision
//     VulnerableProxy.owner is now the attacker
//
//   The developer named the variable "logicOwner" thinking it was separate
//   from the proxy's "owner". The EVM does not know variable names.
//   It only knows slot numbers.
// ─────────────────────────────────────────────────────────────────────────────

/// @notice Logic contract — the developer forgot to align storage with the proxy
/// @dev slot 0 here collides with slot 0 (owner) in VulnerableProxy
contract LogicContract {

    // ❌ BUG: developer declared a variable at slot 0 without realising
    // it maps to the same slot as `owner` in the proxy
    // any write to logicOwner via delegatecall overwrites proxy.owner
    address public logicOwner;

    // sets slot 0 in whatever context this runs in
    // when called via delegatecall from the proxy, slot 0 = proxy.owner
    function setOwner(address newOwner) public {
        logicOwner = newOwner; // ❌ writes proxy.owner, not logicOwner
    }

    // a "utility" function the developer added — also writes slot 0
    function pwn(address who) public {
        logicOwner = who; // ❌ same collision
    }

}

/// @notice Vault proxy that delegatecalls into LogicContract
/// @dev Storage layout is misaligned with LogicContract — slot 0 collision
contract VulnerableDelegatecall {

    // slot 0 — ❌ collides with LogicContract.logicOwner (also slot 0)
    address public owner;
    // slot 1
    address public logic;
    // slot 2
    uint256 public funds;

    constructor(address _logic) payable {
        owner  = msg.sender;
        logic  = _logic;
        funds  = msg.value;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    // ❌ BUG: exposes raw delegatecall to any selector from logic contract
    // any function in logic that writes slot 0 overwrites owner here
    function execute(bytes calldata data) external {
        (bool ok,) = logic.delegatecall(data);
        require(ok, "delegatecall failed");
    }

    // legitimate owner function — withdraw ETH
    function withdraw() external onlyOwner {
        uint256 amount = address(this).balance;
        funds = 0;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }

    function deposit() external payable {
        funds += msg.value;
    }

    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }

    receive() external payable {}

}
