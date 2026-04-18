// SPDX-License-Identifier: MIT
// Vulnerability: Delegatecall
// File: SAFE version — shows the correct fix
// ══════════════════════════════════════════════════
// ✅ Two fixes shown:
//    Fix 1 — EIP-1967: store implementation at a pseudorandom slot
//             far from slot 0 — no collision with any logic variable
//    Fix 2 — aligned storage: proxy and logic share the same layout
// ══════════════════════════════════════════════════
pragma solidity ^0.8.28;

// ─────────────────────────────────────────────────────────────────────────────
// FIX 1 — EIP-1967 STORAGE SLOT
//
// Instead of storing the implementation address at slot 1 (where logic
// variables can collide), store it at:
//
//   bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1)
//
// This is a 32-byte pseudorandom value — effectively impossible to collide
// with any variable a developer would declare at the top of a contract.
// OpenZeppelin's TransparentUpgradeableProxy and UUPS use this exact slot.
//
// FIX 2 — ALIGNED STORAGE LAYOUT
//
// Proxy and logic share the same base storage struct in the right order.
// If slot 0 is owner in the proxy, slot 0 must ALSO be owner in the logic.
// OpenZeppelin enforces this with storage gap arrays in upgradeable contracts.
// ─────────────────────────────────────────────────────────────────────────────

/// @notice Safe logic contract — storage layout matches the proxy exactly
/// @dev slot 0 = owner in BOTH contracts — no collision possible
contract SafeLogicContract {

    // ✅ FIX 2: slot 0 declared identically to the proxy
    // "owner" here maps to "owner" in the proxy — intentional, not a collision
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    // owner functions are safe because slot 0 is MEANT to be owner in both
    // note: msg.sender here is preserved from the original caller
    // so only the real owner can call this via the proxy's execute()
    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0), "zero address");
        owner = newOwner; // writes slot 0 — intentionally matches proxy layout
    }

}

/// @notice Safe vault proxy using EIP-1967 implementation slot
/// @dev implementation address stored at pseudorandom slot — no collision risk
contract SafeDelegatecall {

    // ✅ FIX 2: slot 0 = owner, same as SafeLogicContract
    address public owner;

    // ✅ FIX 1: implementation stored at EIP-1967 slot — NOT at slot 1
    // computed as: keccak256("eip1967.proxy.implementation") - 1
    bytes32 private constant IMPL_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    uint256 public funds;

    constructor(address _logic) payable {
        owner = msg.sender;
        funds = msg.value;
        _setImplementation(_logic);
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    // ✅ FIX 1: reads implementation from the EIP-1967 slot
    function implementation() public view returns (address impl) {
        assembly {
            impl := sload(IMPL_SLOT)
        }
    }

    // ✅ FIX 1: writes implementation to the EIP-1967 slot
    function _setImplementation(address _impl) internal {
        assembly {
            sstore(IMPL_SLOT, _impl)
        }
    }

    // ✅ FIX: only owner can call execute — not arbitrary callers
    // also: the logic contract's layout is aligned so any slot writes
    // land on the right variables
    function execute(bytes calldata data) external onlyOwner {
        (bool ok,) = implementation().delegatecall(data);
        require(ok, "delegatecall failed");
    }

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
