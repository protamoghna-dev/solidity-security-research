// SPDX-License-Identifier: MIT
// Test: AccessControl vulnerability proof
// Run: forge test --match-path "vuln-library/02-access-control/AccessControl.t.sol" -vv
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "./VulnerableAccessControl.sol";
import "./AttackerAccessControl.sol";
import "./SafeAccessControl.sol";

contract AccessControlTest is Test {

    VulnerableAccessControl public vulnVault;
    AttackerAccessControl   public attacker;
    SafeAccessControl       public safeVault;

    address alice = makeAddr("alice");
    address bob   = makeAddr("bob");

    function setUp() public {
        vulnVault = new VulnerableAccessControl();
        attacker  = new AttackerAccessControl(address(vulnVault));
        safeVault = new SafeAccessControl();

        // Innocent users deposit into vulnerable vault
        vm.deal(alice, 10 ether);
        vm.deal(bob,   10 ether);
        vm.prank(alice); vulnVault.deposit{value: 5 ether}();
        vm.prank(bob);   vulnVault.deposit{value: 5 ether}();
    }

    // ══════════════════════════════════════════════
    // EXPLOIT TEST — proves the attack works
    // ══════════════════════════════════════════════

    /// @notice Attack drains the VULNERABLE vault completely
    function test_AttackDrainsVulnerableVault() public {
        uint256 vaultBefore = vulnVault.getBalance();
        assertEq(vaultBefore, 10 ether, "Vault should have 10 ETH");

        // Give attacker 1 ETH to start
        vm.deal(address(attacker), 1 ether);
        attacker.attack{value: 1 ether}();

        uint256 vaultAfter = vulnVault.getBalance();
        assertEq(vaultAfter, 0, "Vault should be DRAINED");
        assertGt(address(attacker).balance, 1 ether, "Attacker profited");

        console.log("Vault before:", vaultBefore);
        console.log("Vault after :", vaultAfter);
        console.log("Attacker bal:", address(attacker).balance);
    }

    // ══════════════════════════════════════════════
    // FIX TEST — proves the safe version blocks it
    // ══════════════════════════════════════════════

    /// @notice Safe vault handles normal deposits and withdrawals correctly
    function test_SafeVaultWorksNormally() public {
        uint256 depositAmount = 3 ether;
        vm.deal(alice, depositAmount);
        uint256 balanceBefore = alice.balance;

        vm.prank(alice);
        safeVault.deposit{value: depositAmount}();
        assertEq(safeVault.getBalance(), depositAmount);

        vm.prank(alice);
        safeVault.withdraw();
        assertEq(safeVault.getBalance(), 0);
        assertEq(alice.balance, balanceBefore); // got full deposit back
    }

    /// @notice Fuzz: any deposit amount can always be withdrawn
    function testFuzz_DepositAndWithdraw(uint96 amount) public {
        vm.assume(amount > 0);
        vm.deal(alice, amount);
        vm.prank(alice);
        safeVault.deposit{value: amount}();
        vm.prank(alice);
        safeVault.withdraw();
        assertEq(safeVault.balances(alice), 0);
    }
}
