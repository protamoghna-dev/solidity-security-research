// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "./VulnerableReentrancy.sol";
import "./AttackerReentrancy.sol";
import "./SafeReentrancy.sol";

contract ReentrancyTest is Test {

    VulnerableReentrancy public vulnVault;
    AttackerReentrancy   public attacker;
    SafeReentrancy       public safeVault;

    address alice = makeAddr("alice");
    address bob   = makeAddr("bob");

    function setUp() public {
        vulnVault = new VulnerableReentrancy();
        attacker  = new AttackerReentrancy(address(vulnVault));
        safeVault = new SafeReentrancy();

        vm.deal(alice, 10 ether);
        vm.deal(bob,   10 ether);

        vm.prank(alice); vulnVault.deposit{value: 5 ether}();
        vm.prank(bob);   vulnVault.deposit{value: 5 ether}();
    }

    function test_AttackDrainsVulnerableVault() public {
        uint256 vaultBefore = vulnVault.getBalance();
        assertEq(vaultBefore, 10 ether);

        vm.deal(address(attacker), 1 ether);
        attacker.attack{value: 1 ether}();

        uint256 vaultAfter = vulnVault.getBalance();
        assertEq(vaultAfter, 0);
        assertGt(address(attacker).balance, 1 ether);

        console.log("Vault before:", vaultBefore);
        console.log("Vault after :", vaultAfter);
        console.log("Attacker bal:", address(attacker).balance);
    }

    function test_SafeVaultResistsAttack() public {
    vm.deal(alice, 5 ether);
    vm.prank(alice);
    safeVault.deposit{value: 5 ether}();

    assertEq(safeVault.getBalance(), 5 ether);

    vm.prank(alice);
    safeVault.withdraw();

    assertEq(safeVault.getBalance(), 0);
    assertEq(alice.balance, 5 ether);
}

    function test_SafeVaultCorrectBalance() public {
        vm.deal(alice, 3 ether);
        vm.prank(alice);
        safeVault.deposit{value: 3 ether}();
        assertEq(safeVault.balances(alice), 3 ether);
    }

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