// SPDX-License-Identifier: MIT
// Test: IntegerOverflow vulnerability proof
// Run: forge test --match-path 'vuln-library/03-integer-overflow/**' -vv
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "./VulnerableIntegerOverflow.sol";
import "./AttackerIntegerOverflow.sol";
import "./SafeIntegerOverflow.sol";

contract IntegerOverflowTest is Test {
    VulnerableIntegerOverflow public vuln;
    AttackerIntegerOverflow public attacker;
    SafeIntegerOverflow public safe;

    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    address empty = makeAddr("empty"); // address that never deposits — balance stays 0

    function setUp() public {
        vuln = new VulnerableIntegerOverflow();
        attacker = new AttackerIntegerOverflow(address(vuln));
        safe = new SafeIntegerOverflow();

        // alice and bob deposit into the vulnerable vault
        vm.deal(alice, 10 ether);
        vm.deal(bob, 10 ether);
        vm.prank(alice);
        vuln.deposit{value: 5 ether}();
        vm.prank(bob);
        vuln.deposit{value: 5 ether}();
    }

    // ══════════════════════════════════════════════
    // EXPLOIT TESTS — proves the attack works
    // ══════════════════════════════════════════════

    /// @notice underflow wraps a zero balance to 2^256 - 1
    function test_Underflow_WrapsZeroBalanceToMax() public {
        assertEq(
            vuln.balances(empty),
            0,
            "empty address should have 0 balance"
        );

        // transferFrom with empty as the from — 0 - 1 wraps inside unchecked{}
        vuln.transferFrom(empty, address(attacker), 1);

        assertEq(
            vuln.balances(empty),
            type(uint256).max,
            "balance wrapped to max uint256"
        );
        assertEq(
            vuln.balances(address(attacker)),
            1,
            "attacker credited 1 from nothing"
        );

        console.log("empty balance after underflow (should be max uint256):");
        console.log(vuln.balances(empty));
    }

    /// @notice attacker contract exploits transferFrom to claim free balance
    function test_AttackGivesAttackerFreeBalance() public {
        assertEq(
            vuln.balances(address(attacker)),
            0,
            "attacker starts with nothing"
        );

        attacker.attack(empty, 5 ether);

        assertEq(
            vuln.balances(address(attacker)),
            5 ether,
            "attacker has 5 ETH balance from nothing"
        );

        console.log(
            "Attacker stolen balance:",
            attacker.stolenBalance() / 1 ether,
            "units"
        );
    }

    /// @notice overflow: 2^128 * 2^128 wraps to 0 — user gets nothing
    function test_Overflow_MultiplicationWrapsToZero() public view {
        uint256 points = 2 ** 128;
        uint256 multiplier = 2 ** 128;
        uint256 result = vuln.claimReward(points, multiplier);
        assertEq(result, 0, "2^128 * 2^128 overflows back to 0");
        console.log("Expected huge reward, got:", result);
    }

    /// @notice normal transfer still requires sufficient balance
    function test_Transfer_RevertsWithoutBalance() public {
        vm.expectRevert("insufficient balance");
        vuln.transfer(alice, 1 ether);
    }

    // ══════════════════════════════════════════════
    // FIX TESTS — proves the safe version blocks it
    // ══════════════════════════════════════════════

    /// @notice 0.8.x checked arithmetic reverts on underflow automatically
    function test_Safe_TransferFrom_RevertsOnUnderflow() public {
        vm.expectRevert("insufficient balance");
        safe.transferFrom(empty, alice, 1);

        assertEq(safe.balances(alice), 0, "alice balance unchanged");
    }

    /// @notice safe version also enforces allowance
    function test_Safe_TransferFrom_RevertsWithoutAllowance() public {
        vm.deal(alice, 5 ether);
        vm.prank(alice);
        safe.deposit{value: 5 ether}();

        vm.prank(bob);
        vm.expectRevert("not approved");
        safe.transferFrom(alice, bob, 1 ether);
    }

    /// @notice legitimate approve + transferFrom works correctly on safe version
    function test_Safe_ApproveAndTransferFrom_Works() public {
        vm.deal(alice, 5 ether);
        vm.prank(alice);
        safe.deposit{value: 5 ether}();
        vm.prank(alice);
        safe.approve(bob, 2 ether);

        vm.prank(bob);
        safe.transferFrom(alice, bob, 2 ether);

        assertEq(safe.balances(alice), 3 ether);
        assertEq(safe.balances(bob), 2 ether);
    }

    /// @notice safe multiplication reverts on overflow — no silent wrap
    function test_Safe_ClaimReward_RevertsOnOverflow() public {
        uint256 points = 2 ** 128;
        uint256 multiplier = 2 ** 128;
        vm.expectRevert();
        safe.claimReward(points, multiplier);
    }

    // ══════════════════════════════════════════════
    // FUZZ TESTS
    // ══════════════════════════════════════════════

    /// @notice fuzz: any non-zero amount against empty address always underflows on vuln
    function testFuzz_Vulnerable_TransferFromAlwaysUnderflows(
        uint256 amount
    ) public {
        vm.assume(amount > 0);
        vuln.transferFrom(empty, alice, amount);
        assertGt(vuln.balances(alice), 0, "alice got free tokens");
    }

    /// @notice fuzz: safe version never lets empty address send tokens
    function testFuzz_Safe_NoUnderflowPossible(uint96 amount) public {
        vm.assume(amount > 0);
        vm.expectRevert();
        safe.transferFrom(empty, alice, amount);
        assertEq(safe.balances(alice), 0);
    }

    /*
  Change this config and comment the previous functions
  [profile.default.fuzz]
runs = 1000
    function testFuzz_Vulnerable_TransferFromAlwaysUnderflows(uint256 amount) public {
    amount = bound(amount, 1, type(uint256).max);  // clamp — never 0
    vuln.transferFrom(empty, alice, amount);
    assertGt(vuln.balances(alice), 0, "alice got free tokens");
}

function testFuzz_Safe_NoUnderflowPossible(uint256 amount) public {
    amount = bound(amount, 1, type(uint256).max);  // clamp — never 0
    vm.expectRevert();
    safe.transferFrom(empty, alice, amount);
    assertEq(safe.balances(alice), 0);
} */
}
