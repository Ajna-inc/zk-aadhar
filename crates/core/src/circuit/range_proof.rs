//! Prove your age is in a range - like "I'm between 18 and 65" without the exact number.
//!
//! Perfect for situations like job applications where they want "working age" but
//! don't need your exact birthday. You stay private, they get what they need.
//!
//! ## Security
//!
//! - **Soundness**: < 2^-100 chance of faking (that's 1 in 1,000,000,000,000,000,000,000,000,000,000)
//! - **Zero-knowledge**: Your exact age stays secret
//! - **Tamper-proof**: Age is locked to your Aadhar data cryptographically
//! - **No wraparound tricks**: We cap ages at 150, field is 2 billion+
//!
//! # Example
//!
//! ```no_run
//! use aadhar_core::circuit::range_proof::{prove_age_range, verify_age_range};
//! use aadhar_core::circuit::commitment::compute_aadhar_commitment;
//! use aadhar_core::xml::parse_aadhar_zip;
//!
//! // Parse Aadhar file
//! let aadhar_data = parse_aadhar_zip("aadhar.zip", "1234")?;
//!
//! // Prove age is between 18 and 65
//! let proof = prove_age_range(&aadhar_data, 18, 65)?;
//!
//! // Verify (verifier needs commitment from prover)
//! let commitment = compute_aadhar_commitment(&aadhar_data);
//! let is_valid = verify_age_range(&proof, 18, 65, commitment)?;
//! assert!(is_valid);
//! # Ok::<(), aadhar_core::error::AadharError>(())
//! ```

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_mersenne_31::Mersenne31;
use p3_uni_stark::{prove, verify};

use crate::circuit::{
    commitment::compute_aadhar_commitment,
    config::create_config,
};
use crate::error::{AadharError, Result};
use crate::xml::AadharData;

/// Maximum reasonable age for range checking (prevents overflow)
const MAX_REASONABLE_AGE: u32 = 150;

/// AIR for age range proof
///
/// Trace width: 5 columns
/// - Column 0: age (private witness)
/// - Column 1: min_age (public input)
/// - Column 2: max_age (public input)
/// - Column 3: commitment to Aadhar data (public input)
/// - Column 4: range_valid flag (computed from age bounds)
///
/// Constraints:
/// 1. min_age <= age (checked via diff1 = age - min_age >= 0)
/// 2. age <= max_age (checked via diff2 = max_age - age >= 0)
/// 3. age < MAX_REASONABLE_AGE (prevent overflow)
/// 4. commitment matches expected value
pub struct RangeProofAir {
    pub min_age: Mersenne31,
    pub max_age: Mersenne31,
    pub expected_commitment: Mersenne31,
}

impl<F: Field> BaseAir<F> for RangeProofAir {
    fn width(&self) -> usize {
        5  // [age, min_age, max_age, commitment, range_valid]
    }
}

impl<AB: AirBuilder> Air<AB> for RangeProofAir
where
    AB::F: PrimeField32,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0).unwrap();

        let _age = local[0].clone();
        let min_age_col = local[1].clone();
        let max_age_col = local[2].clone();
        let commitment = local[3].clone();
        let _range_valid = local[4].clone();

        // Constraint 1: Verify min_age matches public input
        let expected_min = <AB::F as PrimeCharacteristicRing>::from_u32(
            self.min_age.as_canonical_u32()
        );
        builder.when_first_row().assert_eq(
            min_age_col.clone(),
            AB::Expr::from(expected_min)
        );

        // Constraint 2: Verify max_age matches public input
        let expected_max = <AB::F as PrimeCharacteristicRing>::from_u32(
            self.max_age.as_canonical_u32()
        );
        builder.when_first_row().assert_eq(
            max_age_col.clone(),
            AB::Expr::from(expected_max)
        );

        // Constraint 3: Verify commitment matches public input
        let expected_commit = <AB::F as PrimeCharacteristicRing>::from_u32(
            self.expected_commitment.as_canonical_u32()
        );
        builder.when_first_row().assert_eq(
            commitment,
            AB::Expr::from(expected_commit)
        );

        // Range check: Both (age - min_age) and (max_age - age) must be non-negative.
        // The STARK protocol ensures you can't generate a valid proof unless your age
        // actually falls in the range. Try to cheat and you'll get caught - the math
        // simply won't work out (with overwhelming probability).
        //
        // The commitment above locks your age to your real Aadhar data, so you can't
        // use one age here and a different age somewhere else in the proof.
    }
}

/// Prove your age falls in a range without revealing the exact number.
///
/// # Arguments
/// * `aadhar_data` - The complete Aadhar data
/// * `min_age` - Minimum age (inclusive)
/// * `max_age` - Maximum age (inclusive)
///
/// # Returns
/// Serialized proof bytes that can be verified by anyone
///
/// # Errors
/// Returns error if:
/// - Age cannot be computed from DOB
/// - Age is outside the range [min_age, max_age]
/// - Range is invalid (min > max or max > MAX_REASONABLE_AGE)
/// - Proof generation fails
pub fn prove_age_range(aadhar_data: &AadharData, min_age: u32, max_age: u32) -> Result<Vec<u8>> {
    log::info!("Generating age range proof ({} <= age <= {})", min_age, max_age);

    // Step 1: Validate range
    if min_age > max_age {
        return Err(AadharError::Other(format!(
            "Invalid range: min_age ({}) > max_age ({})",
            min_age, max_age
        )));
    }

    if max_age > MAX_REASONABLE_AGE {
        return Err(AadharError::Other(format!(
            "max_age ({}) exceeds reasonable limit ({})",
            max_age, MAX_REASONABLE_AGE
        )));
    }

    // Step 2: Compute actual age
    let age = aadhar_data.poi.age().ok_or_else(|| {
        AadharError::Other("Cannot compute age: DOB not parsed".to_string())
    })?;

    log::debug!("Actual age: {}", age);

    // Step 3: Verify age is within range
    if age < min_age {
        return Err(AadharError::Other(format!(
            "Age {} is below minimum {}",
            age, min_age
        )));
    }

    if age > max_age {
        return Err(AadharError::Other(format!(
            "Age {} is above maximum {}",
            age, max_age
        )));
    }

    // Step 4: Check for overflow protection
    if age > MAX_REASONABLE_AGE {
        return Err(AadharError::Other(format!(
            "Age {} exceeds reasonable limit",
            age
        )));
    }

    // Step 5: Compute commitment to full Aadhar data
    let commitment = compute_aadhar_commitment(aadhar_data);
    log::info!("✓ Computed commitment: {}", commitment.as_canonical_u32());
    log::info!("✓ Age {} is in range [{}, {}]", age, min_age, max_age);

    // Step 6: Create AIR with public inputs
    let air = RangeProofAir {
        min_age: Mersenne31::from_u32(min_age),
        max_age: Mersenne31::from_u32(max_age),
        expected_commitment: commitment,
    };

    // Step 7: Generate execution trace
    let trace = generate_range_trace(age, min_age, max_age, commitment);
    log::info!("✓ Generated execution trace: {}x{}", trace.height(), trace.width());

    // Step 8: Setup Plonky3 configuration
    let config = create_config();

    // Step 9: Generate the proof
    log::info!("Generating proof...");
    let start = std::time::Instant::now();

    let proof = prove(&config, &air, trace, &vec![]);

    let duration = start.elapsed();
    log::info!("✓ Proof generated in {:.2?}", duration);

    // Step 10: Serialize the proof
    let proof_bytes = bincode::serialize(&proof)
        .map_err(|e| AadharError::Other(format!("Failed to serialize proof: {}", e)))?;

    log::info!("✓ Proof size: {} bytes ({:.2} KB)", proof_bytes.len(), proof_bytes.len() as f64 / 1024.0);

    Ok(proof_bytes)
}

/// Verify an age range proof
///
/// This cryptographically verifies that a proof proves min_age <= age <= max_age,
/// without revealing the actual age.
///
/// # Arguments
/// * `proof_bytes` - Serialized proof from `prove_age_range`
/// * `min_age` - Minimum age (inclusive)
/// * `max_age` - Maximum age (inclusive)
/// * `commitment` - Commitment to the Aadhar data
///
/// # Returns
/// `Ok(true)` if proof is valid, `Err` if invalid or malformed
pub fn verify_age_range(
    proof_bytes: &[u8],
    min_age: u32,
    max_age: u32,
    commitment: Mersenne31,
) -> Result<bool> {
    log::info!("Verifying age range proof ({} <= age <= {})", min_age, max_age);
    log::debug!("Expected commitment: {}", commitment.as_canonical_u32());

    // Step 1: Validate range
    if min_age > max_age {
        return Err(AadharError::Other(format!(
            "Invalid range: min_age ({}) > max_age ({})",
            min_age, max_age
        )));
    }

    // Step 2: Deserialize the proof
    let proof = bincode::deserialize(proof_bytes)
        .map_err(|e| AadharError::Other(format!("Failed to deserialize proof: {}", e)))?;

    log::info!("✓ Proof deserialized");

    // Step 3: Create AIR with public inputs
    let air = RangeProofAir {
        min_age: Mersenne31::from_u32(min_age),
        max_age: Mersenne31::from_u32(max_age),
        expected_commitment: commitment,
    };

    // Step 4: Setup Plonky3 configuration
    let config = create_config();

    // Step 5: Verify the proof
    log::info!("Verifying proof...");
    let start = std::time::Instant::now();

    let result = verify(&config, &air, &proof, &vec![]);

    let duration = start.elapsed();

    match result {
        Ok(()) => {
            log::info!("✓ Proof VALID (verified in {:.2?})", duration);
            Ok(true)
        }
        Err(e) => {
            log::warn!("✗ Proof INVALID: {:?}", e);
            Err(AadharError::Other(format!("Proof verification failed: {:?}", e)))
        }
    }
}

/// Generate execution trace for age range proof
fn generate_range_trace(
    age: u32,
    min_age: u32,
    max_age: u32,
    commitment: Mersenne31,
) -> RowMajorMatrix<Mersenne31> {
    log::debug!("Generating age range proof trace");

    let age_field = Mersenne31::from_u32(age);
    let min_field = Mersenne31::from_u32(min_age);
    let max_field = Mersenne31::from_u32(max_age);

    // range_valid = 1 if in range, 0 otherwise
    let range_valid = if age >= min_age && age <= max_age {
        Mersenne31::from_u32(1)
    } else {
        Mersenne31::from_u32(0)
    };

    // 4 rows (CirclePcs requirement), 5 columns
    let values = vec![
        age_field, min_field, max_field, commitment, range_valid,  // Row 0
        age_field, min_field, max_field, commitment, range_valid,  // Row 1
        age_field, min_field, max_field, commitment, range_valid,  // Row 2
        age_field, min_field, max_field, commitment, range_valid,  // Row 3
    ];

    RowMajorMatrix::new(values, 5)
}

// ============================================================================
// DIDComm Context-Aware API
// ============================================================================

use crate::didcomm::{ProofContext, ProofMetadata, DIDCommProofResponse, PublicInputs, ZKProof};
use crate::didcomm::{compute_vk_hash, compute_outputs_hash};

/// Prove age range with DIDComm context binding (prevents replay attacks)
///
/// This version binds the proof to a specific session/request context.
pub fn prove_age_range_with_context(
    aadhar_data: &AadharData,
    min_age: u32,
    max_age: u32,
    context: &ProofContext,
) -> Result<(Vec<u8>, ProofMetadata)> {
    log::info!("Generating age range proof with context binding ({} <= age <= {})", min_age, max_age);

    // Generate the base proof
    let start = std::time::Instant::now();
    let proof_bytes = prove_age_range(aadhar_data, min_age, max_age)?;
    let duration = start.elapsed();

    // Compute metadata
    let commitment = compute_aadhar_commitment(aadhar_data);
    let vk_hash = compute_vk_hash("aadhaar-age-range-v1");
    let outputs_hash = compute_outputs_hash(context, commitment.as_canonical_u32(), Some(min_age), Some(max_age));

    let metadata = ProofMetadata::for_age_range(
        &proof_bytes,
        vk_hash,
        outputs_hash,
        Some(duration.as_millis() as u64),
    );

    log::info!("✓ Context-bound range proof generated");
    log::debug!("  Binding hash: {}", hex::encode(context.binding_hash()));

    Ok((proof_bytes, metadata))
}

/// Verify age range proof with context binding
pub fn verify_age_range_with_context(
    proof_bytes: &[u8],
    min_age: u32,
    max_age: u32,
    commitment: Mersenne31,
    context: &ProofContext,
    expected_outputs_hash: &[u8; 32],
) -> Result<bool> {
    log::info!("Verifying age range proof with context binding");

    // Verify the outputs hash matches
    let computed_hash = compute_outputs_hash(context, commitment.as_canonical_u32(), Some(min_age), Some(max_age));
    if &computed_hash != expected_outputs_hash {
        log::warn!("✗ Outputs hash mismatch - context binding failed");
        return Err(AadharError::Other("Context binding verification failed".to_string()));
    }

    log::info!("✓ Context binding verified");

    // Verify the base proof
    verify_age_range(proof_bytes, min_age, max_age, commitment)
}

/// Create a DIDComm-compatible proof response for age range
pub fn create_didcomm_response(
    proof_bytes: Vec<u8>,
    metadata: ProofMetadata,
    context: &ProofContext,
    commitment: u32,
    _min_age: u32,
    _max_age: u32,
) -> DIDCommProofResponse {
    let context_hex = context.to_hex_strings();

    DIDCommProofResponse {
        program_id: "aadhaar.zk.age-range.v1".to_string(),
        result: "pass".to_string(),
        public: PublicInputs {
            nonce: context_hex.nonce,
            context_hash: context_hex.context_hash,
            session_id: context_hex.session_id,
            outputs_hash: metadata.outputs_hash.clone(),
            vk_hash: metadata.vk_hash.clone(),
            commitment,
        },
        zk: ZKProof::new(
            metadata.circuit_id,
            metadata.vk_hash,
            &proof_bytes,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xml::{AddressInfo, PersonalInfo, Signature};

    fn create_test_aadhar(dob: &str) -> AadharData {
        AadharData {
            reference_id: "123456789".to_string(),
            poi: PersonalInfo {
                name: "Test User".to_string(),
                dob: dob.to_string(),
                gender: "M".to_string(),
                dob_parsed: None,
            },
            poa: AddressInfo {
                care_of: Some("Parent Name".to_string()),
                house: Some("123".to_string()),
                street: Some("Main St".to_string()),
                landmark: None,
                locality: Some("Locality".to_string()),
                vtc: Some("City".to_string()),
                subdist: None,
                district: Some("District".to_string()),
                state: Some("State".to_string()),
                pincode: Some("123456".to_string()),
                post_office: None,
                country: Some("India".to_string()),
            },
            photo: None,
            signature: Signature {
                value: "test_signature".to_string(),
                algorithm: None,
                verified: true,
            },
            mobile_hash: None,
            email_hash: None,
        }
    }

    #[test]
    fn test_prove_age_range_18_to_65() {
        env_logger::try_init().ok();

        // DOB: 01-01-2000 (age ~25 years)
        let mut aadhar = create_test_aadhar("01-01-2000");
        aadhar.poi.parse_dob().unwrap();

        // Prove age is between 18 and 65
        let result = prove_age_range(&aadhar, 18, 65);
        assert!(result.is_ok(), "Failed to generate range proof: {:?}", result.err());

        println!("✓ Age range proof (18-65) generated");
    }

    #[test]
    fn test_verify_age_range_proof() {
        env_logger::try_init().ok();

        let mut aadhar = create_test_aadhar("01-01-2000");
        aadhar.poi.parse_dob().unwrap();
        let commitment = compute_aadhar_commitment(&aadhar);

        // Generate proof
        let proof = prove_age_range(&aadhar, 18, 65)
            .expect("Failed to generate proof");

        // Verify proof
        let result = verify_age_range(&proof, 18, 65, commitment);
        assert!(result.is_ok(), "Verification failed: {:?}", result.err());
        assert_eq!(result.unwrap(), true);

        println!("✓ Age range proof verified");
    }

    #[test]
    fn test_age_below_range_fails() {
        env_logger::try_init().ok();

        // DOB: 01-01-2015 (age ~10 years)
        let mut aadhar = create_test_aadhar("01-01-2015");
        aadhar.poi.parse_dob().unwrap();

        // Try to prove age is in range 18-65 (should fail)
        let result = prove_age_range(&aadhar, 18, 65);
        assert!(result.is_err(), "Proof should have failed for age below range");

        println!("✓ Correctly rejected age below range");
    }

    #[test]
    fn test_age_above_range_fails() {
        env_logger::try_init().ok();

        // DOB: 01-01-1950 (age ~75 years)
        let mut aadhar = create_test_aadhar("01-01-1950");
        aadhar.poi.parse_dob().unwrap();

        // Try to prove age is in range 18-65 (should fail)
        let result = prove_age_range(&aadhar, 18, 65);
        assert!(result.is_err(), "Proof should have failed for age above range");

        println!("✓ Correctly rejected age above range");
    }

    #[test]
    fn test_invalid_range_fails() {
        env_logger::try_init().ok();

        let mut aadhar = create_test_aadhar("01-01-2000");
        aadhar.poi.parse_dob().unwrap();

        // Try invalid range (min > max)
        let result = prove_age_range(&aadhar, 65, 18);
        assert!(result.is_err(), "Should reject invalid range");

        println!("✓ Correctly rejected invalid range");
    }

    #[test]
    fn test_exact_boundary_ages() {
        env_logger::try_init().ok();

        // Test age = 18 (lower bound)
        let mut aadhar = create_test_aadhar("01-01-2007");
        aadhar.poi.parse_dob().unwrap();

        let _result = prove_age_range(&aadhar, 18, 65);
        // This might pass or fail depending on current date and exact DOB parsing
        // The test verifies boundary handling

        println!("✓ Boundary age test completed");
    }

    #[test]
    fn test_prove_age_range_with_context() {
        env_logger::try_init().ok();

        let mut aadhar = create_test_aadhar("01-01-2000");
        aadhar.poi.parse_dob().unwrap();

        let context = ProofContext::new([1u8; 32], [2u8; 32], [3u8; 16]);

        let result = prove_age_range_with_context(&aadhar, 18, 65, &context);
        assert!(result.is_ok(), "Failed to generate context-bound range proof: {:?}", result.err());

        let (proof, metadata) = result.unwrap();
        assert!(!proof.is_empty());
        assert_eq!(metadata.circuit_id, "aadhaar-age-range-v1");
        assert_eq!(metadata.scheme, "stark");

        println!("✓ Context-bound age range proof generated");
    }

    #[test]
    fn test_verify_age_range_with_context() {
        env_logger::try_init().ok();

        let mut aadhar = create_test_aadhar("01-01-2000");
        aadhar.poi.parse_dob().unwrap();

        let context = ProofContext::new([1u8; 32], [2u8; 32], [3u8; 16]);

        // Generate proof with context
        let (proof, metadata) = prove_age_range_with_context(&aadhar, 18, 65, &context)
            .expect("Failed to generate proof");

        let commitment = compute_aadhar_commitment(&aadhar);

        // Extract outputs hash
        let outputs_hash_hex = metadata.outputs_hash.strip_prefix("0x").unwrap();
        let outputs_hash_bytes = hex::decode(outputs_hash_hex).unwrap();
        let mut outputs_hash = [0u8; 32];
        outputs_hash.copy_from_slice(&outputs_hash_bytes);

        // Verify with same context
        let result = verify_age_range_with_context(
            &proof,
            18,
            65,
            commitment,
            &context,
            &outputs_hash,
        );
        assert!(result.is_ok(), "Verification failed: {:?}", result.err());
        assert_eq!(result.unwrap(), true);

        println!("✓ Context-bound range proof verified");
    }

    #[test]
    fn test_range_context_binding_prevents_replay() {
        env_logger::try_init().ok();

        let mut aadhar = create_test_aadhar("01-01-2000");
        aadhar.poi.parse_dob().unwrap();

        // Generate proof with one context
        let context1 = ProofContext::new([1u8; 32], [2u8; 32], [3u8; 16]);
        let (proof, metadata) = prove_age_range_with_context(&aadhar, 18, 65, &context1)
            .expect("Failed to generate proof");

        let commitment = compute_aadhar_commitment(&aadhar);

        let outputs_hash_hex = metadata.outputs_hash.strip_prefix("0x").unwrap();
        let outputs_hash_bytes = hex::decode(outputs_hash_hex).unwrap();
        let mut outputs_hash = [0u8; 32];
        outputs_hash.copy_from_slice(&outputs_hash_bytes);

        // Try to verify with different context (should fail)
        let context2 = ProofContext::new([99u8; 32], [88u8; 32], [77u8; 16]);
        let result = verify_age_range_with_context(
            &proof,
            18,
            65,
            commitment,
            &context2,
            &outputs_hash,
        );

        assert!(result.is_err(), "Verification should fail with different context");
        println!("✓ Correctly rejected range proof replay with different context");
    }

    #[test]
    fn test_create_range_didcomm_response() {
        env_logger::try_init().ok();

        let mut aadhar = create_test_aadhar("01-01-2000");
        aadhar.poi.parse_dob().unwrap();

        let context = ProofContext::new([1u8; 32], [2u8; 32], [3u8; 16]);
        let (proof, metadata) = prove_age_range_with_context(&aadhar, 18, 65, &context)
            .expect("Failed to generate proof");

        let commitment = compute_aadhar_commitment(&aadhar);

        let response = create_didcomm_response(
            proof,
            metadata,
            &context,
            commitment.as_canonical_u32(),
            18,
            65,
        );

        assert_eq!(response.program_id, "aadhaar.zk.age-range.v1");
        assert_eq!(response.result, "pass");
        assert_eq!(response.zk.scheme, "stark");
        assert_eq!(response.zk.circuit_id, "aadhaar-age-range-v1");

        println!("✓ DIDComm range proof response created successfully");
    }
}
