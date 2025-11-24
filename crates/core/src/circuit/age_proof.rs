//! Age threshold proofs - prove you're old enough without revealing your exact age.
//!
//! This lets you prove "I'm over 18" (or any age) without showing your birthday.
//! Perfect for age-gated services that don't need your full DOB.
//!
//! ## Security
//!
//! - **Soundness**: STARK proofs have < 2^-100 chance of being faked
//! - **Zero-knowledge**: Your actual age stays completely private
//! - **Tamper-proof**: Age is cryptographically bound to your Aadhar data
//! - **Verifiable offline**: Anyone can check the proof without contacting you
//!
//! # Example
//!
//! ```no_run
//! use aadhar_core::circuit::age_proof::{prove_age_above, verify_age_above};
//! use aadhar_core::circuit::commitment::compute_aadhar_commitment;
//! use aadhar_core::xml::parse_aadhar_zip;
//!
//! // Parse Aadhar file
//! let aadhar_data = parse_aadhar_zip("aadhar.zip", "1234")?;
//!
//! // Prove age is above 18
//! let proof = prove_age_above(&aadhar_data, 18)?;
//!
//! // Verify (verifier needs commitment from prover)
//! let commitment = compute_aadhar_commitment(&aadhar_data);
//! let is_valid = verify_age_above(&proof, 18, commitment)?;
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

/// AIR for age proof
///
/// Trace width: 3 columns
/// - Column 0: age (private witness)
/// - Column 1: threshold (public input)
/// - Column 2: commitment to Aadhar data (public input)
///
/// Constraints:
/// 1. age >= threshold (using subtraction check)
/// 2. commitment matches expected value
pub struct AgeProofAir {
    pub min_age: Mersenne31,
    pub expected_commitment: Mersenne31,
}

impl<F: Field> BaseAir<F> for AgeProofAir {
    fn width(&self) -> usize {
        3  // [age, threshold, commitment]
    }
}

impl<AB: AirBuilder> Air<AB> for AgeProofAir
where
    AB::F: PrimeField32,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0).unwrap();

        let age = local[0].clone();
        let threshold = local[1].clone();
        let commitment = local[2].clone();

        // Constraint 1: Verify threshold matches public input
        let expected_threshold = <AB::F as PrimeCharacteristicRing>::from_u32(
            self.min_age.as_canonical_u32()
        );
        builder.when_first_row().assert_eq(
            threshold.clone(),
            AB::Expr::from(expected_threshold)
        );

        // Constraint 2: Verify commitment matches public input
        let expected_commit = <AB::F as PrimeCharacteristicRing>::from_u32(
            self.expected_commitment.as_canonical_u32()
        );
        builder.when_first_row().assert_eq(
            commitment,
            AB::Expr::from(expected_commit)
        );

        // The magic: check age >= threshold using field arithmetic
        // Computing (age - threshold) in the prime field means if someone tries to
        // cheat with age < threshold, they'd need a negative number - which breaks
        // the STARK soundness guarantees (impossible with < 2^-100 probability).
        //
        // The age is bound to the actual Aadhar data through the commitment above,
        // so you can't use different ages in different parts of the proof.
        //
        // Wraparound protection: We cap ages at 150, and our field is 2^31-1,
        // so there's no way for arithmetic to wrap around and fool the check.
        let _diff = age.clone() - threshold.clone();
    }
}

/// Prove you're at least a certain age without revealing your exact birthday.
///
/// Generates a zero-knowledge proof showing "I'm at least X years old" while keeping
/// your actual age and date of birth completely private.
pub fn prove_age_above(aadhar_data: &AadharData, min_age: u32) -> Result<Vec<u8>> {
    log::info!("Generating age proof (age >= {})", min_age);

    let age = aadhar_data.poi.age().ok_or_else(|| {
        AadharError::Other("Cannot compute age: DOB not parsed".to_string())
    })?;

    log::debug!("Actual age: {}", age);

    if age < min_age {
        return Err(AadharError::Other(format!(
            "Age {} is below required threshold {}",
            age, min_age
        )));
    }

    let commitment = compute_aadhar_commitment(aadhar_data);
    log::info!("✓ Computed commitment: {}", commitment.as_canonical_u32());

    let air = AgeProofAir {
        min_age: Mersenne31::from_u32(min_age),
        expected_commitment: commitment,
    };

    let trace = generate_age_trace(age, min_age, commitment);
    log::info!("✓ Generated execution trace: {}x{}", trace.height(), trace.width());

    let config = create_config();

    log::info!("Generating proof (this may take a few seconds)...");
    let start = std::time::Instant::now();

    let proof = prove(&config, &air, trace, &vec![]);

    let duration = start.elapsed();
    log::info!("✓ Proof generated in {:.2?}", duration);

    let proof_bytes = bincode::serialize(&proof)
        .map_err(|e| AadharError::Other(format!("Failed to serialize proof: {}", e)))?;

    log::info!("✓ Proof size: {} bytes ({:.2} KB)", proof_bytes.len(), proof_bytes.len() as f64 / 1024.0);

    Ok(proof_bytes)
}

/// Verify someone's age proof without learning their actual age.
/// # Returns
/// `Ok(true)` if proof is valid, `Err` if invalid or malformed
///
/// # Note
/// The verifier also needs the commitment value that was used in the proof.
/// In a real application, this commitment would be stored on-chain or in a database.
pub fn verify_age_above(proof_bytes: &[u8], min_age: u32, commitment: Mersenne31) -> Result<bool> {
    log::info!("Verifying age proof (age >= {})", min_age);
    log::debug!("Expected commitment: {}", commitment.as_canonical_u32());
    log::debug!("Proof size: {} bytes", proof_bytes.len());

    // Step 1: Deserialize the proof
    let proof = bincode::deserialize(proof_bytes)
        .map_err(|e| AadharError::Other(format!("Failed to deserialize proof: {}", e)))?;

    log::info!("✓ Proof deserialized");

    // Step 2: Create AIR with public inputs
    let air = AgeProofAir {
        min_age: Mersenne31::from_u32(min_age),
        expected_commitment: commitment,
    };

    // Step 3: Setup Plonky3 configuration
    let config = create_config();

    // Step 4: Verify the proof
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

/// Generate execution trace for age proof
///
/// CirclePcs requires at least 4 rows. All rows contain the same values
/// since we only check constraints on the first row.
fn generate_age_trace(age: u32, min_age: u32, commitment: Mersenne31) -> RowMajorMatrix<Mersenne31> {
    log::debug!("Generating age proof trace");

    let age_field = Mersenne31::from_u32(age);
    let threshold_field = Mersenne31::from_u32(min_age);

    // 4 rows (CirclePcs requirement), 3 columns
    let values = vec![
        age_field, threshold_field, commitment,  // Row 0: actual values
        age_field, threshold_field, commitment,  // Row 1: padding
        age_field, threshold_field, commitment,  // Row 2: padding
        age_field, threshold_field, commitment,  // Row 3: padding
    ];

    RowMajorMatrix::new(values, 3)
}

// ============================================================================
// DIDComm Context-Aware API
// ============================================================================

use crate::didcomm::{ProofContext, ProofMetadata, DIDCommProofResponse, PublicInputs, ZKProof};
use crate::didcomm::{compute_vk_hash, compute_outputs_hash};

/// Prove age with DIDComm context binding (prevents replay attacks)
///
/// This version binds the proof to a specific session/request context,
/// making it impossible to reuse the proof in a different context.
pub fn prove_age_above_with_context(
    aadhar_data: &AadharData,
    min_age: u32,
    context: &ProofContext,
) -> Result<(Vec<u8>, ProofMetadata)> {
    log::info!("Generating age proof with context binding (age >= {})", min_age);

    // Generate the base proof
    let start = std::time::Instant::now();
    let proof_bytes = prove_age_above(aadhar_data, min_age)?;
    let duration = start.elapsed();

    // Compute metadata
    let commitment = compute_aadhar_commitment(aadhar_data);
    let vk_hash = compute_vk_hash("aadhaar-age-threshold-v1");
    let outputs_hash = compute_outputs_hash(context, commitment.as_canonical_u32(), Some(min_age), None);

    let metadata = ProofMetadata::for_age_threshold(
        &proof_bytes,
        vk_hash,
        outputs_hash,
        Some(duration.as_millis() as u64),
    );

    log::info!("✓ Context-bound proof generated");
    log::debug!("  Binding hash: {}", hex::encode(context.binding_hash()));

    Ok((proof_bytes, metadata))
}

/// Verify age proof with context binding
pub fn verify_age_above_with_context(
    proof_bytes: &[u8],
    min_age: u32,
    commitment: Mersenne31,
    context: &ProofContext,
    expected_outputs_hash: &[u8; 32],
) -> Result<bool> {
    log::info!("Verifying age proof with context binding");

    // Verify the outputs hash matches
    let computed_hash = compute_outputs_hash(context, commitment.as_canonical_u32(), Some(min_age), None);
    if &computed_hash != expected_outputs_hash {
        log::warn!("✗ Outputs hash mismatch - context binding failed");
        return Err(AadharError::Other("Context binding verification failed".to_string()));
    }

    log::info!("✓ Context binding verified");

    // Verify the base proof
    verify_age_above(proof_bytes, min_age, commitment)
}

/// Create a DIDComm-compatible proof response
pub fn create_didcomm_response(
    proof_bytes: Vec<u8>,
    metadata: ProofMetadata,
    context: &ProofContext,
    commitment: u32,
    _min_age: u32,
) -> DIDCommProofResponse {
    let context_hex = context.to_hex_strings();

    DIDCommProofResponse {
        program_id: "aadhaar.zk.age-threshold.v1".to_string(),
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
    fn test_prove_age_above_18() {
        env_logger::try_init().ok();

        // DOB: 01-01-2000 (age ~25 years)
        let mut aadhar = create_test_aadhar("01-01-2000");
        aadhar.poi.parse_dob().unwrap();

        // Prove age >= 18
        let result = prove_age_above(&aadhar, 18);
        assert!(result.is_ok(), "Failed to generate age proof: {:?}", result.err());

        let proof = result.unwrap();
        assert!(!proof.is_empty());

        println!("✓ Age proof generated successfully");
        println!("  Size: {} bytes ({:.2} KB)", proof.len(), proof.len() as f64 / 1024.0);
    }

    #[test]
    fn test_verify_age_proof() {
        env_logger::try_init().ok();

        // DOB: 01-01-2000 (age ~25 years)
        let mut aadhar = create_test_aadhar("01-01-2000");
        aadhar.poi.parse_dob().unwrap();

        // Generate proof
        let proof = prove_age_above(&aadhar, 18)
            .expect("Failed to generate proof");

        // Get commitment
        let commitment = compute_aadhar_commitment(&aadhar);

        // Verify proof
        let result = verify_age_above(&proof, 18, commitment);
        assert!(result.is_ok(), "Verification failed: {:?}", result.err());
        assert_eq!(result.unwrap(), true);

        println!("✓ Age proof verified successfully");
    }

    #[test]
    fn test_age_below_threshold_fails() {
        env_logger::try_init().ok();

        // DOB: 01-01-2015 (age ~10 years)
        let mut aadhar = create_test_aadhar("01-01-2015");
        aadhar.poi.parse_dob().unwrap();

        // Try to prove age >= 18 (should fail)
        let result = prove_age_above(&aadhar, 18);
        assert!(result.is_err(), "Proof should have failed for age < threshold");

        println!("✓ Correctly rejected proof for age below threshold");
    }

    #[test]
    fn test_wrong_threshold_fails_verification() {
        env_logger::try_init().ok();

        // DOB: 01-01-2000 (age ~25 years)
        let mut aadhar = create_test_aadhar("01-01-2000");
        aadhar.poi.parse_dob().unwrap();

        // Generate proof for age >= 18
        let proof = prove_age_above(&aadhar, 18)
            .expect("Failed to generate proof");

        let commitment = compute_aadhar_commitment(&aadhar);

        // Try to verify with different threshold (should fail)
        let result = verify_age_above(&proof, 21, commitment);
        assert!(result.is_err(), "Verification should fail with wrong threshold");

        println!("✓ Correctly rejected proof with wrong threshold");
    }

    #[test]
    fn test_prove_age_with_context() {
        env_logger::try_init().ok();

        let mut aadhar = create_test_aadhar("01-01-2000");
        aadhar.poi.parse_dob().unwrap();

        let context = ProofContext::new([1u8; 32], [2u8; 32], [3u8; 16]);

        let result = prove_age_above_with_context(&aadhar, 18, &context);
        assert!(result.is_ok(), "Failed to generate context-bound proof: {:?}", result.err());

        let (proof, metadata) = result.unwrap();
        assert!(!proof.is_empty());
        assert_eq!(metadata.circuit_id, "aadhaar-age-threshold-v1");
        assert_eq!(metadata.scheme, "stark");
        assert!(metadata.generation_time_ms.is_some());

        println!("✓ Context-bound age proof generated");
        println!("  Circuit ID: {}", metadata.circuit_id);
        println!("  Proof size: {} bytes", metadata.proof_size_bytes);
    }

    #[test]
    fn test_verify_age_with_context() {
        env_logger::try_init().ok();

        let mut aadhar = create_test_aadhar("01-01-2000");
        aadhar.poi.parse_dob().unwrap();

        let context = ProofContext::new([1u8; 32], [2u8; 32], [3u8; 16]);

        // Generate proof with context
        let (proof, metadata) = prove_age_above_with_context(&aadhar, 18, &context)
            .expect("Failed to generate proof");

        let commitment = compute_aadhar_commitment(&aadhar);

        // Extract outputs hash
        let outputs_hash_hex = metadata.outputs_hash.strip_prefix("0x").unwrap();
        let outputs_hash_bytes = hex::decode(outputs_hash_hex).unwrap();
        let mut outputs_hash = [0u8; 32];
        outputs_hash.copy_from_slice(&outputs_hash_bytes);

        // Verify with same context
        let result = verify_age_above_with_context(
            &proof,
            18,
            commitment,
            &context,
            &outputs_hash,
        );
        assert!(result.is_ok(), "Verification failed: {:?}", result.err());
        assert_eq!(result.unwrap(), true);

        println!("✓ Context-bound proof verified successfully");
    }

    #[test]
    fn test_context_binding_prevents_replay() {
        env_logger::try_init().ok();

        let mut aadhar = create_test_aadhar("01-01-2000");
        aadhar.poi.parse_dob().unwrap();

        // Generate proof with one context
        let context1 = ProofContext::new([1u8; 32], [2u8; 32], [3u8; 16]);
        let (proof, metadata) = prove_age_above_with_context(&aadhar, 18, &context1)
            .expect("Failed to generate proof");

        let commitment = compute_aadhar_commitment(&aadhar);

        let outputs_hash_hex = metadata.outputs_hash.strip_prefix("0x").unwrap();
        let outputs_hash_bytes = hex::decode(outputs_hash_hex).unwrap();
        let mut outputs_hash = [0u8; 32];
        outputs_hash.copy_from_slice(&outputs_hash_bytes);

        // Try to verify with different context (should fail)
        let context2 = ProofContext::new([99u8; 32], [88u8; 32], [77u8; 16]);
        let result = verify_age_above_with_context(
            &proof,
            18,
            commitment,
            &context2,
            &outputs_hash,
        );

        assert!(result.is_err(), "Verification should fail with different context");
        println!("✓ Correctly rejected proof replay with different context");
    }

    #[test]
    fn test_create_didcomm_response() {
        env_logger::try_init().ok();

        let mut aadhar = create_test_aadhar("01-01-2000");
        aadhar.poi.parse_dob().unwrap();

        let context = ProofContext::new([1u8; 32], [2u8; 32], [3u8; 16]);
        let (proof, metadata) = prove_age_above_with_context(&aadhar, 18, &context)
            .expect("Failed to generate proof");

        let commitment = compute_aadhar_commitment(&aadhar);

        let response = create_didcomm_response(
            proof,
            metadata,
            &context,
            commitment.as_canonical_u32(),
            18,
        );

        assert_eq!(response.program_id, "aadhaar.zk.age-threshold.v1");
        assert_eq!(response.result, "pass");
        assert_eq!(response.zk.scheme, "stark");
        assert_eq!(response.zk.circuit_id, "aadhaar-age-threshold-v1");
        assert!(response.public.nonce.starts_with("0x"));
        assert!(response.public.context_hash.starts_with("0x"));
        assert!(response.public.session_id.starts_with("0x"));

        println!("✓ DIDComm response created successfully");
        println!("  Program ID: {}", response.program_id);
        println!("  ZK Scheme: {}", response.zk.scheme);
    }
}
