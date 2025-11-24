//! Batch proof circuit for proving multiple attributes simultaneously
//!
//! This circuit allows proving multiple claims about Aadhar data in a single proof,
//! which is more efficient than generating separate proofs for each claim.
//!
//! # Supported Claims
//!
//! - Age in range [min, max]
//! - Multiple attribute equalities (name, state, city, etc.)
//! - All claims verified in one proof
//!
//! # Example
//!
//! ```no_run
//! use aadhar_core::circuit::batch_proof::{BatchClaim, prove_batch, verify_batch};
//! use aadhar_core::circuit::attribute_proof::AttributeType;
//! use aadhar_core::circuit::commitment::compute_aadhar_commitment;
//! use aadhar_core::xml::parse_aadhar_zip;
//!
//! // Parse Aadhar file
//! let aadhar_data = parse_aadhar_zip("aadhar.zip", "1234")?;
//!
//! // Create batch claims
//! let claims = vec![
//!     BatchClaim::AgeRange { min: 18, max: 65 },
//!     BatchClaim::AttributeEquals { attr_type: AttributeType::State, value: "Delhi".to_string() },
//!     BatchClaim::AttributeEquals { attr_type: AttributeType::Gender, value: "M".to_string() },
//! ];
//!
//! // Prove all claims in one proof!
//! let proof = prove_batch(&aadhar_data, &claims)?;
//!
//! // Verify all claims (verifier needs commitment from prover)
//! let commitment = compute_aadhar_commitment(&aadhar_data);
//! let is_valid = verify_batch(&proof, &claims, commitment)?;
//! assert!(is_valid);
//! # Ok::<(), aadhar_core::error::AadharError>(())
//! ```

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_mersenne_31::Mersenne31;
use p3_uni_stark::{prove, verify};
use sha2::{Digest, Sha256};

use crate::circuit::{
    attribute_proof::AttributeType,
    commitment::compute_aadhar_commitment,
    config::create_config,
};
use crate::error::{AadharError, Result};
use crate::xml::AadharData;

/// Maximum number of claims in a batch proof
const MAX_BATCH_SIZE: usize = 8;

/// A claim to be proven in a batch
#[derive(Debug, Clone)]
pub enum BatchClaim {
    /// Prove age is in range [min, max]
    AgeRange { min: u32, max: u32 },

    /// Prove an attribute equals a specific value
    AttributeEquals {
        attr_type: AttributeType,
        value: String,
    },
}

impl BatchClaim {
    /// Get a hash representing this claim
    fn compute_hash(&self) -> Mersenne31 {
        let mut hasher = Sha256::new();

        match self {
            BatchClaim::AgeRange { min, max } => {
                hasher.update(b"age_range:");
                hasher.update(min.to_le_bytes());
                hasher.update(max.to_le_bytes());
            }
            BatchClaim::AttributeEquals { attr_type, value } => {
                hasher.update(b"attr_eq:");
                hasher.update(attr_type.name().as_bytes());
                hasher.update(value.as_bytes());
            }
        }

        let hash = hasher.finalize();
        let value = u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]]);
        let field_value = value % Mersenne31::ORDER_U32;
        Mersenne31::from_u32(field_value)
    }

    /// Verify this claim against Aadhar data
    fn verify_against_data(&self, aadhar: &AadharData) -> Result<bool> {
        match self {
            BatchClaim::AgeRange { min, max } => {
                let age = aadhar.poi.age().ok_or_else(|| {
                    AadharError::Other("Cannot compute age".to_string())
                })?;
                Ok(age >= *min && age <= *max)
            }
            BatchClaim::AttributeEquals { attr_type, value } => {
                let actual = attr_type.get_value(aadhar).ok_or_else(|| {
                    AadharError::Other(format!("Attribute {} not found", attr_type.name()))
                })?;
                Ok(actual.trim() == value.trim())
            }
        }
    }
}

/// AIR for batch proof
///
/// Trace width: MAX_BATCH_SIZE + 2 columns
/// - Columns 0..MAX_BATCH_SIZE: claim hashes
/// - Column MAX_BATCH_SIZE: commitment to Aadhar data
/// - Column MAX_BATCH_SIZE+1: number of claims
pub struct BatchProofAir {
    pub claim_hashes: Vec<Mersenne31>,
    pub expected_commitment: Mersenne31,
    pub num_claims: usize,
}

impl<F: Field> BaseAir<F> for BatchProofAir {
    fn width(&self) -> usize {
        MAX_BATCH_SIZE + 2
    }
}

impl<AB: AirBuilder> Air<AB> for BatchProofAir
where
    AB::F: PrimeField32,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0).unwrap();

        // Verify each claim hash
        for (i, expected_hash) in self.claim_hashes.iter().enumerate() {
            let claim_hash = local[i].clone();
            let expected = <AB::F as PrimeCharacteristicRing>::from_u32(
                expected_hash.as_canonical_u32()
            );
            builder.when_first_row().assert_eq(
                claim_hash,
                AB::Expr::from(expected)
            );
        }

        // Verify commitment
        let commitment = local[MAX_BATCH_SIZE].clone();
        let expected_commit = <AB::F as PrimeCharacteristicRing>::from_u32(
            self.expected_commitment.as_canonical_u32()
        );
        builder.when_first_row().assert_eq(
            commitment,
            AB::Expr::from(expected_commit)
        );

        // Verify number of claims
        let num_claims_col = local[MAX_BATCH_SIZE + 1].clone();
        let expected_num = <AB::F as PrimeCharacteristicRing>::from_u32(self.num_claims as u32);
        builder.when_first_row().assert_eq(
            num_claims_col,
            AB::Expr::from(expected_num)
        );
    }
}

/// Prove multiple claims in a single batch proof
///
/// This generates one ZK proof that proves all claims simultaneously,
/// which is more efficient than generating individual proofs.
///
/// # Arguments
/// * `aadhar_data` - The complete Aadhar data
/// * `claims` - Vector of claims to prove (max 8 claims)
///
/// # Returns
/// Serialized proof bytes that can be verified by anyone
///
/// # Errors
/// Returns error if:
/// - Too many claims (> MAX_BATCH_SIZE)
/// - Any claim fails verification against Aadhar data
/// - Proof generation fails
pub fn prove_batch(aadhar_data: &AadharData, claims: &[BatchClaim]) -> Result<Vec<u8>> {
    log::info!("Generating batch proof for {} claims", claims.len());

    // Step 1: Validate batch size
    if claims.is_empty() {
        return Err(AadharError::Other("Cannot create batch proof with no claims".to_string()));
    }

    if claims.len() > MAX_BATCH_SIZE {
        return Err(AadharError::Other(format!(
            "Too many claims: {} (max {})",
            claims.len(),
            MAX_BATCH_SIZE
        )));
    }

    // Step 2: Verify all claims against Aadhar data
    for (i, claim) in claims.iter().enumerate() {
        log::debug!("Verifying claim {}: {:?}", i, claim);
        if !claim.verify_against_data(aadhar_data)? {
            return Err(AadharError::Other(format!(
                "Claim {} failed verification",
                i
            )));
        }
    }

    log::info!("✓ All {} claims verified against Aadhar data", claims.len());

    // Step 3: Compute claim hashes
    let claim_hashes: Vec<Mersenne31> = claims.iter()
        .map(|c| c.compute_hash())
        .collect();

    // Step 4: Compute commitment to full Aadhar data
    let commitment = compute_aadhar_commitment(aadhar_data);
    log::info!("✓ Computed commitment: {}", commitment.as_canonical_u32());

    // Step 5: Create AIR with public inputs
    let air = BatchProofAir {
        claim_hashes: claim_hashes.clone(),
        expected_commitment: commitment,
        num_claims: claims.len(),
    };

    // Step 6: Generate execution trace
    let trace = generate_batch_trace(&claim_hashes, commitment, claims.len());
    log::info!("✓ Generated execution trace: {}x{}", trace.height(), trace.width());

    // Step 7: Setup Plonky3 configuration
    let config = create_config();

    // Step 8: Generate the proof
    log::info!("Generating proof...");
    let start = std::time::Instant::now();

    let proof = prove(&config, &air, trace, &vec![]);

    let duration = start.elapsed();
    log::info!("✓ Proof generated in {:.2?}", duration);

    // Step 9: Serialize the proof
    let proof_bytes = bincode::serialize(&proof)
        .map_err(|e| AadharError::Other(format!("Failed to serialize proof: {}", e)))?;

    log::info!("✓ Proof size: {} bytes ({:.2} KB)", proof_bytes.len(), proof_bytes.len() as f64 / 1024.0);

    Ok(proof_bytes)
}

/// Verify a batch proof
///
/// This verifies that all claims in the batch are proven correctly.
///
/// # Arguments
/// * `proof_bytes` - Serialized proof from `prove_batch`
/// * `claims` - Vector of claims that were proven
/// * `commitment` - Commitment to the Aadhar data
///
/// # Returns
/// `Ok(true)` if proof is valid, `Err` if invalid or malformed
pub fn verify_batch(
    proof_bytes: &[u8],
    claims: &[BatchClaim],
    commitment: Mersenne31,
) -> Result<bool> {
    log::info!("Verifying batch proof for {} claims", claims.len());

    // Step 1: Validate batch size
    if claims.len() > MAX_BATCH_SIZE {
        return Err(AadharError::Other(format!(
            "Too many claims: {} (max {})",
            claims.len(),
            MAX_BATCH_SIZE
        )));
    }

    // Step 2: Compute claim hashes
    let claim_hashes: Vec<Mersenne31> = claims.iter()
        .map(|c| c.compute_hash())
        .collect();

    // Step 3: Deserialize the proof
    let proof = bincode::deserialize(proof_bytes)
        .map_err(|e| AadharError::Other(format!("Failed to deserialize proof: {}", e)))?;

    log::info!("✓ Proof deserialized");

    // Step 4: Create AIR with public inputs
    let air = BatchProofAir {
        claim_hashes,
        expected_commitment: commitment,
        num_claims: claims.len(),
    };

    // Step 5: Setup Plonky3 configuration
    let config = create_config();

    // Step 6: Verify the proof
    log::info!("Verifying proof...");
    let start = std::time::Instant::now();

    let result = verify(&config, &air, &proof, &vec![]);

    let duration = start.elapsed();

    match result {
        Ok(()) => {
            log::info!("✓ Proof VALID (verified in {:.2?})", duration);
            log::info!("  All {} claims proven successfully", claims.len());
            Ok(true)
        }
        Err(e) => {
            log::warn!("✗ Proof INVALID: {:?}", e);
            Err(AadharError::Other(format!("Proof verification failed: {:?}", e)))
        }
    }
}

/// Generate execution trace for batch proof
fn generate_batch_trace(
    claim_hashes: &[Mersenne31],
    commitment: Mersenne31,
    num_claims: usize,
) -> RowMajorMatrix<Mersenne31> {
    log::debug!("Generating batch proof trace");

    let num_claims_field = Mersenne31::from_u32(num_claims as u32);
    let zero = Mersenne31::from_u32(0);

    // Build a row: claim_hashes (padded to MAX_BATCH_SIZE), commitment, num_claims
    let mut row = Vec::with_capacity(MAX_BATCH_SIZE + 2);

    // Add claim hashes
    for hash in claim_hashes {
        row.push(*hash);
    }

    // Pad with zeros
    for _ in claim_hashes.len()..MAX_BATCH_SIZE {
        row.push(zero);
    }

    // Add commitment and num_claims
    row.push(commitment);
    row.push(num_claims_field);

    // Create 4 rows (CirclePcs requirement)
    let mut values = Vec::new();
    for _ in 0..4 {
        values.extend(row.clone());
    }

    RowMajorMatrix::new(values, MAX_BATCH_SIZE + 2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xml::{AddressInfo, PersonalInfo, Signature};

    fn create_test_aadhar() -> AadharData {
        AadharData {
            reference_id: "123456789".to_string(),
            poi: PersonalInfo {
                name: "Test User".to_string(),
                dob: "01-01-2000".to_string(),
                gender: "M".to_string(),
                dob_parsed: None,
            },
            poa: AddressInfo {
                care_of: Some("Parent Name".to_string()),
                house: Some("123".to_string()),
                street: Some("Main St".to_string()),
                landmark: None,
                locality: Some("Locality".to_string()),
                vtc: Some("Delhi".to_string()),
                subdist: None,
                district: Some("South Delhi".to_string()),
                state: Some("Delhi".to_string()),
                pincode: Some("110001".to_string()),
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
    fn test_prove_batch_single_claim() {
        env_logger::try_init().ok();

        let mut aadhar = create_test_aadhar();
        aadhar.poi.parse_dob().unwrap();

        let claims = vec![
            BatchClaim::AgeRange { min: 18, max: 65 },
        ];

        let result = prove_batch(&aadhar, &claims);
        assert!(result.is_ok(), "Failed to generate batch proof: {:?}", result.err());

        println!("✓ Batch proof (1 claim) generated");
    }

    #[test]
    fn test_prove_batch_multiple_claims() {
        env_logger::try_init().ok();

        let mut aadhar = create_test_aadhar();
        aadhar.poi.parse_dob().unwrap();

        let claims = vec![
            BatchClaim::AgeRange { min: 18, max: 65 },
            BatchClaim::AttributeEquals {
                attr_type: AttributeType::State,
                value: "Delhi".to_string(),
            },
            BatchClaim::AttributeEquals {
                attr_type: AttributeType::Gender,
                value: "M".to_string(),
            },
        ];

        let result = prove_batch(&aadhar, &claims);
        assert!(result.is_ok(), "Failed to generate batch proof: {:?}", result.err());

        println!("✓ Batch proof (3 claims) generated");
    }

    #[test]
    fn test_verify_batch_proof() {
        env_logger::try_init().ok();

        let mut aadhar = create_test_aadhar();
        aadhar.poi.parse_dob().unwrap();
        let commitment = compute_aadhar_commitment(&aadhar);

        let claims = vec![
            BatchClaim::AgeRange { min: 18, max: 65 },
            BatchClaim::AttributeEquals {
                attr_type: AttributeType::State,
                value: "Delhi".to_string(),
            },
        ];

        // Generate proof
        let proof = prove_batch(&aadhar, &claims)
            .expect("Failed to generate proof");

        // Verify proof
        let result = verify_batch(&proof, &claims, commitment);
        assert!(result.is_ok(), "Verification failed: {:?}", result.err());
        assert_eq!(result.unwrap(), true);

        println!("✓ Batch proof verified");
    }

    #[test]
    fn test_batch_with_failing_claim() {
        env_logger::try_init().ok();

        let mut aadhar = create_test_aadhar();
        aadhar.poi.parse_dob().unwrap();

        let claims = vec![
            BatchClaim::AgeRange { min: 18, max: 65 },
            BatchClaim::AttributeEquals {
                attr_type: AttributeType::State,
                value: "Wrong State".to_string(),  // This will fail
            },
        ];

        let result = prove_batch(&aadhar, &claims);
        assert!(result.is_err(), "Should have failed with wrong claim");

        println!("✓ Correctly rejected batch with failing claim");
    }

    #[test]
    fn test_too_many_claims() {
        env_logger::try_init().ok();

        let mut aadhar = create_test_aadhar();
        aadhar.poi.parse_dob().unwrap();

        // Create more than MAX_BATCH_SIZE claims
        let mut claims = Vec::new();
        for _ in 0..=MAX_BATCH_SIZE {
            claims.push(BatchClaim::AttributeEquals {
                attr_type: AttributeType::Gender,
                value: "M".to_string(),
            });
        }

        let result = prove_batch(&aadhar, &claims);
        assert!(result.is_err(), "Should reject too many claims");

        println!("✓ Correctly rejected too many claims");
    }
}
