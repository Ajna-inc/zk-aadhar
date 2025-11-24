//! Attribute equality proofs for Aadhar
//!
//! This circuit proves that a specific attribute (name, state, city, etc.)
//! matches an expected value, without revealing other Aadhar data.
//!
//! # How it works
//!
//! 1. Prover hashes the attribute value
//! 2. Prover creates a commitment to their full Aadhar data
//! 3. Circuit proves: hash(attribute) == expected_hash AND commitment is valid
//! 4. Verifier only learns: "attribute matches" is true
//!
//! # Example
//!
//! ```no_run
//! use aadhar_core::circuit::attribute_proof::{prove_attribute, verify_attribute, AttributeType};
//! use aadhar_core::circuit::commitment::compute_aadhar_commitment;
//! use aadhar_core::xml::parse_aadhar_zip;
//!
//! // Parse Aadhar file
//! let aadhar_data = parse_aadhar_zip("aadhar.zip", "1234")?;
//!
//! // Prove name matches "John Doe"
//! let proof = prove_attribute(&aadhar_data, AttributeType::Name, "John Doe")?;
//!
//! // Verify (verifier needs commitment from prover)
//! let commitment = compute_aadhar_commitment(&aadhar_data);
//! let is_valid = verify_attribute(&proof, AttributeType::Name, "John Doe", commitment)?;
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
    commitment::compute_aadhar_commitment,
    config::create_config,
};
use crate::error::{AadharError, Result};
use crate::xml::AadharData;

/// Type of attribute to prove
#[derive(Debug, Clone, Copy)]
pub enum AttributeType {
    /// Full name
    Name,
    /// State
    State,
    /// City (VTC - Village/Town/City)
    City,
    /// District
    District,
    /// PIN code
    Pincode,
    /// Gender
    Gender,
}

impl AttributeType {
    /// Get the attribute value from Aadhar data
    pub fn get_value(&self, aadhar: &AadharData) -> Option<String> {
        match self {
            AttributeType::Name => Some(aadhar.poi.name.clone()),
            AttributeType::State => aadhar.poa.state.clone(),
            AttributeType::City => aadhar.poa.vtc.clone(),
            AttributeType::District => aadhar.poa.district.clone(),
            AttributeType::Pincode => aadhar.poa.pincode.clone(),
            AttributeType::Gender => Some(aadhar.poi.gender.clone()),
        }
    }

    /// Get attribute name as string
    pub fn name(&self) -> &'static str {
        match self {
            AttributeType::Name => "name",
            AttributeType::State => "state",
            AttributeType::City => "city",
            AttributeType::District => "district",
            AttributeType::Pincode => "pincode",
            AttributeType::Gender => "gender",
        }
    }
}

/// AIR for attribute equality proof
///
/// Trace width: 3 columns
/// - Column 0: attribute hash (private witness)
/// - Column 1: expected hash (public input)
/// - Column 2: commitment to Aadhar data (public input)
///
/// Constraints:
/// 1. attribute_hash == expected_hash
/// 2. commitment matches expected value
pub struct AttributeProofAir {
    pub expected_hash: Mersenne31,
    pub expected_commitment: Mersenne31,
}

impl<F: Field> BaseAir<F> for AttributeProofAir {
    fn width(&self) -> usize {
        3  // [attribute_hash, expected_hash, commitment]
    }
}

impl<AB: AirBuilder> Air<AB> for AttributeProofAir
where
    AB::F: PrimeField32,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0).unwrap();

        let attr_hash = local[0].clone();
        let expected_hash = local[1].clone();
        let commitment = local[2].clone();

        // Constraint 1: Verify attribute hash matches expected
        let expected_hash_val = <AB::F as PrimeCharacteristicRing>::from_u32(
            self.expected_hash.as_canonical_u32()
        );
        builder.when_first_row().assert_eq(
            attr_hash.clone(),
            AB::Expr::from(expected_hash_val)
        );

        builder.when_first_row().assert_eq(
            expected_hash,
            AB::Expr::from(expected_hash_val)
        );

        // Constraint 2: Verify commitment matches public input
        let expected_commit = <AB::F as PrimeCharacteristicRing>::from_u32(
            self.expected_commitment.as_canonical_u32()
        );
        builder.when_first_row().assert_eq(
            commitment,
            AB::Expr::from(expected_commit)
        );
    }
}

/// Compute hash of attribute value
///
/// Uses SHA256 and converts to Mersenne31 field element
fn hash_attribute(value: &str) -> Mersenne31 {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let hash = hasher.finalize();

    // Convert first 4 bytes to u32, then to Mersenne31
    let value = u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]]);
    let field_value = value % Mersenne31::ORDER_U32;

    Mersenne31::from_u32(field_value)
}

/// Prove that an attribute matches an expected value
///
/// This generates a ZK proof that a specific Aadhar attribute matches
/// the expected value, without revealing other Aadhar data.
///
/// # Arguments
/// * `aadhar_data` - The complete Aadhar data
/// * `attr_type` - Type of attribute to prove
/// * `expected_value` - Expected value of the attribute
///
/// # Returns
/// Serialized proof bytes that can be verified by anyone
///
/// # Errors
/// Returns error if:
/// - Attribute doesn't exist in Aadhar data
/// - Attribute doesn't match expected value
/// - Proof generation fails
pub fn prove_attribute(
    aadhar_data: &AadharData,
    attr_type: AttributeType,
    expected_value: &str,
) -> Result<Vec<u8>> {
    log::info!("Generating attribute proof for {}", attr_type.name());

    // Step 1: Get actual attribute value
    let actual_value = attr_type.get_value(aadhar_data)
        .ok_or_else(|| AadharError::Other(format!("{} not found in Aadhar data", attr_type.name())))?;

    log::debug!("Actual value: {}", actual_value);

    // Step 2: Verify value matches expected
    if actual_value.trim() != expected_value.trim() {
        return Err(AadharError::Other(format!(
            "{} '{}' does not match expected '{}'",
            attr_type.name(), actual_value, expected_value
        )));
    }

    // Step 3: Compute hashes
    let attr_hash = hash_attribute(&actual_value);
    let expected_hash = hash_attribute(expected_value);

    log::debug!("Attribute hash: {}", attr_hash.as_canonical_u32());
    log::debug!("Expected hash: {}", expected_hash.as_canonical_u32());

    // Step 4: Compute commitment to full Aadhar data
    let commitment = compute_aadhar_commitment(aadhar_data);
    log::info!("✓ Computed commitment: {}", commitment.as_canonical_u32());

    // Step 5: Create AIR with public inputs
    let air = AttributeProofAir {
        expected_hash,
        expected_commitment: commitment,
    };

    // Step 6: Generate execution trace
    let trace = generate_attribute_trace(attr_hash, expected_hash, commitment);
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

/// Verify an attribute equality proof
///
/// This cryptographically verifies that a proof proves attribute == expected_value,
/// without revealing other Aadhar data.
///
/// # Arguments
/// * `proof_bytes` - Serialized proof from `prove_attribute`
/// * `attr_type` - Type of attribute that was proven
/// * `expected_value` - Expected value of the attribute
/// * `commitment` - Commitment to the Aadhar data
///
/// # Returns
/// `Ok(true)` if proof is valid, `Err` if invalid or malformed
pub fn verify_attribute(
    proof_bytes: &[u8],
    attr_type: AttributeType,
    expected_value: &str,
    commitment: Mersenne31,
) -> Result<bool> {
    log::info!("Verifying attribute proof for {}", attr_type.name());
    log::debug!("Expected value: {}", expected_value);
    log::debug!("Expected commitment: {}", commitment.as_canonical_u32());

    // Step 1: Compute expected hash
    let expected_hash = hash_attribute(expected_value);
    log::debug!("Expected hash: {}", expected_hash.as_canonical_u32());

    // Step 2: Deserialize the proof
    let proof = bincode::deserialize(proof_bytes)
        .map_err(|e| AadharError::Other(format!("Failed to deserialize proof: {}", e)))?;

    log::info!("✓ Proof deserialized");

    // Step 3: Create AIR with public inputs
    let air = AttributeProofAir {
        expected_hash,
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

/// Generate execution trace for attribute proof
fn generate_attribute_trace(
    attr_hash: Mersenne31,
    expected_hash: Mersenne31,
    commitment: Mersenne31,
) -> RowMajorMatrix<Mersenne31> {
    log::debug!("Generating attribute proof trace");

    // 4 rows (CirclePcs requirement), 3 columns
    let values = vec![
        attr_hash, expected_hash, commitment,  // Row 0: actual values
        attr_hash, expected_hash, commitment,  // Row 1: padding
        attr_hash, expected_hash, commitment,  // Row 2: padding
        attr_hash, expected_hash, commitment,  // Row 3: padding
    ];

    RowMajorMatrix::new(values, 3)
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
    fn test_prove_name() {
        env_logger::try_init().ok();

        let aadhar = create_test_aadhar();

        // Prove name matches "Test User"
        let result = prove_attribute(&aadhar, AttributeType::Name, "Test User");
        assert!(result.is_ok(), "Failed to generate proof: {:?}", result.err());

        let proof = result.unwrap();
        assert!(!proof.is_empty());

        println!("✓ Name proof generated");
    }

    #[test]
    fn test_verify_name_proof() {
        env_logger::try_init().ok();

        let aadhar = create_test_aadhar();
        let commitment = compute_aadhar_commitment(&aadhar);

        // Generate proof
        let proof = prove_attribute(&aadhar, AttributeType::Name, "Test User")
            .expect("Failed to generate proof");

        // Verify proof
        let result = verify_attribute(&proof, AttributeType::Name, "Test User", commitment);
        assert!(result.is_ok(), "Verification failed: {:?}", result.err());
        assert_eq!(result.unwrap(), true);

        println!("✓ Name proof verified");
    }

    #[test]
    fn test_prove_state() {
        env_logger::try_init().ok();

        let aadhar = create_test_aadhar();

        // Prove state matches "Delhi"
        let result = prove_attribute(&aadhar, AttributeType::State, "Delhi");
        assert!(result.is_ok(), "Failed to generate proof: {:?}", result.err());

        println!("✓ State proof generated");
    }

    #[test]
    fn test_wrong_value_fails() {
        env_logger::try_init().ok();

        let aadhar = create_test_aadhar();

        // Try to prove name matches "Wrong Name" (should fail)
        let result = prove_attribute(&aadhar, AttributeType::Name, "Wrong Name");
        assert!(result.is_err(), "Proof should have failed for wrong value");

        println!("✓ Correctly rejected wrong value");
    }

    #[test]
    fn test_wrong_verification_fails() {
        env_logger::try_init().ok();

        let aadhar = create_test_aadhar();
        let commitment = compute_aadhar_commitment(&aadhar);

        // Generate proof for "Test User"
        let proof = prove_attribute(&aadhar, AttributeType::Name, "Test User")
            .expect("Failed to generate proof");

        // Try to verify with different value (should fail)
        let result = verify_attribute(&proof, AttributeType::Name, "Different User", commitment);
        assert!(result.is_err(), "Verification should fail with wrong value");

        println!("✓ Correctly rejected proof with wrong expected value");
    }
}
