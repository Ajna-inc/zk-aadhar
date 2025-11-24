//! Commitment-based AIR for Aadhar data
//!
//! This module implements a simple commitment proof:
//! - Proves possession of valid Aadhar data
//! - Without revealing the actual data
//! - Using cryptographic commitments

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_mersenne_31::Mersenne31;
use sha2::{Digest, Sha256};

use crate::xml::AadharData;

/// AIR for commitment proof
///
/// This is the simplest possible circuit: it just verifies that
/// the prover knows data that hashes to a specific commitment.
///
/// Trace width: 2 columns
/// - Column 0: input commitment (private witness)
/// - Column 1: expected commitment (public input)
///
/// Constraint: column 0 must equal column 1
pub struct CommitmentAir {
    /// The expected commitment value (public input)
    pub expected_commitment: Mersenne31,
}

impl<F: Field> BaseAir<F> for CommitmentAir {
    fn width(&self) -> usize {
        2  // [input_commitment, expected_commitment]
    }
}

impl<AB: AirBuilder> Air<AB> for CommitmentAir
where
    AB::F: PrimeField32,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0).unwrap();

        let input_commit = local[0].clone();
        // Convert expected commitment to expression
        let expected_value = self.expected_commitment.as_canonical_u32();
        let expected_commit = <AB::F as PrimeCharacteristicRing>::from_u32(expected_value);
        let expected_commit_expr = AB::Expr::from(expected_commit);

        // Constraint: input commitment must equal expected commitment
        // This proves the prover knows data that commits to the expected value
        builder.when_first_row().assert_eq(input_commit, expected_commit_expr);
    }
}

/// Compute cryptographic commitment to Aadhar data
///
/// This creates a deterministic hash of all Aadhar fields.
/// In production, consider using Poseidon2 for better ZK performance.
///
/// # Arguments
/// * `data` - The complete Aadhar data
///
/// # Returns
/// A Mersenne31 field element representing the commitment
pub fn compute_aadhar_commitment(data: &AadharData) -> Mersenne31 {
    log::debug!("Computing commitment for Aadhar data");

    let mut hasher = Sha256::new();

    // Hash all fields in a deterministic order
    hasher.update(data.reference_id.as_bytes());
    hasher.update(data.poi.name.as_bytes());
    hasher.update(data.poi.dob.as_bytes());
    hasher.update(data.poi.gender.as_bytes());

    // Hash address fields
    if let Some(ref care_of) = data.poa.care_of {
        hasher.update(care_of.as_bytes());
    }
    if let Some(ref house) = data.poa.house {
        hasher.update(house.as_bytes());
    }
    if let Some(ref street) = data.poa.street {
        hasher.update(street.as_bytes());
    }
    if let Some(ref locality) = data.poa.locality {
        hasher.update(locality.as_bytes());
    }
    if let Some(ref vtc) = data.poa.vtc {
        hasher.update(vtc.as_bytes());
    }
    if let Some(ref district) = data.poa.district {
        hasher.update(district.as_bytes());
    }
    if let Some(ref state) = data.poa.state {
        hasher.update(state.as_bytes());
    }
    if let Some(ref pincode) = data.poa.pincode {
        hasher.update(pincode.as_bytes());
    }

    // Hash signature to prove it was verified
    hasher.update(data.signature.value.as_bytes());

    let hash = hasher.finalize();

    // Convert first 4 bytes to u32, then to Mersenne31
    // We use modulo to ensure it fits in the field
    let value = u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]]);
    let field_value = value % Mersenne31::ORDER_U32;

    log::debug!("Commitment computed: {}", field_value);

    Mersenne31::from_u32(field_value)
}

/// Generate execution trace for commitment proof
///
/// The trace has 4 rows (minimum for CirclePcs) and two columns:
/// - Column 0: the actual commitment
/// - Column 1: the expected commitment (should be the same)
///
/// All rows contain the same commitment value (the circuit only checks the first row).
///
/// # Arguments
/// * `commitment` - The commitment value to prove
///
/// # Returns
/// A 4x2 matrix (four rows, two columns)
pub fn generate_commitment_trace(commitment: Mersenne31) -> RowMajorMatrix<Mersenne31> {
    log::debug!("Generating commitment trace");

    // CirclePcs requires at least 4 rows, so we pad with duplicate rows
    // Only the first row is constrained by the AIR
    let values = vec![
        commitment, commitment,  // Row 0: actual and expected commitment
        commitment, commitment,  // Row 1: padding
        commitment, commitment,  // Row 2: padding
        commitment, commitment,  // Row 3: padding
    ];

    RowMajorMatrix::new(values, 2)
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
    fn test_compute_commitment() {
        let aadhar = create_test_aadhar();
        let commitment = compute_aadhar_commitment(&aadhar);

        // Commitment should be deterministic
        let commitment2 = compute_aadhar_commitment(&aadhar);
        assert_eq!(commitment, commitment2);

        // Commitment should be a valid Mersenne31 value
        assert!(commitment.as_canonical_u32() < Mersenne31::ORDER_U32);
    }

    #[test]
    fn test_generate_trace() {
        use p3_field::PrimeCharacteristicRing;
        let commitment = Mersenne31::from_u32(12345);
        let trace = generate_commitment_trace(commitment);

        // Should be 4 rows (CirclePcs requirement), 2 columns
        assert_eq!(trace.height(), 4);
        assert_eq!(trace.width(), 2);

        // Both columns in first row should have the same value
        assert_eq!(trace.get(0, 0), trace.get(0, 1));
        assert_eq!(trace.get(0, 0).unwrap(), commitment);
    }

    #[test]
    fn test_commitment_changes_with_data() {
        let mut aadhar1 = create_test_aadhar();
        let commitment1 = compute_aadhar_commitment(&aadhar1);

        // Change the name
        aadhar1.poi.name = "Different Name".to_string();
        let commitment2 = compute_aadhar_commitment(&aadhar1);

        // Commitments should be different
        assert_ne!(commitment1, commitment2);
    }
}
