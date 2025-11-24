//! Proof generation for Aadhar ZK circuits

use p3_field::PrimeField32;
use p3_matrix::Matrix;
use p3_uni_stark::prove;

use crate::circuit::{
    commitment::{compute_aadhar_commitment, generate_commitment_trace, CommitmentAir},
    config::create_config,
};
use crate::error::{AadharError, Result};
use crate::xml::AadharData;

/// Generate a ZK proof of Aadhar commitment
///
/// This proves that the prover possesses valid Aadhar data that commits
/// to a specific value, without revealing the actual data.
///
/// # Arguments
/// * `aadhar_data` - The complete Aadhar data to prove
///
/// # Returns
/// Serialized proof bytes that can be verified by anyone
///
/// # Example
/// ```no_run
/// use aadhar_core::circuit::prove_aadhar_commitment;
/// use aadhar_core::xml::parse_aadhar_zip;
///
/// let aadhar_data = parse_aadhar_zip("aadhar.zip", "1234")?;
/// let proof = prove_aadhar_commitment(&aadhar_data)?;
/// println!("Proof size: {} bytes", proof.len());
/// # Ok::<(), aadhar_core::error::AadharError>(())
/// ```
pub fn prove_aadhar_commitment(aadhar_data: &AadharData) -> Result<Vec<u8>> {
    log::info!("Generating ZK proof for Aadhar data");
    log::debug!("Name: {}, DOB: {}", aadhar_data.poi.name, aadhar_data.poi.dob);

    // Step 1: Compute commitment to the Aadhar data
    let commitment = compute_aadhar_commitment(aadhar_data);
    log::info!("✓ Computed commitment: {}", commitment.as_canonical_u32());

    // Step 2: Create AIR with the expected commitment
    let air = CommitmentAir {
        expected_commitment: commitment,
    };

    // Step 3: Generate execution trace
    let trace = generate_commitment_trace(commitment);
    log::info!("✓ Generated execution trace: {}x{}", trace.height(), trace.width());

    // Step 4: Setup Plonky3 configuration
    let config = create_config();

    // Step 5: Generate the proof
    log::info!("Generating proof (this may take a few seconds)...");
    let start = std::time::Instant::now();

    let proof = prove(&config, &air, trace, &vec![]);

    let duration = start.elapsed();
    log::info!("✓ Proof generated in {:.2?}", duration);

    // Step 6: Serialize the proof
    let proof_bytes = bincode::serialize(&proof)
        .map_err(|e| AadharError::Other(format!("Failed to serialize proof: {}", e)))?;

    log::info!("✓ Proof size: {} bytes ({:.2} KB)", proof_bytes.len(), proof_bytes.len() as f64 / 1024.0);

    Ok(proof_bytes)
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
    fn test_prove_aadhar_commitment() {
        env_logger::try_init().ok();

        let aadhar = create_test_aadhar();
        let result = prove_aadhar_commitment(&aadhar);

        assert!(result.is_ok(), "Failed to generate proof: {:?}", result.err());

        let proof = result.unwrap();
        assert!(!proof.is_empty(), "Proof should not be empty");
        assert!(proof.len() > 100, "Proof seems too small");
        assert!(proof.len() < 500_000, "Proof seems too large");

        println!("✓ Proof generated successfully");
        println!("  Size: {} bytes ({:.2} KB)", proof.len(), proof.len() as f64 / 1024.0);
    }
}
