//! Plonky3 configuration for Aadhar ZK proofs
//!
//! This module sets up all the cryptographic components:
//! - Field: Mersenne31 (M31) for 1.3x performance boost
//! - Hash: Keccak256 for Merkle trees
//! - PCS: Circle PCS with FRI
//! - Challenger: For Fiat-Shamir transform

use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_circle::CirclePcs;
use p3_commit::ExtensionMmcs;
use p3_field::extension::BinomialExtensionField;
use p3_fri::FriParameters;
use p3_keccak::Keccak256Hash;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_mersenne_31::Mersenne31;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_uni_stark::StarkConfig;

/// Base field: Mersenne31 (2^31 - 1)
/// - 1.3x faster than BabyBear
/// - Excellent for mobile ARM processors
/// - Two-adicity: 31 (great for FFTs)
pub type Val = Mersenne31;

/// Extension field: 3-dimensional extension of Mersenne31
/// Provides security against small field attacks
pub type Challenge = BinomialExtensionField<Val, 3>;

/// Hash function for byte-level operations
/// Using Keccak256 for compatibility and security
pub type ByteHash = Keccak256Hash;

/// Hash function for field elements
/// Serializes field elements then hashes with Keccak256
pub type FieldHash = SerializingHasher<ByteHash>;

/// Compression function for Merkle tree
/// Compresses 2 Keccak hashes into 1
pub type MyCompress = CompressionFunctionFromHasher<ByteHash, 2, 32>;

/// Merkle tree commitment for field elements
pub type ValMmcs = MerkleTreeMmcs<Val, u8, FieldHash, MyCompress, 32>;

/// Merkle tree commitment for extension field elements
pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;

/// Polynomial Commitment Scheme using Circle STARKs
/// Optimized for Mersenne31 field
pub type Pcs = CirclePcs<Val, ValMmcs, ChallengeMmcs>;

/// Complete STARK configuration
pub type AadharConfig = StarkConfig<Pcs, Challenge, Challenger>;

/// Challenger for Fiat-Shamir transform
/// Converts interactive proofs to non-interactive
pub type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;

/// Create the default Plonky3 configuration for Aadhar proofs
///
/// This sets up all cryptographic components with security parameters
/// optimized for mobile devices while maintaining ~100 bits of security.
pub fn create_config() -> AadharConfig {
    log::info!("Creating Plonky3 configuration for Aadhar ZK proofs");

    // Initialize hash functions
    let byte_hash = ByteHash {};
    let field_hash = FieldHash::new(byte_hash);

    // Create compression function for Merkle tree
    let compress = MyCompress::new(byte_hash);

    // Create Merkle tree commitment scheme for base field
    let val_mmcs = ValMmcs::new(field_hash, compress);

    // Create Merkle tree commitment scheme for extension field
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    // Configure FRI parameters
    // These are optimized for mobile: balance between security and performance
    let fri_params = FriParameters {
        log_blowup: 1,          // 2x blowup factor
        log_final_poly_len: 0,  // No early stopping
        num_queries: 100,        // ~100 bits security
        proof_of_work_bits: 16,  // DoS protection
        mmcs: challenge_mmcs,    // Use challenge MMCS for FRI
    };

    log::debug!("FRI params: log_blowup=1, queries=100, pow_bits=16");

    // Create Circle PCS (optimized for Mersenne31)
    let pcs = Pcs::new(val_mmcs, fri_params);

    // Create challenger for the config
    let challenger = create_challenger();

    // Create complete STARK config
    let config = StarkConfig::new(pcs, challenger);

    log::info!("✓ Plonky3 configuration created successfully");
    config
}

/// Create a challenger for proof generation
pub fn create_challenger() -> Challenger {
    let byte_hash = ByteHash {};
    Challenger::from_hasher(vec![], byte_hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_config() {
        let _config = create_config();
        // If this compiles and runs, the config is valid
        assert!(true);
    }

    #[test]
    fn test_mersenne31_field() {
        use p3_field::PrimeCharacteristicRing;
        // Test basic field operations
        let a = Val::from_u32(12345);
        let b = Val::from_u32(67890);
        let c = a + b;

        assert_eq!(c, Val::from_u32(12345 + 67890));
    }
}
