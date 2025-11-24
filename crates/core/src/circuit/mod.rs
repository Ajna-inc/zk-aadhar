//! Zero-Knowledge proof circuits for Aadhar verification
//!
//! This module implements Plonky3-based ZK circuits for proving claims
//! about Aadhar data without revealing the actual data.
//!
//! # Available Circuits
//!
//! ## 1. Commitment Proof
//! Proves possession of valid Aadhar data:
//! - `prove_aadhar_commitment()` - Generate proof
//! - `verify_aadhar_commitment()` - Verify proof
//!
//! ## 2. Age Proof
//! Proves age is above a threshold without revealing exact age:
//! - `age_proof::prove_age_above()` - Generate age proof
//! - `age_proof::verify_age_above()` - Verify age proof
//!
//! ## 3. Range Proof
//! Proves age is within a specific range:
//! - `range_proof::prove_age_range()` - Generate range proof
//! - `range_proof::verify_age_range()` - Verify range proof
//!
//! ## 4. Attribute Proof
//! Proves specific attributes match expected values:
//! - `attribute_proof::prove_attribute()` - Generate attribute proof
//! - `attribute_proof::verify_attribute()` - Verify attribute proof
//!
//! ## 5. Batch Proof
//! Proves multiple claims in a single proof (more efficient):
//! - `batch_proof::prove_batch()` - Generate batch proof
//! - `batch_proof::verify_batch()` - Verify batch proof

pub mod config;
pub mod commitment;
pub mod prover;
pub mod verifier;
pub mod age_proof;
pub mod range_proof;
pub mod attribute_proof;
pub mod batch_proof;

pub use config::{create_config, AadharConfig};
pub use commitment::{compute_aadhar_commitment, CommitmentAir};
pub use prover::prove_aadhar_commitment;
pub use verifier::verify_aadhar_commitment;
