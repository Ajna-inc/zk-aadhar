//! DIDComm integration for Proof-of-Execution protocol
//!
//! This module provides context binding and metadata for integrating
//! Aadhar ZK proofs with the DIDComm Proof-of-Execution (PoE) protocol.

use crate::error::{AadharError, Result};
use sha2::{Sha256, Digest};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};

/// Context for binding proofs to specific sessions/requests
///
/// This prevents replay attacks by cryptographically tying each proof
/// to a specific context. Without the correct nonce, context_hash, and
/// session_id, a proof can't be reused elsewhere.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofContext {
    /// Random 32-byte nonce from the verifier
    pub nonce: [u8; 32],
    /// SHA256 hash of the request context
    pub context_hash: [u8; 32],
    /// 16-byte session identifier
    pub session_id: [u8; 16],
}

impl ProofContext {
    /// Create a new proof context
    pub fn new(nonce: [u8; 32], context_hash: [u8; 32], session_id: [u8; 16]) -> Self {
        Self {
            nonce,
            context_hash,
            session_id,
        }
    }

    /// Compute a binding hash from the context
    ///
    /// This hash is included in the proof to cryptographically tie it
    /// to this specific context. The verifier will recompute this hash
    /// and check it matches.
    pub fn binding_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.nonce);
        hasher.update(&self.context_hash);
        hasher.update(&self.session_id);
        hasher.finalize().into()
    }

    /// Encode context as hex strings for DIDComm transport
    pub fn to_hex_strings(&self) -> ProofContextHex {
        ProofContextHex {
            nonce: format!("0x{}", hex::encode(&self.nonce)),
            context_hash: format!("0x{}", hex::encode(&self.context_hash)),
            session_id: format!("0x{}", hex::encode(&self.session_id)),
        }
    }

    /// Decode context from hex strings
    pub fn from_hex_strings(hex: &ProofContextHex) -> Result<Self> {
        let nonce = decode_hex_array(&hex.nonce, "nonce")?;
        let context_hash = decode_hex_array(&hex.context_hash, "context_hash")?;
        let session_id = decode_hex_array(&hex.session_id, "session_id")?;

        Ok(Self {
            nonce,
            context_hash,
            session_id,
        })
    }
}

/// Hex-encoded version of ProofContext for JSON serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofContextHex {
    pub nonce: String,           // "0x..." (32 bytes hex)
    pub context_hash: String,    // "0x..." (32 bytes hex)
    pub session_id: String,      // "0x..." (16 bytes hex)
}

/// Metadata about a ZK proof for DIDComm PoE protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofMetadata {
    /// Circuit identifier (e.g., "aadhaar-age-threshold-v1")
    pub circuit_id: String,
    /// Hex-encoded hash of the verifying key
    pub vk_hash: String,
    /// Hex-encoded hash of public outputs
    pub outputs_hash: String,
    /// Size of the proof in bytes
    pub proof_size_bytes: usize,
    /// ZK scheme used (always "stark" for us)
    pub scheme: String,
    /// Optional: proof generation time in milliseconds
    pub generation_time_ms: Option<u64>,
}

impl ProofMetadata {
    /// Create metadata for an age threshold proof
    pub fn for_age_threshold(
        proof_bytes: &[u8],
        vk_hash: [u8; 32],
        outputs_hash: [u8; 32],
        generation_time_ms: Option<u64>,
    ) -> Self {
        Self {
            circuit_id: "aadhaar-age-threshold-v1".to_string(),
            vk_hash: format!("0x{}", hex::encode(vk_hash)),
            outputs_hash: format!("0x{}", hex::encode(outputs_hash)),
            proof_size_bytes: proof_bytes.len(),
            scheme: "stark".to_string(),
            generation_time_ms,
        }
    }

    /// Create metadata for an age range proof
    pub fn for_age_range(
        proof_bytes: &[u8],
        vk_hash: [u8; 32],
        outputs_hash: [u8; 32],
        generation_time_ms: Option<u64>,
    ) -> Self {
        Self {
            circuit_id: "aadhaar-age-range-v1".to_string(),
            vk_hash: format!("0x{}", hex::encode(vk_hash)),
            outputs_hash: format!("0x{}", hex::encode(outputs_hash)),
            proof_size_bytes: proof_bytes.len(),
            scheme: "stark".to_string(),
            generation_time_ms,
        }
    }

    /// Create metadata for an attribute proof
    pub fn for_attribute(
        proof_bytes: &[u8],
        vk_hash: [u8; 32],
        outputs_hash: [u8; 32],
        generation_time_ms: Option<u64>,
    ) -> Self {
        Self {
            circuit_id: "aadhaar-attribute-v1".to_string(),
            vk_hash: format!("0x{}", hex::encode(vk_hash)),
            outputs_hash: format!("0x{}", hex::encode(outputs_hash)),
            proof_size_bytes: proof_bytes.len(),
            scheme: "stark".to_string(),
            generation_time_ms,
        }
    }
}

/// DIDComm-compatible proof response
///
/// This is the format expected by the DIDComm PoE protocol's `submit-poe` message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DIDCommProofResponse {
    /// The program/circuit identifier
    pub program_id: String,
    /// Proof verification result ("pass" or "fail")
    pub result: String,
    /// Public inputs and outputs
    pub public: PublicInputs,
    /// Zero-knowledge proof data
    pub zk: ZKProof,
}

/// Public inputs/outputs for DIDComm PoE
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicInputs {
    /// Nonce from request (hex string)
    pub nonce: String,
    /// Context hash (hex string)
    pub context_hash: String,
    /// Session ID (hex string)
    pub session_id: String,
    /// Hash of all public outputs (hex string)
    pub outputs_hash: String,
    /// Verifying key hash (hex string)
    pub vk_hash: String,
    /// Commitment to Aadhar data
    pub commitment: u32,
}

/// Zero-knowledge proof data for DIDComm
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZKProof {
    /// ZK scheme ("stark")
    pub scheme: String,
    /// Circuit identifier
    pub circuit_id: String,
    /// Verifying key hash (hex string)
    pub vk_hash: String,
    /// Base64 URL-safe encoded proof
    pub proof_b64: String,
}

impl ZKProof {
    /// Create ZK proof structure from proof bytes
    pub fn new(circuit_id: String, vk_hash: String, proof_bytes: &[u8]) -> Self {
        let proof_b64 = URL_SAFE_NO_PAD.encode(proof_bytes);
        Self {
            scheme: "stark".to_string(),
            circuit_id,
            vk_hash,
            proof_b64,
        }
    }

    /// Decode proof bytes from base64
    pub fn decode_proof(&self) -> Result<Vec<u8>> {
        URL_SAFE_NO_PAD
            .decode(&self.proof_b64)
            .map_err(|e| AadharError::Other(format!("Failed to decode proof: {}", e)))
    }
}

/// Compute the verifying key hash for a circuit
///
/// For now, we use a placeholder based on the circuit ID.
/// In a full implementation, this would hash the actual verifying key.
pub fn compute_vk_hash(circuit_id: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"UIDAI_AADHAR_VK_V1:");
    hasher.update(circuit_id.as_bytes());
    hasher.finalize().into()
}

/// Compute the hash of public outputs
///
/// This creates a commitment to all public inputs/outputs to ensure
/// the verifier sees the same values as used in the proof.
pub fn compute_outputs_hash(
    context: &ProofContext,
    commitment: u32,
    min_age: Option<u32>,
    max_age: Option<u32>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();

    // Hash context
    hasher.update(&context.nonce);
    hasher.update(&context.context_hash);
    hasher.update(&context.session_id);

    // Hash commitment
    hasher.update(&commitment.to_le_bytes());

    // Hash age constraints if present
    if let Some(min) = min_age {
        hasher.update(&min.to_le_bytes());
    }
    if let Some(max) = max_age {
        hasher.update(&max.to_le_bytes());
    }

    hasher.finalize().into()
}

/// Helper: decode hex string to fixed-size array
fn decode_hex_array<const N: usize>(hex_str: &str, field_name: &str) -> Result<[u8; N]> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(hex_str)
        .map_err(|e| AadharError::InvalidInput(format!("Invalid hex for {}: {}", field_name, e)))?;

    if bytes.len() != N {
        return Err(AadharError::InvalidInput(format!(
            "{} must be {} bytes, got {}",
            field_name, N, bytes.len()
        )));
    }

    let mut array = [0u8; N];
    array.copy_from_slice(&bytes);
    Ok(array)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_context_binding_hash() {
        let context = ProofContext::new(
            [1u8; 32],
            [2u8; 32],
            [3u8; 16],
        );

        let hash = context.binding_hash();
        assert_eq!(hash.len(), 32);

        // Same input should give same hash
        let context2 = ProofContext::new([1u8; 32], [2u8; 32], [3u8; 16]);
        assert_eq!(hash, context2.binding_hash());

        // Different input should give different hash
        let context3 = ProofContext::new([4u8; 32], [2u8; 32], [3u8; 16]);
        assert_ne!(hash, context3.binding_hash());
    }

    #[test]
    fn test_proof_context_hex_encoding() {
        let context = ProofContext::new([0xAB; 32], [0xCD; 32], [0xEF; 16]);

        let hex = context.to_hex_strings();
        assert!(hex.nonce.starts_with("0x"));
        assert!(hex.context_hash.starts_with("0x"));
        assert!(hex.session_id.starts_with("0x"));

        // Should be able to decode back
        let decoded = ProofContext::from_hex_strings(&hex).unwrap();
        assert_eq!(decoded.nonce, context.nonce);
        assert_eq!(decoded.context_hash, context.context_hash);
        assert_eq!(decoded.session_id, context.session_id);
    }

    #[test]
    fn test_compute_vk_hash() {
        let hash1 = compute_vk_hash("aadhaar-age-threshold-v1");
        let hash2 = compute_vk_hash("aadhaar-age-threshold-v1");
        assert_eq!(hash1, hash2);

        let hash3 = compute_vk_hash("aadhaar-age-range-v1");
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_compute_outputs_hash() {
        let context = ProofContext::new([1u8; 32], [2u8; 32], [3u8; 16]);

        let hash1 = compute_outputs_hash(&context, 12345, Some(18), None);
        let hash2 = compute_outputs_hash(&context, 12345, Some(18), None);
        assert_eq!(hash1, hash2);

        // Different commitment should give different hash
        let hash3 = compute_outputs_hash(&context, 99999, Some(18), None);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_zk_proof_encoding() {
        let proof_bytes = vec![1, 2, 3, 4, 5];
        let zk = ZKProof::new(
            "aadhaar-age-threshold-v1".to_string(),
            "0xabcd".to_string(),
            &proof_bytes,
        );

        assert_eq!(zk.scheme, "stark");
        assert!(!zk.proof_b64.is_empty());

        // Should be able to decode back
        let decoded = zk.decode_proof().unwrap();
        assert_eq!(decoded, proof_bytes);
    }

    #[test]
    fn test_proof_metadata_creation() {
        let proof_bytes = vec![1, 2, 3];
        let vk_hash = [0xAB; 32];
        let outputs_hash = [0xCD; 32];

        let meta = ProofMetadata::for_age_threshold(&proof_bytes, vk_hash, outputs_hash, Some(1500));

        assert_eq!(meta.circuit_id, "aadhaar-age-threshold-v1");
        assert_eq!(meta.scheme, "stark");
        assert_eq!(meta.proof_size_bytes, 3);
        assert_eq!(meta.generation_time_ms, Some(1500));
        assert!(meta.vk_hash.starts_with("0x"));
        assert!(meta.outputs_hash.starts_with("0x"));
    }
}
