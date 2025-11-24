//! Node.js bindings for Aadhar ZK Proof System
//!
//! This crate provides JavaScript/TypeScript bindings using napi-rs.

#![deny(clippy::all)]

use napi::bindgen_prelude::*;
use napi_derive::napi;

use aadhar_core::{
    xml::parse_aadhar_xml as core_parse_aadhar_xml,
    circuit::{
        age_proof::{prove_age_above_with_context, verify_age_above_with_context, create_didcomm_response as age_create_response},
        range_proof::{prove_age_range_with_context, verify_age_range_with_context, create_didcomm_response as range_create_response},
        commitment::compute_aadhar_commitment,
    },
    didcomm::{ProofContext as CoreProofContext, DIDCommProofResponse as CoreDIDCommResponse},
};
use p3_mersenne_31::Mersenne31;
use p3_field::{PrimeField32, PrimeCharacteristicRing};

// ============================================================================
// Type Conversions and Wrappers
// ============================================================================

/// Aadhar data parsed from XML
#[napi(object)]
pub struct AadharData {
    /// Reference ID
    pub reference_id: String,
    /// Person's name
    pub name: String,
    /// Date of birth (DD-MM-YYYY)
    pub dob: String,
    /// Gender
    pub gender: String,
    /// Age in years (if DOB parsed successfully)
    pub age: Option<u32>,
    /// Commitment to Aadhar data
    pub commitment: u32,
    /// XML digital signature verified
    pub signature_verified: bool,
}

/// DIDComm proof context for replay prevention
#[napi(object)]
pub struct ProofContext {
    /// 32-byte nonce (hex string)
    pub nonce: String,
    /// 32-byte context hash (hex string)
    pub context_hash: String,
    /// 16-byte session ID (hex string)
    pub session_id: String,
}

/// Proof metadata
#[napi(object)]
pub struct ProofMetadata {
    /// Circuit identifier (e.g., "aadhaar-age-threshold-v1")
    pub circuit_id: String,
    /// Verifying key hash (hex string)
    pub vk_hash: String,
    /// Public outputs hash (hex string)
    pub outputs_hash: String,
    /// Proof size in bytes
    pub proof_size_bytes: u32,
    /// ZK scheme ("stark")
    pub scheme: String,
    /// Generation time in milliseconds
    pub generation_time_ms: Option<f64>,
}

/// Proof result with metadata
#[napi(object)]
pub struct ProofResult {
    /// Proof bytes (base64 encoded)
    pub proof: String,
    /// Proof metadata
    pub metadata: ProofMetadata,
}

/// Complete DIDComm proof response
#[napi(object)]
pub struct DIDCommProofResponse {
    /// Program ID
    pub program_id: String,
    /// Result ("pass" or "fail")
    pub result: String,
    /// Public inputs/outputs
    pub public: PublicInputs,
    /// Zero-knowledge proof
    pub zk: ZKProof,
}

#[napi(object)]
pub struct PublicInputs {
    pub nonce: String,
    pub context_hash: String,
    pub session_id: String,
    pub outputs_hash: String,
    pub vk_hash: String,
    pub commitment: u32,
}

#[napi(object)]
pub struct ZKProof {
    pub scheme: String,
    pub circuit_id: String,
    pub vk_hash: String,
    pub proof_b64: String,
}

// Helper functions for conversion
fn decode_hex_32(hex_str: &str) -> Result<[u8; 32]> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(hex_str)
        .map_err(|e| Error::from_reason(format!("Invalid hex: {}", e)))?;

    if bytes.len() != 32 {
        return Err(Error::from_reason(format!(
            "Expected 32 bytes, got {}",
            bytes.len()
        )));
    }

    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes);
    Ok(array)
}

fn decode_hex_16(hex_str: &str) -> Result<[u8; 16]> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(hex_str)
        .map_err(|e| Error::from_reason(format!("Invalid hex: {}", e)))?;

    if bytes.len() != 16 {
        return Err(Error::from_reason(format!(
            "Expected 16 bytes, got {}",
            bytes.len()
        )));
    }

    let mut array = [0u8; 16];
    array.copy_from_slice(&bytes);
    Ok(array)
}

fn context_from_js(ctx: &ProofContext) -> Result<CoreProofContext> {
    let nonce = decode_hex_32(&ctx.nonce)?;
    let context_hash = decode_hex_32(&ctx.context_hash)?;
    let session_id = decode_hex_16(&ctx.session_id)?;

    Ok(CoreProofContext::new(nonce, context_hash, session_id))
}

// ============================================================================
// Exported Functions
// ============================================================================

/// Parse Aadhar XML data
///
/// # Arguments
/// * `xmlContent` - Raw XML string from Aadhar file
///
/// # Returns
/// Parsed Aadhar data with commitment
///
/// # Example
/// ```javascript
/// const aadhar = parseAadharXml(xmlString);
/// console.log('Name:', aadhar.name);
/// console.log('Age:', aadhar.age);
/// console.log('Commitment:', aadhar.commitment);
/// ```
#[napi]
pub fn parse_aadhar_xml(xml_content: String) -> Result<AadharData> {
    let aadhar_data = core_parse_aadhar_xml(&xml_content)
        .map_err(|e| Error::from_reason(format!("Failed to parse XML: {}", e)))?;

    let commitment = compute_aadhar_commitment(&aadhar_data).as_canonical_u32();

    Ok(AadharData {
        reference_id: aadhar_data.reference_id,
        name: aadhar_data.poi.name.clone(),
        dob: aadhar_data.poi.dob.clone(),
        gender: aadhar_data.poi.gender.clone(),
        age: aadhar_data.poi.age(),
        commitment,
        signature_verified: aadhar_data.signature.verified,
    })
}

/// Generate age threshold proof with DIDComm context binding
///
/// # Arguments
/// * `xmlContent` - Raw XML string
/// * `minAge` - Minimum age threshold
/// * `context` - DIDComm proof context (nonce, context_hash, session_id)
///
/// # Returns
/// Proof result with base64-encoded proof and metadata
///
/// # Example
/// ```javascript
/// const proof = await proveAgeThreshold(xmlString, 18, {
///   nonce: '0x' + randomBytes(32).toString('hex'),
///   contextHash: '0x' + sha256(contextData).toString('hex'),
///   sessionId: '0x' + randomBytes(16).toString('hex')
/// });
/// ```
#[napi]
pub fn prove_age_threshold(
    xml_content: String,
    min_age: u32,
    context: ProofContext,
) -> Result<ProofResult> {
    // Parse XML
    let aadhar_data = core_parse_aadhar_xml(&xml_content)
        .map_err(|e| Error::from_reason(format!("Failed to parse XML: {}", e)))?;

    // Convert context
    let core_context = context_from_js(&context)?;

    // Generate proof
    let (proof_bytes, metadata) = prove_age_above_with_context(&aadhar_data, min_age, &core_context)
        .map_err(|e| Error::from_reason(format!("Failed to generate proof: {}", e)))?;

    // Encode proof as base64
    use base64::{engine::general_purpose::STANDARD, Engine};
    let proof_b64 = STANDARD.encode(&proof_bytes);

    Ok(ProofResult {
        proof: proof_b64,
        metadata: ProofMetadata {
            circuit_id: metadata.circuit_id,
            vk_hash: metadata.vk_hash,
            outputs_hash: metadata.outputs_hash,
            proof_size_bytes: metadata.proof_size_bytes as u32,
            scheme: metadata.scheme,
            generation_time_ms: metadata.generation_time_ms.map(|t| t as f64),
        },
    })
}

/// Generate age range proof with DIDComm context binding
///
/// # Arguments
/// * `xmlContent` - Raw XML string
/// * `minAge` - Minimum age
/// * `maxAge` - Maximum age
/// * `context` - DIDComm proof context
///
/// # Example
/// ```javascript
/// const proof = await proveAgeRange(xmlString, 18, 65, context);
/// ```
#[napi]
pub fn prove_age_range(
    xml_content: String,
    min_age: u32,
    max_age: u32,
    context: ProofContext,
) -> Result<ProofResult> {
    let aadhar_data = core_parse_aadhar_xml(&xml_content)
        .map_err(|e| Error::from_reason(format!("Failed to parse XML: {}", e)))?;

    let core_context = context_from_js(&context)?;

    let (proof_bytes, metadata) = prove_age_range_with_context(&aadhar_data, min_age, max_age, &core_context)
        .map_err(|e| Error::from_reason(format!("Failed to generate proof: {}", e)))?;

    use base64::{engine::general_purpose::STANDARD, Engine};
    let proof_b64 = STANDARD.encode(&proof_bytes);

    Ok(ProofResult {
        proof: proof_b64,
        metadata: ProofMetadata {
            circuit_id: metadata.circuit_id,
            vk_hash: metadata.vk_hash,
            outputs_hash: metadata.outputs_hash,
            proof_size_bytes: metadata.proof_size_bytes as u32,
            scheme: metadata.scheme,
            generation_time_ms: metadata.generation_time_ms.map(|t| t as f64),
        },
    })
}

/// Create DIDComm proof response for age threshold proof
///
/// # Arguments
/// * `proofResult` - Proof result from proveAgeThreshold
/// * `context` - Same context used for proof generation
/// * `minAge` - Same min age used for proof generation
///
/// # Returns
/// Complete DIDComm PoE response ready to send
///
/// # Example
/// ```javascript
/// const response = createDIDCommResponse(proofResult, context, 18);
/// await sendDIDCommMessage(response);
/// ```
#[napi]
pub fn create_didcomm_age_response(
    xml_content: String,
    proof_result: ProofResult,
    context: ProofContext,
    min_age: u32,
) -> Result<DIDCommProofResponse> {
    // Parse XML to get commitment
    let aadhar_data = core_parse_aadhar_xml(&xml_content)
        .map_err(|e| Error::from_reason(format!("Failed to parse XML: {}", e)))?;

    let commitment = compute_aadhar_commitment(&aadhar_data).as_canonical_u32();
    let core_context = context_from_js(&context)?;

    // Decode proof from base64
    use base64::{engine::general_purpose::STANDARD, Engine};
    let proof_bytes = STANDARD.decode(&proof_result.proof)
        .map_err(|e| Error::from_reason(format!("Invalid proof base64: {}", e)))?;

    // Convert metadata
    let core_metadata = aadhar_core::didcomm::ProofMetadata {
        circuit_id: proof_result.metadata.circuit_id,
        vk_hash: proof_result.metadata.vk_hash,
        outputs_hash: proof_result.metadata.outputs_hash,
        proof_size_bytes: proof_result.metadata.proof_size_bytes as usize,
        scheme: proof_result.metadata.scheme,
        generation_time_ms: proof_result.metadata.generation_time_ms.map(|t| t as u64),
    };

    // Create DIDComm response
    let response = age_create_response(proof_bytes, core_metadata, &core_context, commitment, min_age);

    // Convert to JS object
    Ok(DIDCommProofResponse {
        program_id: response.program_id,
        result: response.result,
        public: PublicInputs {
            nonce: response.public.nonce,
            context_hash: response.public.context_hash,
            session_id: response.public.session_id,
            outputs_hash: response.public.outputs_hash,
            vk_hash: response.public.vk_hash,
            commitment: response.public.commitment,
        },
        zk: ZKProof {
            scheme: response.zk.scheme,
            circuit_id: response.zk.circuit_id,
            vk_hash: response.zk.vk_hash,
            proof_b64: response.zk.proof_b64,
        },
    })
}

/// Verify age threshold proof with context
///
/// # Arguments
/// * `proofBase64` - Base64-encoded proof
/// * `minAge` - Minimum age threshold
/// * `commitment` - Commitment value
/// * `context` - DIDComm context
/// * `outputsHash` - Expected outputs hash (hex string)
///
/// # Returns
/// true if proof is valid, throws error otherwise
#[napi]
pub fn verify_age_threshold(
    proof_base64: String,
    min_age: u32,
    commitment: u32,
    context: ProofContext,
    outputs_hash: String,
) -> Result<bool> {
    use base64::{engine::general_purpose::STANDARD, Engine};

    let proof_bytes = STANDARD.decode(&proof_base64)
        .map_err(|e| Error::from_reason(format!("Invalid proof base64: {}", e)))?;

    let core_context = context_from_js(&context)?;
    let outputs_hash_bytes = decode_hex_32(&outputs_hash)?;
    let commitment_field = Mersenne31::from_u32(commitment);

    verify_age_above_with_context(
        &proof_bytes,
        min_age,
        commitment_field,
        &core_context,
        &outputs_hash_bytes,
    )
    .map_err(|e| Error::from_reason(format!("Verification failed: {}", e)))
}

/// Get library version
#[napi]
pub fn get_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
