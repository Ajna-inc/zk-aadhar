//! Verify Aadhar XML signatures using W3C XMLDSig standard.
//!
//! Aadhar files are signed with RSA-SHA1, use SHA256 digests, and C14N canonicalization.

use crate::error::{AadharError, Result};
use crate::crypto::c14n;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rsa::{RsaPublicKey, Pkcs1v15Sign, traits::PublicKeyParts};
use sha1::Sha1;
use sha2::Sha256;
use digest::Digest;
use quick_xml::Reader;
use quick_xml::events::Event;
use x509_parser::prelude::*;
use num_bigint_dig::BigUint;

/// Verify the Aadhar XML signature - returns true if authentic, false/error otherwise.
pub fn verify_xmldsig(xml_content: &str) -> Result<bool> {
    log::info!("Verifying XML Digital Signature (XMLDSig)");

    // Extract and canonicalize the signed portion
    let signed_info = c14n::extract_signed_info(xml_content)?;
    let signed_info_canonical = c14n::canonicalize_exclusive(&signed_info)?;
    log::debug!("SignedInfo canonical length: {} bytes", signed_info_canonical.len());

    let signature_value = extract_element_text(xml_content, "SignatureValue")?;
    log::debug!("SignatureValue length: {} chars", signature_value.len());

    // Clean up whitespace and XML entities from the base64 signature
    let signature_clean = signature_value
        .replace("&#13;", "")
        .replace("\n", "")
        .replace("\r", "")
        .replace(" ", "")
        .replace("\t", "");

    let signature_bytes = BASE64.decode(&signature_clean)
        .map_err(|e| AadharError::CryptoError(format!("Failed to decode signature: {}", e)))?;

    log::info!("✓ Signature decoded: {} bytes", signature_bytes.len());

    // Step 4: Hash the canonicalized SignedInfo with SHA1
    // (SignatureMethod is "rsa-sha1", so we hash SignedInfo with SHA1)
    let mut hasher = Sha1::new();
    hasher.update(signed_info_canonical.as_bytes());
    let hash = hasher.finalize();

    log::debug!("SignedInfo SHA1 hash: {}", hex::encode(&hash));

    // Step 5: Extract and load the embedded certificate from XML
    let public_key = extract_embedded_certificate(xml_content)?;
    let padding = Pkcs1v15Sign::new::<Sha1>();

    log::info!("Verifying RSA-SHA1 signature with embedded certificate...");
    public_key.verify(padding, &hash, &signature_bytes)
        .map_err(|e| AadharError::SignatureVerificationFailed(format!(
            "RSA verification failed: {}. This could mean: \
            1) XML was tampered with, \
            2) Wrong UIDAI certificate, or \
            3) Signature format issue",
            e
        )))?;

    log::info!("✓ Signature verification SUCCESSFUL!");

    // Step 6: Optional - verify the DigestValue matches the XML content
    // This ensures the XML content hash is correct
    verify_digest_value(xml_content)?;

    Ok(true)
}

/// Verify that the DigestValue in SignedInfo matches the actual XML content hash
fn verify_digest_value(xml_content: &str) -> Result<()> {
    log::info!("Verifying DigestValue (SHA256 of canonicalized XML)...");

    // Extract expected DigestValue
    let expected_digest = extract_element_text(xml_content, "DigestValue")?;
    let expected_digest_bytes = BASE64.decode(&expected_digest)
        .map_err(|e| AadharError::CryptoError(format!("Failed to decode DigestValue: {}", e)))?;

    log::debug!("Expected DigestValue: {}", hex::encode(&expected_digest_bytes));

    // Remove Signature element and canonicalize with C14N 1.0 (inclusive)
    let canonical_xml = c14n::canonicalize_without_signature(xml_content)?;

    // Hash the canonicalized XML with SHA256
    let mut hasher = Sha256::new();
    hasher.update(canonical_xml.as_bytes());
    let actual_digest = hasher.finalize();

    log::debug!("Actual XML SHA256: {}", hex::encode(&actual_digest));

    // Compare
    if expected_digest_bytes.as_slice() == actual_digest.as_slice() {
        log::info!("✓ DigestValue matches XML content hash");
        Ok(())
    } else {
        log::warn!("✗ DigestValue mismatch");
        log::warn!("  Expected: {}", hex::encode(&expected_digest_bytes));
        log::warn!("  Actual:   {}", hex::encode(&actual_digest));
        Err(AadharError::SignatureVerificationFailed(
            "DigestValue does not match XML content hash".to_string()
        ))
    }
}

/// Extract text content from an XML element
fn extract_element_text(xml_content: &str, element_name: &str) -> Result<String> {
    let mut reader = Reader::from_str(xml_content);
    reader.config_mut().trim_text(false); // Don't trim - we need exact content

    let mut buf = Vec::new();
    let mut in_element = false;
    let mut text_content = String::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                if String::from_utf8_lossy(e.name().as_ref()) == element_name {
                    in_element = true;
                }
            }
            Ok(Event::Text(e)) if in_element => {
                text_content.push_str(&e.unescape()?.to_string());
            }
            Ok(Event::End(e)) => {
                if String::from_utf8_lossy(e.name().as_ref()) == element_name {
                    return Ok(text_content);
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(AadharError::XmlParseError(e.to_string())),
            _ => {}
        }
        buf.clear();
    }

    Err(AadharError::MissingField(element_name.to_string()))
}

/// Extract the X509 certificate embedded in the XML signature and return public key
fn extract_embedded_certificate(xml_content: &str) -> Result<RsaPublicKey> {
    log::info!("Extracting embedded X509 certificate from signature...");

    // Extract the X509Certificate element
    let cert_b64 = extract_element_text(xml_content, "X509Certificate")?;

    // Remove &#13; entities and whitespace
    let cert_clean = cert_b64
        .replace("&#13;", "")
        .replace("\n", "")
        .replace("\r", "")
        .replace(" ", "")
        .replace("\t", "");

    // Decode base64
    let cert_der = BASE64.decode(&cert_clean)
        .map_err(|e| AadharError::CryptoError(format!("Failed to decode certificate: {}", e)))?;

    log::debug!("Certificate DER size: {} bytes", cert_der.len());

    // Parse X509 certificate
    let (_, cert) = X509Certificate::from_der(&cert_der)
        .map_err(|e| AadharError::CryptoError(format!("Failed to parse X509 certificate: {}", e)))?;

    // Extract subject
    let subject = cert.subject().to_string();
    log::info!("Certificate subject: {}", subject);

    // Extract public key from certificate
    let public_key_info = cert.public_key();

    // The public key is in SubjectPublicKeyInfo (SPKI) format
    // Extract the bit string data
    let public_key_der = &public_key_info.subject_public_key.data;

    // Use x509-parser's built-in RSA public key parsing
    use x509_parser::public_key::RSAPublicKey;
    use nom::Finish;

    let (_, rsa_key) = RSAPublicKey::from_der(&public_key_der)
        .finish()
        .map_err(|e| AadharError::CryptoError(format!("Failed to parse RSA key: {:?}", e)))?;

    // Convert to rsa crate's RsaPublicKey
    let n = BigUint::from_bytes_be(rsa_key.modulus);
    let e = BigUint::from_bytes_be(rsa_key.exponent);

    let public_key = rsa::RsaPublicKey::new(n, e)
        .map_err(|e| AadharError::CryptoError(format!("Failed to create RSA public key: {}", e)))?;

    log::info!("✓ Extracted RSA public key from embedded certificate");
    log::debug!("  Key size: {} bits", public_key.size() * 8);

    Ok(public_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_element_text() {
        let xml = r#"<Root><Value>test content</Value></Root>"#;
        let result = extract_element_text(xml, "Value").unwrap();
        assert_eq!(result, "test content");
    }

    #[test]
    fn test_extract_element_with_entities() {
        let xml = r#"<Root><Value>line1&#13;
line2</Value></Root>"#;
        let result = extract_element_text(xml, "Value").unwrap();
        assert!(result.contains("line1"));
    }

    #[test]
    fn test_verify_real_aadhar_signature() {
        use std::io::Read;
        env_logger::try_init().ok();

        let file = std::fs::File::open("../../tests/fixtures/offlineaadhaar20251123074351915.zip").unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();
        let mut zip_file = archive.by_index_decrypt(0, b"1111").unwrap();

        let mut xml_content = String::new();
        std::io::Read::read_to_string(&mut zip_file, &mut xml_content).unwrap();

        let result = verify_xmldsig(&xml_content);
        assert!(result.is_ok(), "Signature verification failed: {:?}", result.err());
        assert!(result.unwrap(), "Signature should be valid");
    }

    #[test]
    fn test_extract_element_not_found() {
        let xml = r#"<Root><Value>test</Value></Root>"#;
        let result = extract_element_text(xml, "NonExistent");
        assert!(result.is_err());
    }
}
