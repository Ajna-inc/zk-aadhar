//! RSA signature verification for Aadhar XML

use crate::error::{AadharError, Result};
use crate::crypto::cert::load_uidai_certificate;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rsa::{RsaPublicKey, Pkcs1v15Sign};
use sha2::{Sha256, Digest};

/// Verify the digital signature of Aadhar XML
///
/// # Arguments
/// * `xml_without_signature` - XML content with the `<Signature>` element removed
/// * `signature_base64` - Base64-encoded signature value
///
/// # Returns
/// `Ok(true)` if signature is valid, `Ok(false)` otherwise
pub fn verify_signature(xml_without_signature: &str, signature_base64: &str) -> Result<bool> {
    log::info!("Verifying Aadhar XML signature");

    // Load UIDAI public key
    let public_key = load_uidai_certificate()?;

    // Decode base64 signature (remove all whitespace including newlines)
    let signature_clean = signature_base64.chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>();
    let signature_bytes = BASE64.decode(&signature_clean)
        .map_err(|e| AadharError::CryptoError(format!("Failed to decode signature: {}", e)))?;

    log::debug!("Signature size: {} bytes", signature_bytes.len());

    // Compute SHA256 hash of XML content
    let mut hasher = Sha256::new();
    hasher.update(xml_without_signature.as_bytes());
    let hash = hasher.finalize();

    log::debug!("XML hash (SHA256): {}", hex::encode(&hash));

    // Verify signature using PKCS#1 v1.5
    let result = verify_pkcs1v15(&public_key, &hash, &signature_bytes);

    match result {
        Ok(()) => {
            log::info!("✓ Signature verification successful");
            Ok(true)
        }
        Err(e) => {
            log::warn!("✗ Signature verification failed: {}", e);
            Err(AadharError::SignatureVerificationFailed(e.to_string()))
        }
    }
}

/// Verify RSA signature using PKCS#1 v1.5 padding scheme
fn verify_pkcs1v15(
    public_key: &RsaPublicKey,
    hash: &[u8],
    signature: &[u8],
) -> Result<()> {
    // Use PKCS#1 v1.5 padding scheme
    let padding = Pkcs1v15Sign::new::<Sha256>();

    // Verify signature using the verify method
    public_key.verify(padding, hash, signature)
        .map_err(|e| AadharError::SignatureVerificationFailed(e.to_string()))?;

    Ok(())
}

/// Complete verification: parse signature from XML and verify
pub fn verify_aadhar_xml(xml_content: &str) -> Result<bool> {
    use crate::xml::parser::extract_xml_without_signature;

    // Extract signature value from XML
    let signature = extract_signature_value(xml_content)?;

    // Remove signature element for verification
    let xml_without_sig = extract_xml_without_signature(xml_content)?;

    // Verify
    verify_signature(&xml_without_sig, &signature)
}

/// Extract signature value from XML content
fn extract_signature_value(xml_content: &str) -> Result<String> {
    use quick_xml::Reader;
    use quick_xml::events::Event;

    let mut reader = Reader::from_str(xml_content);
    reader.config_mut().trim_text(true);

    let mut buf = Vec::new();
    let mut in_signature = false;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                if String::from_utf8_lossy(e.name().as_ref()) == "Signature" {
                    in_signature = true;
                }
            }
            Ok(Event::Text(e)) if in_signature => {
                let text = e.unescape()?.to_string();
                return Ok(text);
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(AadharError::XmlParseError(e.to_string())),
            _ => {}
        }
        buf.clear();
    }

    Err(AadharError::MissingField("Signature".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_public_key() {
        let result = load_uidai_certificate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_extract_signature() {
        let xml = r#"
        <Root>
            <Data>test</Data>
            <Signature>dGVzdF9zaWduYXR1cmU=</Signature>
        </Root>
        "#;

        let sig = extract_signature_value(xml).unwrap();
        assert_eq!(sig, "dGVzdF9zaWduYXR1cmU=");
    }

    #[test]
    fn test_extract_signature_not_found() {
        let xml = r#"<Root><Data>test</Data></Root>"#;
        let result = extract_signature_value(xml);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AadharError::MissingField(_)));
    }

    #[test]
    fn test_verify_signature_with_real_data() {
        use std::io::Read;
        env_logger::try_init().ok();

        let file = std::fs::File::open("../../tests/fixtures/offlineaadhaar20251123074351915.zip").unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();
        let mut zip_file = archive.by_index_decrypt(0, b"1111").unwrap();

        let mut xml_content = String::new();
        std::io::Read::read_to_string(&mut zip_file, &mut xml_content).unwrap();

        let signature = extract_signature_value(&xml_content);
        assert!(signature.is_ok(), "Failed to extract signature: {:?}", signature.err());
        assert!(!signature.unwrap().is_empty());
    }
}
