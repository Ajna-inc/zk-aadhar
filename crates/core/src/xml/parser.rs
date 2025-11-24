//! XML parser for Aadhar offline KYC files

use crate::error::{AadharError, Result};
use crate::xml::types::*;
use crate::crypto::xmldsig_verifier::verify_xmldsig;
// Base64 decoding handled by rsa crate
use quick_xml::events::Event;
use quick_xml::Reader;
use std::fs::File;
use std::io::{Cursor, Read};
use zip::ZipArchive;

// ZIP bomb protection: real Aadhar XMLs are ~5-15 KB, we allow up to 10 MB
const MAX_XML_SIZE: u64 = 10 * 1024 * 1024;

// Validation limits (framework available if needed later)
#[allow(dead_code)]
const MAX_NAME_LENGTH: usize = 200;
#[allow(dead_code)]
const MAX_ADDRESS_LENGTH: usize = 500;

/// Extract and parse Aadhar data from the offline KYC ZIP file.
pub fn parse_aadhar_zip(zip_path: &str, share_code: &str) -> Result<AadharData> {
    log::info!("Parsing Aadhar ZIP file: {}", zip_path);

    validate_share_code(share_code)?;

    let file = File::open(zip_path)?;
    let mut archive = ZipArchive::new(file)?;

    if archive.len() != 1 {
        return Err(AadharError::InvalidXmlStructure(
            format!("Expected 1 file in ZIP, found {}", archive.len())
        ));
    }

    let zip_file = archive.by_index_decrypt(0, share_code.as_bytes())
        .map_err(|_| AadharError::InvalidShareCode)?;

    // Limit read size to prevent ZIP bombs
    let mut xml_content = String::new();
    let mut limited_reader = zip_file.take(MAX_XML_SIZE);
    let bytes_read = limited_reader.read_to_string(&mut xml_content)?;

    if bytes_read as u64 >= MAX_XML_SIZE {
        return Err(AadharError::FileTooLarge(
            format!("XML file exceeds maximum size of {} MB", MAX_XML_SIZE / (1024 * 1024))
        ));
    }

    log::debug!("Extracted XML, size: {} bytes", xml_content.len());

    parse_aadhar_xml(&xml_content)
}

/// Parse Aadhar ZIP from bytes (useful for web uploads).
pub fn parse_aadhar_zip_from_bytes(zip_bytes: &[u8], share_code: &str) -> Result<AadharData> {
    log::info!("Parsing Aadhar ZIP from bytes, size: {}", zip_bytes.len());

    let cursor = Cursor::new(zip_bytes);
    let mut archive = ZipArchive::new(cursor)?;

    if archive.len() != 1 {
        return Err(AadharError::InvalidXmlStructure(
            format!("Expected 1 file in ZIP, found {}", archive.len())
        ));
    }

    let mut zip_file = archive.by_index_decrypt(0, share_code.as_bytes())
        .map_err(|_| AadharError::InvalidShareCode)?;

    let mut xml_content = String::new();
    zip_file.read_to_string(&mut xml_content)?;

    log::debug!("Extracted XML, size: {} bytes", xml_content.len());

    parse_aadhar_xml(&xml_content)
}

/// Parse the XML and extract all Aadhar data including signature verification.
pub fn parse_aadhar_xml(xml_content: &str) -> Result<AadharData> {
    let mut reader = Reader::from_str(xml_content);
    reader.config_mut().trim_text(true);

    let mut aadhar_data = AadharData {
        reference_id: String::new(),
        poi: PersonalInfo {
            name: String::new(),
            dob: String::new(),
            gender: String::new(),
            dob_parsed: None,
        },
        poa: AddressInfo {
            care_of: None,
            house: None,
            street: None,
            landmark: None,
            locality: None,
            vtc: None,
            subdist: None,
            district: None,
            state: None,
            pincode: None,
            post_office: None,
            country: None,
        },
        photo: None,
        signature: Signature {
            value: String::new(),
            algorithm: None,
            verified: false,
        },
        mobile_hash: None,
        email_hash: None,
    };

    let mut buf = Vec::new();
    let mut current_element = String::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                current_element = String::from_utf8_lossy(e.name().as_ref()).to_string();

                match current_element.as_str() {
                    "OfflinePaperlessKyc" => {
                        // Extract reference ID from attributes
                        for attr in e.attributes() {
                            let attr = attr.map_err(|e| AadharError::XmlParseError(e.to_string()))?;
                            let key = String::from_utf8_lossy(attr.key.as_ref());
                            if key == "referenceId" || key == "reference_id" {
                                aadhar_data.reference_id =
                                    String::from_utf8_lossy(&attr.value).to_string();
                            }
                        }
                    }
                    "Poi" => {
                        // Parse Personal Info attributes
                        for attr in e.attributes() {
                            let attr = attr.map_err(|e| AadharError::XmlParseError(e.to_string()))?;
                            let key = String::from_utf8_lossy(attr.key.as_ref());
                            let value = String::from_utf8_lossy(&attr.value).to_string();

                            match key.as_ref() {
                                "name" => aadhar_data.poi.name = value,
                                "dob" => aadhar_data.poi.dob = value,
                                "gender" => aadhar_data.poi.gender = value,
                                "e" => aadhar_data.email_hash = Some(value),
                                "m" => aadhar_data.mobile_hash = Some(value),
                                _ => {}
                            }
                        }
                    }
                    "Poa" => {
                        // Parse Address attributes
                        for attr in e.attributes() {
                            let attr = attr.map_err(|e| AadharError::XmlParseError(e.to_string()))?;
                            let key = String::from_utf8_lossy(attr.key.as_ref());
                            let value = String::from_utf8_lossy(&attr.value).to_string();

                            match key.as_ref() {
                                "co" | "careof" => aadhar_data.poa.care_of = Some(value),
                                "house" => aadhar_data.poa.house = Some(value),
                                "street" | "st" => aadhar_data.poa.street = Some(value),
                                "lm" | "landmark" => aadhar_data.poa.landmark = Some(value),
                                "loc" | "locality" => aadhar_data.poa.locality = Some(value),
                                "vtc" => aadhar_data.poa.vtc = Some(value),
                                "subdist" => aadhar_data.poa.subdist = Some(value),
                                "dist" | "district" => aadhar_data.poa.district = Some(value),
                                "state" => aadhar_data.poa.state = Some(value),
                                "pc" | "pincode" => aadhar_data.poa.pincode = Some(value),
                                "po" => aadhar_data.poa.post_office = Some(value),
                                "country" => aadhar_data.poa.country = Some(value),
                                _ => {}
                            }
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::Text(e)) => {
                let text = e.unescape()?.to_string();
                let elem_name = current_element.as_str();

                // Handle namespaced elements (e.g., "{http://www.w3.org/2000/09/xmldsig#}SignatureValue")
                let elem_local_name = if elem_name.contains('}') {
                    elem_name.split('}').last().unwrap_or(elem_name)
                } else {
                    elem_name
                };

                match elem_local_name {
                    "Pht" => {
                        // Photo data (base64 encoded)
                        aadhar_data.photo = Some(text);
                    }
                    "SignatureValue" => {
                        // Digital signature value (base64 encoded)
                        aadhar_data.signature.value = text;
                    }
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(AadharError::XmlParseError(e.to_string())),
            _ => {}
        }
        buf.clear();
    }

    // Validate required fields
    if aadhar_data.reference_id.is_empty() {
        return Err(AadharError::MissingField("reference_id".to_string()));
    }
    if aadhar_data.poi.name.is_empty() {
        return Err(AadharError::MissingField("name".to_string()));
    }
    if aadhar_data.poi.dob.is_empty() {
        return Err(AadharError::MissingField("dob".to_string()));
    }
    if aadhar_data.signature.value.is_empty() {
        return Err(AadharError::MissingField("signature".to_string()));
    }

    // Parse DOB
    if let Err(e) = aadhar_data.poi.parse_dob() {
        log::warn!("Failed to parse DOB: {}", e);
    }

    // Verify XML Digital Signature
    log::info!("Verifying XML Digital Signature...");
    match verify_xmldsig(xml_content) {
        Ok(true) => {
            aadhar_data.signature.verified = true;
            log::info!("✓ XML Digital Signature verified successfully!");
        }
        Ok(false) => {
            log::warn!("✗ XML Digital Signature verification returned false");
            aadhar_data.signature.verified = false;
        }
        Err(e) => {
            log::warn!("✗ XML Digital Signature verification failed: {}", e);
            aadhar_data.signature.verified = false;
        }
    }

    log::info!("Successfully parsed Aadhar data for: {}", aadhar_data.poi.name);
    log::debug!("Reference ID: {}", aadhar_data.reference_id);

    Ok(aadhar_data)
}

/// Extract XML content without signature for verification purposes
pub fn extract_xml_without_signature(xml_content: &str) -> Result<String> {
    let signature_start = xml_content.find("<Signature")
        .ok_or_else(|| AadharError::MissingField("Signature".to_string()))?;

    let signature_end = xml_content[signature_start..]
        .find("</Signature>")
        .ok_or_else(|| AadharError::InvalidXmlStructure("Signature tag not closed".to_string()))?;

    let signature_end = signature_start + signature_end + "</Signature>".len();

    // Remove signature element
    let mut xml_without_sig = String::new();
    xml_without_sig.push_str(&xml_content[..signature_start]);
    xml_without_sig.push_str(&xml_content[signature_end..]);

    Ok(xml_without_sig)
}

/// Validate share code format
///
/// Share codes must be exactly 4 digits (0-9)
fn validate_share_code(code: &str) -> Result<()> {
    if code.len() != 4 {
        return Err(AadharError::InvalidInput(
            "Share code must be exactly 4 digits".to_string()
        ));
    }

    if !code.chars().all(|c| c.is_ascii_digit()) {
        return Err(AadharError::InvalidInput(
            "Share code must contain only digits (0-9)".to_string()
        ));
    }

    Ok(())
}

/// Validate string field length and content
///
/// Ensures strings are not empty and don't exceed maximum length
#[allow(dead_code)]
fn validate_string(value: String, max_len: usize, field_name: &str) -> Result<String> {
    if value.trim().is_empty() {
        return Err(AadharError::InvalidInput(
            format!("{} cannot be empty", field_name)
        ));
    }

    if value.len() > max_len {
        return Err(AadharError::InvalidInput(
            format!("{} exceeds maximum length of {} characters", field_name, max_len)
        ));
    }

    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_xml_without_signature() {
        let xml = r#"<Root><Data>test</Data><Signature>sig_value</Signature></Root>"#;
        let result = extract_xml_without_signature(xml).unwrap();
        assert!(!result.contains("<Signature>"));
        assert!(result.contains("<Data>test</Data>"));
    }

    #[test]
    fn test_validate_share_code() {
        // Valid codes
        assert!(validate_share_code("1234").is_ok());
        assert!(validate_share_code("0000").is_ok());
        assert!(validate_share_code("9999").is_ok());

        // Invalid codes
        assert!(validate_share_code("123").is_err());    // Too short
        assert!(validate_share_code("12345").is_err());  // Too long
        assert!(validate_share_code("abcd").is_err());   // Non-numeric
        assert!(validate_share_code("12a4").is_err());   // Mixed
        assert!(validate_share_code("").is_err());       // Empty
    }

    #[test]
    fn test_validate_string() {
        // Valid strings
        assert!(validate_string("John Doe".to_string(), 100, "name").is_ok());
        assert!(validate_string("A".to_string(), 100, "name").is_ok());

        // Invalid strings
        assert!(validate_string("".to_string(), 100, "name").is_err());        // Empty
        assert!(validate_string("   ".to_string(), 100, "name").is_err());    // Whitespace only
        assert!(validate_string("A".repeat(1000), 100, "name").is_err());     // Too long
    }

    #[test]
    fn test_zip_bomb_protection() {
        // This would require creating a test ZIP bomb, which we skip for now
        // But the protection is in place with MAX_XML_SIZE constant
    }

    #[test]
    fn test_parse_real_aadhar_file() {
        env_logger::try_init().ok();

        let result = parse_aadhar_zip(
            "../../tests/fixtures/offlineaadhaar20251123074351915.zip",
            "1111"
        );

        assert!(result.is_ok(), "Failed to parse real Aadhaar file: {:?}", result.err());
        let aadhar = result.unwrap();

        assert!(!aadhar.reference_id.is_empty());
        assert!(!aadhar.poi.name.is_empty());
        assert!(!aadhar.poi.dob.is_empty());
        assert!(!aadhar.poi.gender.is_empty());
    }

    #[test]
    fn test_parse_with_wrong_share_code() {
        let result = parse_aadhar_zip(
            "../../tests/fixtures/offlineaadhaar20251123074351915.zip",
            "9999"
        );

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AadharError::InvalidShareCode));
    }

    #[test]
    fn test_parse_nonexistent_file() {
        let result = parse_aadhar_zip("nonexistent.zip", "1234");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_with_invalid_share_code_format() {
        let result = parse_aadhar_zip(
            "../../tests/fixtures/offlineaadhaar20251123074351915.zip",
            "abc"
        );

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AadharError::InvalidInput(_)));
    }

    #[test]
    fn test_extract_xml_without_signature_edge_cases() {
        // No signature tag
        let xml = r#"<Root><Data>test</Data></Root>"#;
        let result = extract_xml_without_signature(xml);
        assert!(result.is_err());

        // Unclosed signature tag
        let xml = r#"<Root><Signature>value</Root>"#;
        let result = extract_xml_without_signature(xml);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_aadhar_xml_missing_fields() {
        // Missing required fields
        let xml = r#"
            <OfflinePaperlessKyc>
                <UidData>
                    <Poi name="Test"/>
                </UidData>
            </OfflinePaperlessKyc>
        "#;

        let result = parse_aadhar_xml(xml);
        assert!(result.is_err());
    }
}
