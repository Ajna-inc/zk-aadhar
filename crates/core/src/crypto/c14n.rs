//! XML Canonicalization (C14N) using xml_c14n crate
//!
//! Provides functions for XML canonicalization required for XMLDSig verification.

use crate::error::{AadharError, Result};
use xml_c14n::{canonicalize_xml, CanonicalizationMode, CanonicalizationOptions};

/// Canonicalize XML using C14N 1.0 (inclusive)
///
/// This is used for DigestValue computation after removing the Signature element.
pub fn canonicalize_inclusive(xml_content: &str) -> Result<String> {
    log::debug!("Canonicalizing XML with C14N 1.0 (inclusive)");

    let options = CanonicalizationOptions {
        mode: CanonicalizationMode::Canonical1_0,
        keep_comments: false,
        inclusive_ns_prefixes: vec![],
    };

    canonicalize_xml(xml_content, options)
        .map_err(|e| AadharError::Other(format!("C14N canonicalization failed: {}", e)))
}

/// Canonicalize XML using Exclusive C14N
///
/// This is used for SignedInfo element canonicalization.
pub fn canonicalize_exclusive(xml_content: &str) -> Result<String> {
    log::debug!("Canonicalizing XML with Exclusive C14N");

    let options = CanonicalizationOptions {
        mode: CanonicalizationMode::ExclusiveCanonical1_0,
        keep_comments: false,
        inclusive_ns_prefixes: vec![],
    };

    canonicalize_xml(xml_content, options)
        .map_err(|e| AadharError::Other(format!("Exclusive C14N canonicalization failed: {}", e)))
}

/// Remove Signature element from XML and canonicalize with C14N 1.0
///
/// This implements the "enveloped-signature" transform from XMLDSig.
pub fn canonicalize_without_signature(xml_content: &str) -> Result<String> {
    log::info!("Removing Signature element and canonicalizing...");

    // Find and remove Signature element
    let sig_start = xml_content.find("<Signature")
        .ok_or_else(|| AadharError::MissingField("Signature element not found".to_string()))?;

    let sig_end = xml_content[sig_start..]
        .find("</Signature>")
        .ok_or_else(|| AadharError::InvalidXmlStructure("Signature closing tag not found".to_string()))?;

    let sig_end_abs = sig_start + sig_end + "</Signature>".len();

    // Remove signature element
    let mut xml_without_sig = String::new();
    xml_without_sig.push_str(&xml_content[..sig_start]);
    xml_without_sig.push_str(&xml_content[sig_end_abs..]);

    log::debug!("Signature element removed, XML size: {} -> {} bytes",
               xml_content.len(), xml_without_sig.len());

    // Canonicalize with C14N 1.0 (inclusive)
    canonicalize_inclusive(&xml_without_sig)
}

/// Extract SignedInfo element from XML with proper namespace handling
pub fn extract_signed_info(xml_content: &str) -> Result<String> {
    log::debug!("Extracting SignedInfo element...");

    let signed_info_start = xml_content.find("<SignedInfo>")
        .ok_or_else(|| AadharError::MissingField("SignedInfo element not found".to_string()))?;

    let signed_info_end = xml_content[signed_info_start..]
        .find("</SignedInfo>")
        .ok_or_else(|| AadharError::InvalidXmlStructure("SignedInfo closing tag not found".to_string()))?;

    let signed_info_end_abs = signed_info_start + signed_info_end + "</SignedInfo>".len();

    let signed_info_raw = &xml_content[signed_info_start..signed_info_end_abs];

    // XMLDSig namespace - SignedInfo needs this for proper canonicalization
    // When extracting SignedInfo, we need to add the namespace declaration
    // that was on the parent Signature element
    let xmldsig_ns = "http://www.w3.org/2000/09/xmldsig#";

    // Add namespace to SignedInfo if not already present
    let signed_info = if !signed_info_raw.contains("xmlns") {
        // Insert namespace after <SignedInfo
        signed_info_raw.replace("<SignedInfo>",
            &format!("<SignedInfo xmlns=\"{}\">", xmldsig_ns))
    } else {
        signed_info_raw.to_string()
    };

    log::debug!("SignedInfo extracted: {} bytes", signed_info.len());

    Ok(signed_info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonicalize_inclusive() {
        let xml = r#"<root><child>text</child></root>"#;
        let result = canonicalize_inclusive(xml);
        assert!(result.is_ok());
        // C14N should normalize the XML
        assert_eq!(result.unwrap(), "<root><child>text</child></root>");
    }

    #[test]
    fn test_canonicalize_exclusive() {
        let xml = r#"<root><child>text</child></root>"#;
        let result = canonicalize_exclusive(xml);
        assert!(result.is_ok());
    }

    #[test]
    fn test_remove_signature() {
        let xml = r#"<root><data>test</data><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo>...</SignedInfo></Signature></root>"#;
        let result = canonicalize_without_signature(xml);
        assert!(result.is_ok());
        let canonical = result.unwrap();
        assert!(!canonical.contains("Signature"));
        assert!(canonical.contains("data"));
    }

    #[test]
    fn test_extract_signed_info() {
        let xml = r#"<root><SignedInfo><test>data</test></SignedInfo></root>"#;
        let result = extract_signed_info(xml);
        assert!(result.is_ok());
        let signed_info = result.unwrap();
        // Should contain SignedInfo and the xmlns namespace
        assert!(signed_info.contains("<SignedInfo"));
        assert!(signed_info.contains("xmlns"));
    }
}
