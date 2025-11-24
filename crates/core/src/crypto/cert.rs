//! UIDAI certificate handling

use crate::error::{AadharError, Result};
use rsa::{RsaPublicKey, pkcs1::DecodeRsaPublicKey, traits::PublicKeyParts};
use x509_parser::prelude::*;

/// Load the UIDAI public certificate embedded in the binary
pub fn load_uidai_certificate() -> Result<RsaPublicKey> {
    // Embed the certificate at compile time
    const UIDAI_CERT: &[u8] = include_bytes!("uidai_offline_publickey.cer");

    log::info!("Loading UIDAI public certificate, size: {} bytes", UIDAI_CERT.len());

    // Parse X.509 certificate (try PEM format first, then DER)
    let cert_pem = std::str::from_utf8(UIDAI_CERT)
        .map_err(|e| AadharError::InvalidCertificate(format!("Certificate is not valid UTF-8: {}", e)))?;

    let (_, pem) = parse_x509_pem(cert_pem.as_bytes())
        .map_err(|e| AadharError::InvalidCertificate(format!("Failed to parse PEM: {}", e)))?;

    let (_, cert) = X509Certificate::from_der(&pem.contents)
        .map_err(|e| AadharError::InvalidCertificate(format!("Failed to parse certificate: {}", e)))?;

    log::debug!("Certificate subject: {}", cert.subject());
    log::debug!("Certificate issuer: {}", cert.issuer());
    log::debug!("Certificate validity: {:?} to {:?}",
        cert.validity().not_before,
        cert.validity().not_after
    );

    // Extract public key from certificate
    let public_key_der = cert.public_key().raw;

    // Parse RSA public key
    let rsa_public_key = RsaPublicKey::from_pkcs1_der(public_key_der)
        .or_else(|_| {
            // Try PKCS8 format if PKCS1 fails
            use rsa::pkcs8::DecodePublicKey;
            RsaPublicKey::from_public_key_der(public_key_der)
        })
        .map_err(|e| AadharError::CryptoError(format!("Failed to parse RSA public key: {}", e)))?;

    log::info!("Successfully loaded RSA public key, size: {} bits", rsa_public_key.size() * 8);

    Ok(rsa_public_key)
}

/// Verify certificate validity
pub fn verify_certificate_validity() -> Result<bool> {
    const UIDAI_CERT: &[u8] = include_bytes!("uidai_offline_publickey.cer");

    let cert_pem = std::str::from_utf8(UIDAI_CERT)
        .map_err(|e| AadharError::InvalidCertificate(format!("Certificate is not valid UTF-8: {}", e)))?;

    let (_, pem) = parse_x509_pem(cert_pem.as_bytes())
        .map_err(|e| AadharError::InvalidCertificate(format!("Failed to parse PEM: {}", e)))?;

    let (_, cert) = X509Certificate::from_der(&pem.contents)
        .map_err(|e| AadharError::InvalidCertificate(format!("Failed to parse certificate: {}", e)))?;

    // Check if certificate is currently valid
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let not_before = cert.validity().not_before.timestamp();
    let not_after = cert.validity().not_after.timestamp();

    if now < not_before {
        log::warn!("Certificate not yet valid");
        return Ok(false);
    }

    if now > not_after {
        log::warn!("Certificate has expired");
        return Ok(false);
    }

    log::info!("Certificate is valid");
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_certificate() {
        let result = load_uidai_certificate();
        assert!(result.is_ok(), "Failed to load certificate: {:?}", result.err());

        let key = result.unwrap();
        // UIDAI uses 2048-bit RSA keys
        assert_eq!(key.size(), 256); // 2048 bits = 256 bytes
    }

    #[test]
    fn test_verify_certificate_validity() {
        let result = verify_certificate_validity();
        assert!(result.is_ok());
    }
}
