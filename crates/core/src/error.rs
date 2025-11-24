//! Error types for the Aadhar core library

use thiserror::Error;

/// Result type alias for Aadhar operations
pub type Result<T> = std::result::Result<T, AadharError>;

/// Error types that can occur during Aadhar operations
#[derive(Error, Debug)]
pub enum AadharError {
    /// Error during ZIP file extraction
    #[error("Failed to extract ZIP file: {0}")]
    ZipError(String),

    /// Error during XML parsing
    #[error("Failed to parse XML: {0}")]
    XmlParseError(String),

    /// Invalid share code provided
    #[error("Invalid share code")]
    InvalidShareCode,

    /// Missing required field in XML
    #[error("Missing required field: {0}")]
    MissingField(String),

    /// Invalid XML structure
    #[error("Invalid XML structure: {0}")]
    InvalidXmlStructure(String),

    /// Cryptographic error
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),

    /// Signature verification failed
    #[error("Signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    /// Invalid certificate
    #[error("Invalid certificate: {0}")]
    InvalidCertificate(String),

    /// Certificate expired
    #[error("Certificate expired")]
    CertificateExpired,

    /// I/O error
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// UTF-8 conversion error
    #[error("UTF-8 conversion error: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),

    /// Base64 decode error
    #[error("Base64 decode error: {0}")]
    Base64Error(#[from] base64::DecodeError),

    /// File too large
    #[error("File too large: {0}")]
    FileTooLarge(String),

    /// Invalid input
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Generic error
    #[error("Error: {0}")]
    Other(String),
}

impl From<zip::result::ZipError> for AadharError {
    fn from(err: zip::result::ZipError) -> Self {
        AadharError::ZipError(err.to_string())
    }
}

impl From<quick_xml::Error> for AadharError {
    fn from(err: quick_xml::Error) -> Self {
        AadharError::XmlParseError(err.to_string())
    }
}

impl From<rsa::Error> for AadharError {
    fn from(err: rsa::Error) -> Self {
        AadharError::CryptoError(err.to_string())
    }
}

impl From<x509_parser::error::X509Error> for AadharError {
    fn from(err: x509_parser::error::X509Error) -> Self {
        AadharError::InvalidCertificate(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = AadharError::InvalidShareCode;
        assert_eq!(err.to_string(), "Invalid share code");

        let err = AadharError::MissingField("test".to_string());
        assert!(err.to_string().contains("test"));
    }

    #[test]
    fn test_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err: AadharError = io_err.into();
        assert!(matches!(err, AadharError::IoError(_)));
    }

    #[test]
    fn test_error_from_zip() {
        use zip::result::ZipError;
        let zip_err = ZipError::FileNotFound;
        let err: AadharError = zip_err.into();
        assert!(matches!(err, AadharError::ZipError(_)));
    }
}
