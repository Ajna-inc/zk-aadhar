//! Cryptographic operations for Aadhar verification

pub mod rsa_verifier;
pub mod cert;
pub mod xmldsig_verifier;
pub mod c14n;

pub use rsa_verifier::verify_signature;
pub use cert::load_uidai_certificate;
pub use xmldsig_verifier::verify_xmldsig;
