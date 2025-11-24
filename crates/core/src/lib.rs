//! Aadhar Core Library
//!
//! This library provides functionality for parsing and verifying
//! Aadhar offline KYC XML files, and generating zero-knowledge proofs
//! for selective disclosure of identity attributes.

pub mod xml;
pub mod crypto;
pub mod error;
pub mod circuit;
pub mod didcomm;

pub use error::{AadharError, Result};

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
