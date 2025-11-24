//! XML parsing module for Aadhar offline KYC files

pub mod parser;
pub mod types;

pub use parser::{parse_aadhar_xml, parse_aadhar_zip, parse_aadhar_zip_from_bytes, extract_xml_without_signature};
pub use types::*;
