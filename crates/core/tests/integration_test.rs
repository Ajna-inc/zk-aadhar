//! Integration tests for Aadhar core library

use aadhar_core::xml::{parse_aadhar_zip, extract_xml_without_signature};
use aadhar_core::crypto::verify_xmldsig;
use std::path::PathBuf;

/// Get path to test fixtures
fn get_fixture_path(filename: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop(); // go to workspace root
    path.pop();
    path.push("tests");
    path.push("fixtures");
    path.push(filename);
    path
}

#[test]
fn test_parse_real_aadhar_file() {
    env_logger::try_init().ok();

    let zip_path = get_fixture_path("offlineaadhaar20251123074351915.zip");
    let share_code = "1111";

    println!("Testing with file: {:?}", zip_path);
    assert!(zip_path.exists(), "Test fixture not found");

    let result = parse_aadhar_zip(
        zip_path.to_str().unwrap(),
        share_code
    );

    match &result {
        Ok(data) => {
            println!("✓ Successfully parsed Aadhar file");
            println!("  Reference ID: {}", data.reference_id);
            println!("  Name: {}", data.poi.name);
            println!("  DOB: {}", data.poi.dob);
            println!("  Gender: {}", data.poi.gender);

            if let Some(age) = data.poi.calculate_age() {
                println!("  Age: {} years", age);
            }

            if let Some(city) = data.poa.city() {
                println!("  City: {}", city);
            }

            println!("  State: {}", data.poa.state.as_ref().unwrap_or(&"N/A".to_string()));
            println!("  Has photo: {}", data.photo.is_some());
            println!("  Has signature: {}", !data.signature.value.is_empty());

            assert!(!data.reference_id.is_empty());
            assert!(!data.poi.name.is_empty());
            assert!(!data.poi.dob.is_empty());
            assert!(!data.signature.value.is_empty());
        }
        Err(e) => {
            panic!("Failed to parse Aadhar file: {:?}", e);
        }
    }

    assert!(result.is_ok());
}

#[test]
fn test_wrong_share_code() {
    env_logger::try_init().ok();

    let zip_path = get_fixture_path("offlineaadhaar20251123074351915.zip");
    let wrong_code = "1234"; // Wrong share code

    let result = parse_aadhar_zip(
        zip_path.to_str().unwrap(),
        wrong_code
    );

    assert!(result.is_err(), "Should fail with wrong share code");
    println!("✓ Correctly rejected wrong share code");
}

#[test]
#[ignore] // Run with: cargo test -- --ignored
fn test_verify_real_signature() {
    env_logger::try_init().ok();

    let zip_path = get_fixture_path("offlineaadhaar20251123074351915.zip");
    let share_code = "1111";

    // First parse the file
    let aadhar_data = parse_aadhar_zip(
        zip_path.to_str().unwrap(),
        share_code
    ).expect("Failed to parse Aadhar file");

    println!("✓ Parsed Aadhar file");
    println!("  Attempting signature verification...");

    // For signature verification, we need the original XML
    // Let's extract it again
    use std::fs::File;
    use std::io::Read;
    use zip::ZipArchive;

    let file = File::open(&zip_path).unwrap();
    let mut archive = ZipArchive::new(file).unwrap();
    let mut zip_file = archive.by_index_decrypt(0, share_code.as_bytes()).unwrap();

    let mut xml_content = String::new();
    zip_file.read_to_string(&mut xml_content).unwrap();

    // Extract XML without signature
    let xml_without_sig = extract_xml_without_signature(&xml_content)
        .expect("Failed to extract XML without signature");

    println!("  XML size: {} bytes", xml_content.len());
    println!("  Signature algorithm: XMLDSig (RSA-SHA1)");

    // Verify signature using XMLDSig standard
    let verification_result = verify_xmldsig(&xml_content);

    match verification_result {
        Ok(true) => {
            println!("✓ XML Digital Signature verification SUCCESSFUL!");
            println!("  ✓ Data is authentic (signed by UIDAI)");
            println!("  ✓ Data is untampered (integrity verified)");
        }
        Ok(false) => {
            println!("✗ Signature verification FAILED (returned false)");
            panic!("Signature verification failed");
        }
        Err(e) => {
            println!("✗ Signature verification ERROR: {:?}", e);
            panic!("Signature verification error: {:?}", e);
        }
    }
}
