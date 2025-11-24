//! Example: Parse an Aadhar offline KYC file
//!
//! Usage:
//!   cargo run --example parse_aadhar -- <path_to_zip> <share_code>

use aadhar_core::xml::parse_aadhar_zip;

fn main() {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();

    if args.len() < 3 {
        eprintln!("Usage: {} <aadhar_zip_path> <share_code>", args[0]);
        eprintln!("Example: {} ~/offlineaadhar.zip 1234", args[0]);
        std::process::exit(1);
    }

    let zip_path = &args[1];
    let share_code = &args[2];

    println!("🔍 Parsing Aadhar file: {}", zip_path);
    println!("🔐 Using share code: {}", share_code);
    println!();

    match parse_aadhar_zip(zip_path, share_code) {
        Ok(data) => {
            println!("✅ Successfully parsed Aadhar data!");
            println!();
            println!("📋 Personal Information:");
            println!("  Reference ID: {}", data.reference_id);
            println!("  Name: {}", data.poi.name);
            println!("  Date of Birth: {}", data.poi.dob);
            println!("  Gender: {}", data.poi.gender);

            if let Some(age) = data.poi.calculate_age() {
                println!("  Age: {} years", age);

                if data.poi.is_above_age(18).unwrap_or(false) {
                    println!("  ✓ Above 18 years old");
                }
            }

            println!();
            println!("📍 Address Information:");
            if let Some(ref care_of) = data.poa.care_of {
                println!("  Care of: {}", care_of);
            }
            if let Some(ref house) = data.poa.house {
                println!("  House: {}", house);
            }
            if let Some(ref street) = data.poa.street {
                println!("  Street: {}", street);
            }
            if let Some(ref locality) = data.poa.locality {
                println!("  Locality: {}", locality);
            }
            if let Some(city) = data.poa.city() {
                println!("  City: {}", city);
            }
            if let Some(ref district) = data.poa.district {
                println!("  District: {}", district);
            }
            if let Some(ref state) = data.poa.state {
                println!("  State: {}", state);
            }
            if let Some(ref pincode) = data.poa.pincode {
                println!("  PIN Code: {}", pincode);
            }

            println!();
            println!("🔐 Security:");
            println!("  Has digital signature: {}", !data.signature.value.is_empty());
            println!("  Has photo: {}", data.photo.is_some());
            if data.mobile_hash.is_some() {
                println!("  Mobile number: <hashed>");
            }
            if data.email_hash.is_some() {
                println!("  Email: <hashed>");
            }

            println!();
            println!("✅ All data parsed successfully!");
        }
        Err(e) => {
            eprintln!("❌ Error parsing Aadhar file: {:?}", e);
            std::process::exit(1);
        }
    }
}
