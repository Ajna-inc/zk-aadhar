//! CLI tool for Aadhar Zero-Knowledge Proofs
//!
//! Production-ready ZK proof system for Aadhar offline KYC verification.

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

use aadhar_core::circuit::{
    age_proof::{prove_age_above, verify_age_above},
    attribute_proof::{prove_attribute, verify_attribute, AttributeType},
    batch_proof::{prove_batch, verify_batch, BatchClaim},
    range_proof::{prove_age_range, verify_age_range},
    compute_aadhar_commitment, prove_aadhar_commitment, verify_aadhar_commitment,
};
use aadhar_core::xml::parse_aadhar_zip;
use p3_field::{PrimeCharacteristicRing, PrimeField32};

#[derive(Parser)]
#[command(name = "aadhar-zk")]
#[command(about = "Zero-Knowledge Proofs for Aadhar Offline KYC", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Parse and display Aadhar data
    Parse {
        /// Path to Aadhar ZIP file
        #[arg(short, long)]
        file: PathBuf,

        /// Share code (4-digit password)
        #[arg(short, long)]
        code: String,
    },

    /// Generate a commitment proof
    ProveCommitment {
        /// Path to Aadhar ZIP file
        #[arg(short, long)]
        file: PathBuf,

        /// Share code (4-digit password)
        #[arg(short, long)]
        code: String,

        /// Output file for proof
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Verify a commitment proof
    VerifyCommitment {
        /// Path to proof file
        #[arg(short, long)]
        proof: PathBuf,

        /// Expected commitment value
        #[arg(short, long)]
        commitment: u32,
    },

    /// Generate an age proof
    ProveAge {
        /// Path to Aadhar ZIP file
        #[arg(short, long)]
        file: PathBuf,

        /// Share code (4-digit password)
        #[arg(short, long)]
        code: String,

        /// Minimum age threshold
        #[arg(short = 't', long)]
        min_age: u32,

        /// Output file for proof
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Verify an age proof
    VerifyAge {
        /// Path to proof file
        #[arg(short, long)]
        proof: PathBuf,

        /// Minimum age threshold
        #[arg(short = 't', long)]
        min_age: u32,

        /// Expected commitment value
        #[arg(short, long)]
        commitment: u32,
    },

    /// Generate an attribute proof (name, state, city, etc.)
    ProveAttribute {
        /// Path to Aadhar ZIP file
        #[arg(short, long)]
        file: PathBuf,

        /// Share code (4-digit password)
        #[arg(short, long)]
        code: String,

        /// Attribute type (name, state, city, district, pincode, gender)
        #[arg(short = 't', long)]
        attr_type: String,

        /// Expected value to prove
        #[arg(long)]
        value: String,

        /// Output file for proof
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Verify an attribute proof
    VerifyAttribute {
        /// Path to proof file
        #[arg(short, long)]
        proof: PathBuf,

        /// Attribute type (name, state, city, district, pincode, gender)
        #[arg(short = 't', long)]
        attr_type: String,

        /// Expected value
        #[arg(long)]
        value: String,

        /// Expected commitment value
        #[arg(short, long)]
        commitment: u32,
    },

    /// Generate an age range proof
    ProveAgeRange {
        /// Path to Aadhar ZIP file
        #[arg(short, long)]
        file: PathBuf,

        /// Share code (4-digit password)
        #[arg(short, long)]
        code: String,

        /// Minimum age
        #[arg(long)]
        min_age: u32,

        /// Maximum age
        #[arg(long)]
        max_age: u32,

        /// Output file for proof
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Verify an age range proof
    VerifyAgeRange {
        /// Path to proof file
        #[arg(short, long)]
        proof: PathBuf,

        /// Minimum age
        #[arg(long)]
        min_age: u32,

        /// Maximum age
        #[arg(long)]
        max_age: u32,

        /// Expected commitment value
        #[arg(short, long)]
        commitment: u32,
    },

    /// Generate a batch proof (multiple claims in one proof)
    ProveBatch {
        /// Path to Aadhar ZIP file
        #[arg(short, long)]
        file: PathBuf,

        /// Share code (4-digit password)
        #[arg(short, long)]
        code: String,

        /// Claims specification file (JSON format)
        #[arg(short = 's', long)]
        claims_file: PathBuf,

        /// Output file for proof
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Verify a batch proof
    VerifyBatch {
        /// Path to proof file
        #[arg(short, long)]
        proof: PathBuf,

        /// Claims specification file (JSON format)
        #[arg(short = 's', long)]
        claims_file: PathBuf,

        /// Expected commitment value
        #[arg(short, long)]
        commitment: u32,
    },

    /// Show example usage
    Examples,
}

/// Convert PathBuf to &str with proper error handling (production-ready)
#[allow(dead_code)]
fn path_to_str(path: &PathBuf) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| anyhow::anyhow!("File path contains invalid UTF-8 characters"))
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logger
    if cli.verbose {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
    } else {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    }

    match cli.command {
        Commands::Parse { file, code } => cmd_parse(file, code),
        Commands::ProveCommitment { file, code, output } => cmd_prove_commitment(file, code, output),
        Commands::VerifyCommitment { proof, commitment } => cmd_verify_commitment(proof, commitment),
        Commands::ProveAge { file, code, min_age, output } => cmd_prove_age(file, code, min_age, output),
        Commands::VerifyAge { proof, min_age, commitment } => cmd_verify_age(proof, min_age, commitment),
        Commands::ProveAttribute { file, code, attr_type, value, output } => {
            cmd_prove_attribute(file, code, attr_type, value, output)
        }
        Commands::VerifyAttribute { proof, attr_type, value, commitment } => {
            cmd_verify_attribute(proof, attr_type, value, commitment)
        }
        Commands::ProveAgeRange { file, code, min_age, max_age, output } => {
            cmd_prove_age_range(file, code, min_age, max_age, output)
        }
        Commands::VerifyAgeRange { proof, min_age, max_age, commitment } => {
            cmd_verify_age_range(proof, min_age, max_age, commitment)
        }
        Commands::ProveBatch { file, code, claims_file, output } => {
            cmd_prove_batch(file, code, claims_file, output)
        }
        Commands::VerifyBatch { proof, claims_file, commitment } => {
            cmd_verify_batch(proof, claims_file, commitment)
        }
        Commands::Examples => cmd_examples(),
    }
}

fn cmd_parse(file: PathBuf, code: String) -> Result<()> {
    println!("📄 Parsing Aadhar file: {}", file.display());
    println!();

    let file_str = file.to_str()
        .ok_or_else(|| anyhow::anyhow!("File path contains invalid UTF-8 characters"))?;
    let mut aadhar = parse_aadhar_zip(file_str, &code)?;
    aadhar.poi.parse_dob()?;

    println!("✅ Successfully parsed Aadhar data");
    println!();
    println!("Personal Information:");
    println!("  Name:     {}", aadhar.poi.name);
    println!("  DOB:      {}", aadhar.poi.dob);
    println!("  Age:      {} years", aadhar.poi.age().unwrap_or(0));
    println!("  Gender:   {}", aadhar.poi.gender);
    println!();
    println!("Address:");
    println!("  {}", aadhar.poa.full_address());
    println!();
    println!("Signature:");
    println!("  Verified: {}", aadhar.signature.verified);
    println!();

    let commitment = compute_aadhar_commitment(&aadhar);
    println!("Commitment: {}", commitment.as_canonical_u32());

    Ok(())
}

fn cmd_prove_commitment(file: PathBuf, code: String, output: PathBuf) -> Result<()> {
    println!("🔐 Generating commitment proof...");
    println!();

    let aadhar = parse_aadhar_zip(file.to_str().unwrap(), &code)?;
    let commitment = compute_aadhar_commitment(&aadhar);

    println!("Commitment: {}", commitment.as_canonical_u32());
    println!();

    let proof = prove_aadhar_commitment(&aadhar)?;
    std::fs::write(&output, &proof)?;

    println!("✅ Proof generated successfully!");
    println!("   Size: {} bytes ({:.2} KB)", proof.len(), proof.len() as f64 / 1024.0);
    println!("   Saved to: {}", output.display());
    println!();
    println!("To verify this proof, use:");
    println!("  aadhar-zk verify-commitment --proof {} --commitment {}",
             output.display(), commitment.as_canonical_u32());

    Ok(())
}

fn cmd_verify_commitment(proof_path: PathBuf, commitment_value: u32) -> Result<()> {
    println!("🔍 Verifying commitment proof...");
    println!();

    let proof = std::fs::read(&proof_path)?;
    let commitment = p3_mersenne_31::Mersenne31::from_u32(commitment_value);

    println!("Proof size: {} bytes", proof.len());
    println!("Expected commitment: {}", commitment_value);
    println!();

    let is_valid = verify_aadhar_commitment(&proof, commitment)?;

    if is_valid {
        println!("✅ Proof is VALID!");
        println!("   The prover possesses valid Aadhar data with commitment {}", commitment_value);
    } else {
        println!("❌ Proof is INVALID!");
    }

    Ok(())
}

fn cmd_prove_age(file: PathBuf, code: String, min_age: u32, output: PathBuf) -> Result<()> {
    println!("🎂 Generating age proof (age >= {})...", min_age);
    println!();

    let mut aadhar = parse_aadhar_zip(file.to_str().unwrap(), &code)?;
    aadhar.poi.parse_dob()?;

    let actual_age = aadhar.poi.age().unwrap();
    println!("Actual age: {} years", actual_age);

    if actual_age < min_age {
        anyhow::bail!("Age {} is below required threshold {}", actual_age, min_age);
    }

    let commitment = compute_aadhar_commitment(&aadhar);
    println!("Commitment: {}", commitment.as_canonical_u32());
    println!();

    let proof = prove_age_above(&aadhar, min_age)?;
    std::fs::write(&output, &proof)?;

    println!("✅ Age proof generated successfully!");
    println!("   Size: {} bytes ({:.2} KB)", proof.len(), proof.len() as f64 / 1024.0);
    println!("   Saved to: {}", output.display());
    println!();
    println!("To verify this proof, use:");
    println!("  aadhar-zk verify-age --proof {} --min-age {} --commitment {}",
             output.display(), min_age, commitment.as_canonical_u32());

    Ok(())
}

fn cmd_verify_age(proof_path: PathBuf, min_age: u32, commitment_value: u32) -> Result<()> {
    use p3_field::PrimeCharacteristicRing;

    println!("🔍 Verifying age proof (age >= {})...", min_age);
    println!();

    let proof = std::fs::read(&proof_path)?;
    let commitment = p3_mersenne_31::Mersenne31::from_u32(commitment_value);

    println!("Proof size: {} bytes", proof.len());
    println!("Minimum age: {}", min_age);
    println!("Expected commitment: {}", commitment_value);
    println!();

    let is_valid = verify_age_above(&proof, min_age, commitment)?;

    if is_valid {
        println!("✅ Proof is VALID!");
        println!("   The prover is at least {} years old", min_age);
        println!("   (actual age is hidden)");
    } else {
        println!("❌ Proof is INVALID!");
    }

    Ok(())
}

fn cmd_prove_attribute(
    file: PathBuf,
    code: String,
    attr_type: String,
    value: String,
    output: PathBuf,
) -> Result<()> {
    println!("🔐 Generating attribute proof ({} = '{}')...", attr_type, value);
    println!();

    let aadhar = parse_aadhar_zip(file.to_str().unwrap(), &code)?;
    let commitment = compute_aadhar_commitment(&aadhar);

    let attr = parse_attribute_type(&attr_type)?;

    println!("Attribute: {}", attr_type);
    println!("Expected value: {}", value);
    println!("Commitment: {}", commitment.as_canonical_u32());
    println!();

    let proof = prove_attribute(&aadhar, attr, &value)?;
    std::fs::write(&output, &proof)?;

    println!("✅ Attribute proof generated successfully!");
    println!("   Size: {} bytes ({:.2} KB)", proof.len(), proof.len() as f64 / 1024.0);
    println!("   Saved to: {}", output.display());
    println!();
    println!("To verify this proof, use:");
    println!("  aadhar-zk verify-attribute --proof {} --attr-type {} --value '{}' --commitment {}",
             output.display(), attr_type, value, commitment.as_canonical_u32());

    Ok(())
}

fn cmd_verify_attribute(
    proof_path: PathBuf,
    attr_type: String,
    value: String,
    commitment_value: u32,
) -> Result<()> {
    println!("🔍 Verifying attribute proof ({} = '{}')...", attr_type, value);
    println!();

    let proof = std::fs::read(&proof_path)?;
    let commitment = p3_mersenne_31::Mersenne31::from_u32(commitment_value);
    let attr = parse_attribute_type(&attr_type)?;

    println!("Proof size: {} bytes", proof.len());
    println!("Attribute: {}", attr_type);
    println!("Expected value: {}", value);
    println!("Expected commitment: {}", commitment_value);
    println!();

    let is_valid = verify_attribute(&proof, attr, &value, commitment)?;

    if is_valid {
        println!("✅ Proof is VALID!");
        println!("   The {} matches '{}'", attr_type, value);
        println!("   (other Aadhar data is hidden)");
    } else {
        println!("❌ Proof is INVALID!");
    }

    Ok(())
}

fn parse_attribute_type(s: &str) -> Result<AttributeType> {
    match s.to_lowercase().as_str() {
        "name" => Ok(AttributeType::Name),
        "state" => Ok(AttributeType::State),
        "city" => Ok(AttributeType::City),
        "district" => Ok(AttributeType::District),
        "pincode" => Ok(AttributeType::Pincode),
        "gender" => Ok(AttributeType::Gender),
        _ => anyhow::bail!("Invalid attribute type: {}. Valid types: name, state, city, district, pincode, gender", s),
    }
}

fn cmd_prove_age_range(
    file: PathBuf,
    code: String,
    min_age: u32,
    max_age: u32,
    output: PathBuf,
) -> Result<()> {
    println!("🎯 Generating age range proof ({} <= age <= {})...", min_age, max_age);
    println!();

    let mut aadhar = parse_aadhar_zip(file.to_str().unwrap(), &code)?;
    aadhar.poi.parse_dob()?;

    let actual_age = aadhar.poi.age().unwrap();
    println!("Actual age: {} years", actual_age);

    let commitment = compute_aadhar_commitment(&aadhar);
    println!("Commitment: {}", commitment.as_canonical_u32());
    println!();

    let proof = prove_age_range(&aadhar, min_age, max_age)?;
    std::fs::write(&output, &proof)?;

    println!("✅ Age range proof generated successfully!");
    println!("   Size: {} bytes ({:.2} KB)", proof.len(), proof.len() as f64 / 1024.0);
    println!("   Saved to: {}", output.display());
    println!();
    println!("To verify this proof, use:");
    println!("  aadhar-zk verify-age-range --proof {} --min-age {} --max-age {} --commitment {}",
             output.display(), min_age, max_age, commitment.as_canonical_u32());

    Ok(())
}

fn cmd_verify_age_range(
    proof_path: PathBuf,
    min_age: u32,
    max_age: u32,
    commitment_value: u32,
) -> Result<()> {
    println!("🔍 Verifying age range proof ({} <= age <= {})...", min_age, max_age);
    println!();

    let proof = std::fs::read(&proof_path)?;
    let commitment = p3_mersenne_31::Mersenne31::from_u32(commitment_value);

    println!("Proof size: {} bytes", proof.len());
    println!("Age range: [{}, {}]", min_age, max_age);
    println!("Expected commitment: {}", commitment_value);
    println!();

    let is_valid = verify_age_range(&proof, min_age, max_age, commitment)?;

    if is_valid {
        println!("✅ Proof is VALID!");
        println!("   Age is in range [{}, {}]", min_age, max_age);
        println!("   (exact age is hidden)");
    } else {
        println!("❌ Proof is INVALID!");
    }

    Ok(())
}

fn cmd_prove_batch(
    file: PathBuf,
    code: String,
    claims_file: PathBuf,
    output: PathBuf,
) -> Result<()> {
    println!("📦 Generating batch proof...");
    println!();

    let mut aadhar = parse_aadhar_zip(file.to_str().unwrap(), &code)?;
    aadhar.poi.parse_dob()?;

    // For simplicity, parse JSON claims
    let claims_json = std::fs::read_to_string(&claims_file)?;
    let claims = parse_claims_from_json(&claims_json)?;

    println!("Number of claims: {}", claims.len());
    for (i, claim) in claims.iter().enumerate() {
        println!("  {}. {:?}", i + 1, claim);
    }

    let commitment = compute_aadhar_commitment(&aadhar);
    println!("Commitment: {}", commitment.as_canonical_u32());
    println!();

    let proof = prove_batch(&aadhar, &claims)?;
    std::fs::write(&output, &proof)?;

    println!("✅ Batch proof generated successfully!");
    println!("   Size: {} bytes ({:.2} KB)", proof.len(), proof.len() as f64 / 1024.0);
    println!("   Saved to: {}", output.display());
    println!();
    println!("To verify this proof, use:");
    println!("  aadhar-zk verify-batch --proof {} --claims-file {} --commitment {}",
             output.display(), claims_file.display(), commitment.as_canonical_u32());

    Ok(())
}

fn cmd_verify_batch(
    proof_path: PathBuf,
    claims_file: PathBuf,
    commitment_value: u32,
) -> Result<()> {
    println!("🔍 Verifying batch proof...");
    println!();

    let proof = std::fs::read(&proof_path)?;
    let commitment = p3_mersenne_31::Mersenne31::from_u32(commitment_value);

    let claims_json = std::fs::read_to_string(&claims_file)?;
    let claims = parse_claims_from_json(&claims_json)?;

    println!("Proof size: {} bytes", proof.len());
    println!("Number of claims: {}", claims.len());
    println!("Expected commitment: {}", commitment_value);
    println!();

    let is_valid = verify_batch(&proof, &claims, commitment)?;

    if is_valid {
        println!("✅ Proof is VALID!");
        println!("   All {} claims verified successfully", claims.len());
    } else {
        println!("❌ Proof is INVALID!");
    }

    Ok(())
}

fn parse_claims_from_json(json: &str) -> Result<Vec<BatchClaim>> {
    use serde_json::Value;

    let data: Value = serde_json::from_str(json)?;
    let claims_array = data.as_array()
        .ok_or_else(|| anyhow::anyhow!("Claims must be an array"))?;

    let mut claims = Vec::new();

    for claim_val in claims_array {
        let claim_type = claim_val["type"].as_str()
            .ok_or_else(|| anyhow::anyhow!("Claim missing 'type' field"))?;

        match claim_type {
            "age_range" => {
                let min = claim_val["min"].as_u64()
                    .ok_or_else(|| anyhow::anyhow!("age_range missing 'min'"))? as u32;
                let max = claim_val["max"].as_u64()
                    .ok_or_else(|| anyhow::anyhow!("age_range missing 'max'"))? as u32;
                claims.push(BatchClaim::AgeRange { min, max });
            }
            "attribute_equals" => {
                let attr = claim_val["attribute"].as_str()
                    .ok_or_else(|| anyhow::anyhow!("attribute_equals missing 'attribute'"))?;
                let value = claim_val["value"].as_str()
                    .ok_or_else(|| anyhow::anyhow!("attribute_equals missing 'value'"))?;

                let attr_type = parse_attribute_type(attr)?;
                claims.push(BatchClaim::AttributeEquals {
                    attr_type,
                    value: value.to_string(),
                });
            }
            _ => anyhow::bail!("Unknown claim type: {}", claim_type),
        }
    }

    Ok(claims)
}

fn cmd_examples() -> Result<()> {
    println!("📚 Example Usage");
    println!();
    println!("1. Parse an Aadhar file:");
    println!("   aadhar-zk parse -f aadhar.zip -c 1234");
    println!();
    println!("2. Generate a commitment proof:");
    println!("   aadhar-zk prove-commitment -f aadhar.zip -c 1234 -o proof.bin");
    println!();
    println!("3. Verify a commitment proof:");
    println!("   aadhar-zk verify-commitment -p proof.bin -c 123456789");
    println!();
    println!("4. Generate an age proof (age >= 18):");
    println!("   aadhar-zk prove-age -f aadhar.zip -c 1234 -t 18 -o age_proof.bin");
    println!();
    println!("5. Verify an age proof:");
    println!("   aadhar-zk verify-age -p age_proof.bin -t 18 -c 123456789");
    println!();
    println!("6. Generate an attribute proof (state = 'Delhi'):");
    println!("   aadhar-zk prove-attribute -f aadhar.zip -c 1234 -t state -v 'Delhi' -o state_proof.bin");
    println!();
    println!("7. Verify an attribute proof:");
    println!("   aadhar-zk verify-attribute -p state_proof.bin -t state -v 'Delhi' -c 123456789");
    println!();
    println!("💡 Tips:");
    println!("   - Use --verbose or -v for detailed logging");
    println!("   - The commitment value binds the proof to specific Aadhar data");
    println!("   - Proofs are zero-knowledge: they don't reveal the actual data");
    println!("   - Attribute types: name, state, city, district, pincode, gender");
    println!();

    Ok(())
}
