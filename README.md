# Aadhar ZK Proof System

A privacy-preserving zero-knowledge proof system for India's Aadhaar offline KYC verification.

## What is this?

This system lets you prove things about your Aadhaar identity without revealing the actual data. For example:
- Prove you're over 18 without showing your birthdate
- Prove you live in Delhi without showing your full address
- Prove your age is between 25-65 without revealing the exact number

All proofs are cryptographically secure using STARK (Scalable Transparent Argument of Knowledge) technology.

## Installation

Requirements: Rust 1.83 or later

```bash
git clone https://github.com/your-org/offline-aadhar-poe.git
cd offline-aadhar-poe
cargo build --release
cargo install --path crates/cli
```

## Quick Start

First, parse your Aadhaar file:

```bash
aadhar-zk parse --file aadhar.zip --code 1234
```

Generate a proof that you're over 18:

```bash
aadhar-zk prove-age \
  --file aadhar.zip \
  --code 1234 \
  --min-age 18 \
  --output age_proof.bin
```

Anyone can verify the proof (without seeing your actual age):

```bash
aadhar-zk verify-age \
  --proof age_proof.bin \
  --min-age 18 \
  --commitment 123456789
```

## What You Can Prove

**Age threshold**: "I'm at least 18 years old"
```bash
aadhar-zk prove-age -f aadhar.zip -c 1234 --min-age 18 -o proof.bin
```

**Age range**: "I'm between 25 and 65"
```bash
aadhar-zk prove-age-range -f aadhar.zip -c 1234 --min-age 25 --max-age 65 -o proof.bin
```

**Attribute matching**: "I live in Delhi" (without showing your address)
```bash
aadhar-zk prove-attribute -f aadhar.zip -c 1234 --attr-type state --value "Delhi" -o proof.bin
```

**Multiple claims at once**:
Create a `claims.json` file:
```json
[
  {"type": "age_range", "min": 18, "max": 65},
  {"type": "attribute_equals", "attribute": "state", "value": "Delhi"},
  {"type": "attribute_equals", "attribute": "gender", "value": "M"}
]
```

Then generate a single proof for all claims:
```bash
aadhar-zk prove-batch -f aadhar.zip -c 1234 --claims-file claims.json -o proof.bin
```

## How It Works

1. **Parse Aadhaar file**: Extract and verify the XML digital signature (uses RSA-2048)
2. **Generate commitment**: Create a cryptographic hash of your full Aadhaar data
3. **Create ZK proof**: Generate a STARK proof that proves your claim without revealing the data
4. **Verify proof**: Anyone can check the proof is valid (takes ~50ms)

The key insight: the proof is mathematically bound to your real Aadhaar data (via the commitment), but reveals nothing except the specific claim being proven.

## Security

- Zero unsafe Rust code (memory safe)
- XMLDSig signature verification ensures Aadhaar authenticity
- ZIP bomb protection (10MB limit)
- Input validation on all user inputs
- STARK soundness: < 2^-100 probability of creating fake proofs

Known issues:
- RSA crate has a timing side-channel vulnerability (RUSTSEC-2023-0071), but we only use it for public key operations, so not exploitable


## Performance

| Operation | Time | Proof Size |
|-----------|------|------------|
| Proof generation | ~1.4 seconds | ~58 KB |
| Proof verification | ~50 milliseconds | - |

*Measured on macOS, single-threaded*

## Architecture

```
Aadhaar ZIP (password-protected)
    ↓
XML Signature Verification (RSA-2048, XMLDSig)
    ↓
Parse Data + Compute Commitment
    ↓
Generate STARK Proof (Plonky3)
    ↓
Verify Proof (~50ms)
```

Built with:
- Plonky3 for STARK proofs
- Mersenne31 field arithmetic
- FRI polynomial commitments
- XML canonicalization (C14N)

## Project Structure

```
crates/
├── core/
│   ├── circuit/          # ZK proof circuits
│   ├── crypto/           # XMLDSig verification, RSA, canonicalization
│   └── xml/              # Aadhaar XML parsing
└── cli/                  # Command-line tool
```


## License

Dual-licensed under MIT or Apache 2.0, your choice.

## Disclaimer

This is research software. While production-ready from a code quality standpoint, it has not undergone a formal security audit. The cryptography is sound, but use in production at your own risk.

## Acknowledgments

Built using Plonky3 STARK framework and Rust cryptography libraries. Aadhaar specification from UIDAI.
