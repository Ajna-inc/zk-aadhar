# @ajna-inc/zk-aadhar

Zero-knowledge proof system for India's Aadhaar offline KYC verification using STARK proofs.

## Features

- 🔐 **Zero-Knowledge Proofs** - Prove age/attributes without revealing PII
- ⚡ **STARK-based** - Fast proof generation (~12ms) using Plonky3
- 🔒 **Digital Signature Verification** - Validates UIDAI's RSA signature
- 🌐 **DIDComm Compatible** - Proof-of-Execution format support
- 🚫 **Replay Protection** - Context binding prevents proof reuse
- 📱 **Mobile-Ready** - Works with Ascar DB for secure storage

## Installation

```bash
npm install @ajna-inc/zk-aadhar
```

## Quick Start

```javascript
const {
  parseAadharXml,
  proveAgeThreshold,
  verifyAgeThreshold,
  createDidcommAgeResponse,
  getVersion
} = require('@ajna-inc/zk-aadhar');

// 1. Parse Aadhaar XML (from offline KYC ZIP)
const aadhar = parseAadharXml(xmlString);
console.log('Name:', aadhar.name);
console.log('Age:', aadhar.age);
console.log('Commitment:', aadhar.commitment);

// 2. Create DIDComm context for proof
const context = {
  nonce: '0x' + randomBytes(32).toString('hex'),
  contextHash: '0x' + sha256(requestData).toString('hex'),
  sessionId: '0x' + randomBytes(16).toString('hex')
};

// 3. Generate age threshold proof (age >= 18)
const proof = proveAgeThreshold(xmlString, 18, context);

// 4. Create DIDComm response
const response = createDidcommAgeResponse(xmlString, proof, context, 18);

// 5. Verify proof
const isValid = verifyAgeThreshold(
  proof.proof,
  18,
  aadhar.commitment,
  context,
  proof.metadata.outputsHash
);
```

## API Reference

### `parseAadharXml(xmlContent: string): AadharData`

Parses Aadhaar offline KYC XML and verifies digital signature.

**Returns:**
```typescript
{
  referenceId: string,
  name: string,
  dob: string,
  gender: string,
  age: number,
  commitment: number,
  signatureVerified: boolean
}
```

### `proveAgeThreshold(xmlContent: string, minAge: number, context: ProofContext): ProofResult`

Generates a zero-knowledge proof that age >= minAge.

**Parameters:**
- `xmlContent` - Raw Aadhaar XML string
- `minAge` - Minimum age threshold
- `context` - DIDComm context (nonce, contextHash, sessionId)

**Returns:**
```typescript
{
  proof: string,        // Base64-encoded STARK proof
  metadata: {
    circuitId: string,
    vkHash: string,
    outputsHash: string,
    proofSizeBytes: number,
    scheme: string,
    generationTimeMs: number
  }
}
```

### `proveAgeRange(xmlContent: string, minAge: number, maxAge: number, context: ProofContext): ProofResult`

Generates proof that minAge <= age <= maxAge.

### `createDidcommAgeResponse(xmlContent: string, proof: ProofResult, context: ProofContext, minAge: number): DIDCommProofResponse`

Creates a DIDComm-compatible proof response.

**Returns:**
```typescript
{
  programId: string,
  result: string,
  public: {
    nonce: string,
    contextHash: string,
    sessionId: string,
    outputsHash: string,
    vkHash: string,
    commitment: number
  },
  zk: {
    scheme: string,
    circuitId: string,
    vkHash: string,
    proofB64: string
  }
}
```

### `verifyAgeThreshold(proofBase64: string, minAge: number, commitment: number, context: ProofContext, outputsHash: string): boolean`

Verifies an age threshold proof.

**Returns:** `true` if proof is valid, throws error otherwise.

### `getVersion(): string`

Returns the library version.

## Mobile Integration with Ascar DB

```javascript
// 1. Extract XML from offline KYC ZIP
const xmlContent = extractFromZip(zipFile, shareCode);

// 2. Base64-encode for Ascar DB storage
const xmlBase64 = Buffer.from(xmlContent).toString('base64');
await ascarDb.store('aadhar_xml', xmlBase64);

// 3. Later: Retrieve and decode
const storedBase64 = await ascarDb.retrieve('aadhar_xml');
const xmlString = Buffer.from(storedBase64, 'base64').toString('utf-8');

// 4. Generate proof
const proof = proveAgeThreshold(xmlString, 18, context);
```

## Performance

Benchmarked on Apple M-series (arm64):

| Operation | Time | Notes |
|-----------|------|-------|
| Parse XML | < 1ms | Includes signature verification |
| Generate Proof (threshold) | ~12ms | STARK proof, 58KB |
| Generate Proof (range) | ~68ms | STARK proof, 59KB |
| Verify Proof | ~2ms | Very fast verification |

## Security Features

- ✅ **Digital Signature Verification** - UIDAI's RSA-2048 signature
- ✅ **Zero-Knowledge** - No PII revealed in proofs
- ✅ **Replay Protection** - Context binding prevents reuse
- ✅ **Commitment Binding** - Proof tied to specific Aadhaar
- ✅ **Tamper Detection** - Invalid XML rejected

## Platform Support

Pre-built binaries for:
- macOS (x64, arm64)
- Linux (x64, arm64, musl)
- Windows (x64, arm64)

## Example Code

See `example.js` for complete usage examples including:
- XML parsing
- Proof generation
- DIDComm responses
- Proof verification
- Mobile workflow simulation

## License

MIT

## Links

- [GitHub](https://github.com/ajna-inc/offline-aadhar-poe)
- [Issues](https://github.com/ajna-inc/offline-aadhar-poe/issues)
- [DIDComm Spec](https://didcomm.org/)

## Warning

⚠️ **Never commit real Aadhaar data to version control!**

This library is for legitimate KYC verification only. Misuse of Aadhaar data is illegal under Indian law.
