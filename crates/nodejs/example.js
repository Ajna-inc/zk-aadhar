/**
 * Example usage of Aadhar ZK Node.js bindings
 */

const {
  parseAadharXml,
  proveAgeThreshold,
  proveAgeRange,
  createDIDCommAgeResponse,
  verifyAgeThreshold,
  getVersion,
} = require('./index.js');

const crypto = require('crypto');
const fs = require('fs');

console.log('Aadhar ZK Version:', getVersion());
console.log('');

/**
 * Example 1: Parse XML from storage
 */
function exampleParseXml(xmlString) {
  console.log('=== Example 1: Parse XML ===');

  const aadhar = parseAadharXml(xmlString);

  console.log('Reference ID:', aadhar.referenceId);
  console.log('Name:', aadhar.name);
  console.log('DOB:', aadhar.dob);
  console.log('Age:', aadhar.age);
  console.log('Gender:', aadhar.gender);
  console.log('Commitment:', aadhar.commitment);
  console.log('Signature Verified:', aadhar.signatureVerified);
  console.log('');

  return aadhar;
}

/**
 * Example 2: Generate age threshold proof
 */
async function exampleAgeProof(xmlString) {
  console.log('=== Example 2: Age Threshold Proof (age >= 18) ===');

  // Create DIDComm context
  const context = {
    nonce: '0x' + crypto.randomBytes(32).toString('hex'),
    contextHash: '0x' + crypto.createHash('sha256').update('request-context').digest('hex'),
    sessionId: '0x' + crypto.randomBytes(16).toString('hex'),
  };

  console.log('Context created:');
  console.log('  Nonce:', context.nonce.substring(0, 20) + '...');
  console.log('  Context Hash:', context.contextHash.substring(0, 20) + '...');
  console.log('  Session ID:', context.sessionId);
  console.log('');

  // Generate proof
  console.time('Proof generation');
  const proof = proveAgeThreshold(xmlString, 18, context);
  console.timeEnd('Proof generation');

  console.log('Proof generated:');
  console.log('  Circuit ID:', proof.metadata.circuitId);
  console.log('  Scheme:', proof.metadata.scheme);
  console.log('  Proof size:', proof.metadata.proofSizeBytes, 'bytes');
  console.log('  Generation time:', proof.metadata.generationTimeMs, 'ms');
  console.log('  VK Hash:', proof.metadata.vkHash.substring(0, 20) + '...');
  console.log('  Outputs Hash:', proof.metadata.outputsHash.substring(0, 20) + '...');
  console.log('  Proof (base64):', proof.proof.substring(0, 50) + '...');
  console.log('');

  return { proof, context };
}

/**
 * Example 3: Create DIDComm response
 */
function exampleDIDCommResponse(xmlString, proofResult, context) {
  console.log('=== Example 3: DIDComm Response ===');

  const response = createDIDCommAgeResponse(xmlString, proofResult, context, 18);

  console.log('DIDComm Response:');
  console.log('  Program ID:', response.programId);
  console.log('  Result:', response.result);
  console.log('  Commitment:', response.public.commitment);
  console.log('  ZK Scheme:', response.zk.scheme);
  console.log('  Circuit ID:', response.zk.circuitId);
  console.log('');

  // Show JSON structure
  console.log('Full JSON (first 200 chars):');
  const json = JSON.stringify(response, null, 2);
  console.log(json.substring(0, 200) + '...');
  console.log('');

  return response;
}

/**
 * Example 4: Verify proof
 */
function exampleVerifyProof(proofResult, aadhar, context) {
  console.log('=== Example 4: Verify Proof ===');

  console.time('Proof verification');
  const isValid = verifyAgeThreshold(
    proofResult.proof,
    18,
    aadhar.commitment,
    context,
    proofResult.metadata.outputsHash
  );
  console.timeEnd('Proof verification');

  console.log('Verification result:', isValid ? '✅ VALID' : '❌ INVALID');
  console.log('');

  return isValid;
}

/**
 * Example 5: Age range proof
 */
function exampleAgeRangeProof(xmlString) {
  console.log('=== Example 5: Age Range Proof (18 <= age <= 65) ===');

  const context = {
    nonce: '0x' + crypto.randomBytes(32).toString('hex'),
    contextHash: '0x' + crypto.createHash('sha256').update('range-context').digest('hex'),
    sessionId: '0x' + crypto.randomBytes(16).toString('hex'),
  };

  console.time('Range proof generation');
  const proof = proveAgeRange(xmlString, 18, 65, context);
  console.timeEnd('Range proof generation');

  console.log('Range proof generated:');
  console.log('  Circuit ID:', proof.metadata.circuitId);
  console.log('  Proof size:', proof.metadata.proofSizeBytes, 'bytes');
  console.log('');

  return proof;
}

/**
 * Example 6: Complete workflow with Ascar DB simulation
 */
async function exampleCompleteWorkflow() {
  console.log('=== Example 6: Complete Mobile Workflow ===');
  console.log('');

  // Simulate: App retrieves encrypted XML from Ascar DB
  console.log('1. App retrieves encrypted XML from Ascar DB...');
  const encryptedXml = '...'; // Would be actual encrypted data
  console.log('   ✓ Retrieved');
  console.log('');

  // Simulate: App decrypts XML
  console.log('2. App decrypts XML using device key...');
  const xmlString = '...'; // Would be decrypted XML
  console.log('   ✓ Decrypted');
  console.log('');

  // 3. Parse XML
  console.log('3. Parse Aadhar data from XML...');
  // const aadhar = parseAadharXml(xmlString);
  console.log('   ✓ Parsed (commitment:', '12345', ')');
  console.log('');

  // 4. Generate proof
  console.log('4. Generate ZK proof with DIDComm context...');
  const context = {
    nonce: '0x' + crypto.randomBytes(32).toString('hex'),
    contextHash: '0x' + crypto.randomBytes(32).toString('hex'),
    sessionId: '0x' + crypto.randomBytes(16).toString('hex'),
  };
  // const proof = proveAgeThreshold(xmlString, 18, context);
  console.log('   ✓ Proof generated (~50KB)');
  console.log('');

  // 5. Create DIDComm response
  console.log('5. Create DIDComm response...');
  // const response = createDIDCommAgeResponse(xmlString, proof, context, 18);
  console.log('   ✓ Response formatted');
  console.log('');

  // 6. Send to verifier
  console.log('6. Send proof to verifier via DIDComm...');
  console.log('   ✓ Sent (program_id: aadhaar.zk.age-threshold.v1)');
  console.log('');

  console.log('Workflow complete! ✨');
  console.log('');
}

// Main execution
async function main() {
  console.log('╔════════════════════════════════════════════════════════╗');
  console.log('║    Aadhar ZK Proof System - Node.js Examples          ║');
  console.log('╚════════════════════════════════════════════════════════╝');
  console.log('');

  // Note: Replace with actual XML content
  const sampleXml = `
    <OfflinePaperlessKyc referenceId="123456789">
      <UidData>
        <Poi name="Test User" dob="01-01-2000" gender="M"/>
        <Poa dist="Delhi" state="Delhi"/>
      </UidData>
      <Signature>base64signature...</Signature>
    </OfflinePaperlessKyc>
  `;

  try {
    // Run examples with real XML if available
    if (fs.existsSync('../../tests/fixtures/sample.xml')) {
      const xmlString = fs.readFileSync('../../tests/fixtures/sample.xml', 'utf8');

      const aadhar = exampleParseXml(xmlString);
      const { proof, context } = await exampleAgeProof(xmlString);
      exampleDIDCommResponse(xmlString, proof, context);
      exampleVerifyProof(proof, aadhar, context);
      exampleAgeRangeProof(xmlString);
    } else {
      console.log('Note: Real XML file not found. Showing workflow example only.');
      console.log('');
    }

    await exampleCompleteWorkflow();

    console.log('╔════════════════════════════════════════════════════════╗');
    console.log('║  All examples completed successfully! ✅               ║');
    console.log('╚════════════════════════════════════════════════════════╝');
  } catch (error) {
    console.error('Error:', error.message);
    console.error('');
    console.error('Note: This is expected if running without real Aadhar XML file.');
    console.error('For real usage, provide XML content from Ascar DB.');
  }
}

// Run if executed directly
if (require.main === module) {
  main().catch(console.error);
}

module.exports = {
  exampleParseXml,
  exampleAgeProof,
  exampleDIDCommResponse,
  exampleVerifyProof,
  exampleAgeRangeProof,
  exampleCompleteWorkflow,
};
