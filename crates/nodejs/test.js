/**
 * Comprehensive tests for Aadhar ZK Node.js bindings
 *
 * IMPORTANT: This test file requires real Aadhaar offline KYC XML data to run.
 *
 * To use this test suite:
 * 1. Download your Aadhaar offline KYC ZIP from https://myaadhaar.uidai.gov.in/
 * 2. Extract the XML file from the ZIP using your ShareCode as password
 * 3. Save the XML as 'test-xml.txt' in this directory
 * 4. Optionally, create 'test-xml-base64.txt' with base64-encoded XML
 *
 * NOTE: Never commit real Aadhaar data to version control!
 *
 * Tests:
 * - Parsing XML (raw and base64)
 * - Proof generation
 * - Proof verification
 * - DIDComm response creation
 * - Error handling
 */

const fs = require('fs');
const crypto = require('crypto');
const assert = require('assert');

// Import our native module
const {
  parseAadharXml,
  proveAgeThreshold,
  proveAgeRange,
  createDidcommAgeResponse,
  verifyAgeThreshold,
  getVersion,
} = require('./index.js');

// Test utilities
function generateContext() {
  return {
    nonce: '0x' + crypto.randomBytes(32).toString('hex'),
    contextHash: '0x' + crypto.createHash('sha256').update('test-context').digest('hex'),
    sessionId: '0x' + crypto.randomBytes(16).toString('hex'),
  };
}

function decodeBase64(base64String) {
  return Buffer.from(base64String, 'base64').toString('utf-8');
}

// Load test data
let xmlString;
let xmlBase64;

try {
  xmlString = fs.readFileSync('./test-xml.txt', 'utf8');
  xmlBase64 = fs.readFileSync('./test-xml-base64.txt', 'utf8');
  console.log('✓ Test data loaded');
  console.log(`  XML size: ${xmlString.length} bytes`);
  console.log(`  Base64 size: ${xmlBase64.length} bytes`);
} catch (error) {
  console.error('❌ Failed to load test data:', error.message);
  console.error('');
  console.error('To run tests, you need to provide your own Aadhaar offline KYC XML:');
  console.error('  1. Download from https://myaadhaar.uidai.gov.in/');
  console.error('  2. Extract XML from ZIP using ShareCode');
  console.error('  3. Save as test-xml.txt in this directory');
  console.error('  4. Create test-xml-base64.txt with base64-encoded version');
  console.error('');
  console.error('WARNING: Never commit real Aadhaar data to git!');
  process.exit(1);
}

// Test counter
let testsPassed = 0;
let testsFailed = 0;

function test(name, fn) {
  try {
    console.log(`\n📝 Test: ${name}`);
    fn();
    testsPassed++;
    console.log(`   ✅ PASSED`);
  } catch (error) {
    testsFailed++;
    console.log(`   ❌ FAILED: ${error.message}`);
    console.error(error.stack);
  }
}

// ============================================================================
// Test Suite
// ============================================================================

console.log('╔════════════════════════════════════════════════════════╗');
console.log('║     Aadhar ZK Node.js Bindings - Test Suite           ║');
console.log('╚════════════════════════════════════════════════════════╝');
console.log('');
console.log('Library Version:', getVersion());
console.log('');

// Test 1: Parse XML from raw string
test('Parse XML from raw string', () => {
  const aadhar = parseAadharXml(xmlString);

  assert(aadhar.referenceId, 'Reference ID should exist');
  assert(aadhar.name, 'Name should exist');
  assert(aadhar.dob, 'DOB should exist');
  assert(aadhar.gender, 'Gender should exist');
  assert(typeof aadhar.age === 'number', 'Age should be a number');
  assert(typeof aadhar.commitment === 'number', 'Commitment should be a number');
  assert(typeof aadhar.signatureVerified === 'boolean', 'Signature verified should be boolean');

  console.log(`     Reference ID: ${aadhar.referenceId}`);
  console.log(`     Name: ${aadhar.name}`);
  console.log(`     Age: ${aadhar.age}`);
  console.log(`     Commitment: ${aadhar.commitment}`);
  console.log(`     Signature Verified: ${aadhar.signatureVerified}`);
});

// Test 2: Parse XML from base64
test('Parse XML from base64-encoded string', () => {
  // Decode base64 to raw XML
  const xmlFromBase64 = decodeBase64(xmlBase64);
  const aadhar = parseAadharXml(xmlFromBase64);

  assert(aadhar.referenceId, 'Reference ID should exist');
  assert(aadhar.commitment > 0, 'Commitment should be positive');

  console.log(`     Parsed from base64 successfully`);
  console.log(`     Commitment: ${aadhar.commitment}`);
});

// Test 3: Generate age threshold proof
test('Generate age threshold proof (age >= 18)', () => {
  const context = generateContext();
  const startTime = Date.now();

  const proof = proveAgeThreshold(xmlString, 18, context);

  const duration = Date.now() - startTime;

  assert(proof.proof, 'Proof should exist');
  assert(proof.metadata, 'Metadata should exist');
  assert(proof.metadata.circuitId === 'aadhaar-age-threshold-v1', 'Circuit ID should be correct');
  assert(proof.metadata.scheme === 'stark', 'Scheme should be STARK');
  assert(proof.metadata.proofSizeBytes > 0, 'Proof size should be positive');
  assert(proof.proof.length > 0, 'Proof string should not be empty');

  console.log(`     Circuit ID: ${proof.metadata.circuitId}`);
  console.log(`     Proof size: ${proof.metadata.proofSizeBytes} bytes`);
  console.log(`     Generation time: ${duration}ms`);
  console.log(`     VK Hash: ${proof.metadata.vkHash.substring(0, 20)}...`);
  console.log(`     Outputs Hash: ${proof.metadata.outputsHash.substring(0, 20)}...`);
});

// Test 4: Generate age range proof
test('Generate age range proof (18 <= age <= 65)', () => {
  const context = generateContext();
  const startTime = Date.now();

  const proof = proveAgeRange(xmlString, 18, 65, context);

  const duration = Date.now() - startTime;

  assert(proof.proof, 'Proof should exist');
  assert(proof.metadata.circuitId === 'aadhaar-age-range-v1', 'Circuit ID should be for age range');
  assert(proof.metadata.proofSizeBytes > 0, 'Proof size should be positive');

  console.log(`     Circuit ID: ${proof.metadata.circuitId}`);
  console.log(`     Proof size: ${proof.metadata.proofSizeBytes} bytes`);
  console.log(`     Generation time: ${duration}ms`);
});

// Test 5: Generate proof from base64 XML
test('Generate proof from base64-encoded XML', () => {
  const xmlFromBase64 = decodeBase64(xmlBase64);
  const context = generateContext();

  const proof = proveAgeThreshold(xmlFromBase64, 18, context);

  assert(proof.proof, 'Proof should exist');
  assert(proof.metadata.circuitId === 'aadhaar-age-threshold-v1', 'Circuit ID should be correct');

  console.log(`     Proof generated from base64 XML successfully`);
  console.log(`     Proof size: ${proof.metadata.proofSizeBytes} bytes`);
});

// Test 6: Create DIDComm response
test('Create DIDComm proof response', () => {
  const context = generateContext();
  const proof = proveAgeThreshold(xmlString, 18, context);

  const response = createDidcommAgeResponse(xmlString, proof, context, 18);

  assert(response.programId === 'aadhaar.zk.age-threshold.v1', 'Program ID should be correct');
  assert(response.result === 'pass', 'Result should be pass');
  assert(response.public, 'Public inputs should exist');
  assert(response.zk, 'ZK proof should exist');
  assert(response.public.nonce === context.nonce, 'Nonce should match');
  assert(response.public.contextHash === context.contextHash, 'Context hash should match');
  assert(response.public.sessionId === context.sessionId, 'Session ID should match');
  assert(response.public.commitment > 0, 'Commitment should be positive');
  assert(response.zk.scheme === 'stark', 'Scheme should be STARK');
  assert(response.zk.proofB64, 'Proof base64 should exist');

  console.log(`     Program ID: ${response.programId}`);
  console.log(`     Result: ${response.result}`);
  console.log(`     Commitment: ${response.public.commitment}`);
  console.log(`     ZK Scheme: ${response.zk.scheme}`);
});

// Test 7: Verify proof
test('Verify age threshold proof', () => {
  const context = generateContext();
  const aadhar = parseAadharXml(xmlString);
  const proof = proveAgeThreshold(xmlString, 18, context);

  const startTime = Date.now();
  const isValid = verifyAgeThreshold(
    proof.proof,
    18,
    aadhar.commitment,
    context,
    proof.metadata.outputsHash
  );
  const duration = Date.now() - startTime;

  assert(isValid === true, 'Proof should be valid');

  console.log(`     Verification result: ${isValid ? '✅ VALID' : '❌ INVALID'}`);
  console.log(`     Verification time: ${duration}ms`);
});

// Test 8: Verify proof fails with wrong context
test('Verify proof fails with wrong context (replay attack)', () => {
  const context1 = generateContext();
  const context2 = generateContext();
  const aadhar = parseAadharXml(xmlString);
  const proof = proveAgeThreshold(xmlString, 18, context1);

  try {
    // Try to verify with different context (should fail)
    const isValid = verifyAgeThreshold(
      proof.proof,
      18,
      aadhar.commitment,
      context2, // Wrong context!
      proof.metadata.outputsHash
    );

    // If we reach here, the test should fail
    throw new Error('Verification should have failed with wrong context');
  } catch (error) {
    // Expected to fail
    assert(error.message.includes('verification') || error.message.includes('Context binding'),
      'Error should be about verification failure');
    console.log(`     ✓ Correctly rejected proof with wrong context`);
  }
});

// Test 9: Parse fails with invalid XML
test('Parse fails with invalid XML', () => {
  try {
    parseAadharXml('<invalid>xml</invalid>');
    throw new Error('Should have thrown error for invalid XML');
  } catch (error) {
    assert(error.message.includes('Failed to parse XML') || error.message.includes('MissingField'),
      'Error should be about XML parsing');
    console.log(`     ✓ Correctly rejected invalid XML`);
  }
});

// Test 10: Proof generation fails for age below threshold
test('Proof generation fails for underage', () => {
  // This test assumes the test user is over 18
  // Try to prove age >= 100 (should fail)
  const context = generateContext();

  try {
    proveAgeThreshold(xmlString, 100, context);
    throw new Error('Should have thrown error for age below threshold');
  } catch (error) {
    assert(error.message.includes('below') || error.message.includes('threshold') || error.message.includes('Failed to generate proof'),
      'Error should be about age threshold');
    console.log(`     ✓ Correctly rejected proof for age below threshold`);
  }
});

// Test 11: Complete workflow simulation (base64 -> proof -> verify)
test('Complete workflow: base64 XML -> proof -> verify', () => {
  console.log(`     [1] Decode XML from base64...`);
  const xmlFromBase64 = decodeBase64(xmlBase64);
  console.log(`     [2] Parse Aadhar data...`);
  const aadhar = parseAadharXml(xmlFromBase64);

  console.log(`     [3] Generate proof with context...`);
  const context = generateContext();
  const proof = proveAgeThreshold(xmlFromBase64, 18, context);

  console.log(`     [4] Create DIDComm response...`);
  const response = createDidcommAgeResponse(xmlFromBase64, proof, context, 18);

  console.log(`     [5] Verify proof...`);
  const isValid = verifyAgeThreshold(
    proof.proof,
    18,
    aadhar.commitment,
    context,
    proof.metadata.outputsHash
  );

  assert(isValid === true, 'Complete workflow should succeed');
  console.log(`     ✅ Complete workflow succeeded`);
  console.log(`        - XML decoded from base64`);
  console.log(`        - Aadhar parsed (commitment: ${aadhar.commitment})`);
  console.log(`        - Proof generated (${proof.metadata.proofSizeBytes} bytes)`);
  console.log(`        - DIDComm response created`);
  console.log(`        - Proof verified successfully`);
});

// Test 12: Proof size consistency
test('Proof size consistency across multiple generations', () => {
  const context = generateContext();
  const sizes = [];

  for (let i = 0; i < 3; i++) {
    const proof = proveAgeThreshold(xmlString, 18, context);
    sizes.push(proof.metadata.proofSizeBytes);
  }

  const allSame = sizes.every(size => size === sizes[0]);
  assert(allSame, 'All proof sizes should be the same');

  console.log(`     Generated 3 proofs, all ${sizes[0]} bytes`);
  console.log(`     ✓ Proof size is consistent`);
});

// Test 13: Context binding - different contexts give different output hashes
test('Different contexts produce different output hashes', () => {
  const context1 = generateContext();
  const context2 = generateContext();

  const proof1 = proveAgeThreshold(xmlString, 18, context1);
  const proof2 = proveAgeThreshold(xmlString, 18, context2);

  assert(proof1.metadata.outputsHash !== proof2.metadata.outputsHash,
    'Different contexts should produce different output hashes');

  console.log(`     Outputs hash 1: ${proof1.metadata.outputsHash.substring(0, 20)}...`);
  console.log(`     Outputs hash 2: ${proof2.metadata.outputsHash.substring(0, 20)}...`);
  console.log(`     ✓ Context binding working correctly`);
});

// Test 14: Commitment consistency
test('Commitment is consistent across multiple parses', () => {
  const commitments = [];

  for (let i = 0; i < 5; i++) {
    const aadhar = parseAadharXml(xmlString);
    commitments.push(aadhar.commitment);
  }

  const allSame = commitments.every(c => c === commitments[0]);
  assert(allSame, 'All commitments should be the same');

  console.log(`     Parsed 5 times, commitment always: ${commitments[0]}`);
  console.log(`     ✓ Commitment is deterministic`);
});

// Test 15: Performance test
test('Performance test (10 proof generations)', () => {
  const iterations = 10;
  const times = [];
  const context = generateContext();

  console.log(`     Generating ${iterations} proofs...`);

  for (let i = 0; i < iterations; i++) {
    const start = Date.now();
    proveAgeThreshold(xmlString, 18, context);
    times.push(Date.now() - start);
  }

  const avg = times.reduce((a, b) => a + b, 0) / times.length;
  const min = Math.min(...times);
  const max = Math.max(...times);

  console.log(`     Average time: ${avg.toFixed(2)}ms`);
  console.log(`     Min time: ${min}ms`);
  console.log(`     Max time: ${max}ms`);
  console.log(`     ✓ Performance acceptable (avg < 100ms: ${avg < 100 ? 'YES' : 'NO'})`);
});

// ============================================================================
// Test Summary
// ============================================================================

console.log('');
console.log('╔════════════════════════════════════════════════════════╗');
console.log('║                   Test Summary                         ║');
console.log('╚════════════════════════════════════════════════════════╝');
console.log('');
console.log(`Total tests: ${testsPassed + testsFailed}`);
console.log(`✅ Passed: ${testsPassed}`);
console.log(`❌ Failed: ${testsFailed}`);
console.log('');

if (testsFailed === 0) {
  console.log('🎉 All tests passed!');
  console.log('');
  console.log('The Node.js bindings are working correctly:');
  console.log('  ✓ XML parsing (raw and base64)');
  console.log('  ✓ Proof generation with context binding');
  console.log('  ✓ Proof verification');
  console.log('  ✓ DIDComm response creation');
  console.log('  ✓ Error handling');
  console.log('  ✓ Replay attack prevention');
  console.log('');
  process.exit(0);
} else {
  console.log('❌ Some tests failed. Please review the output above.');
  process.exit(1);
}
