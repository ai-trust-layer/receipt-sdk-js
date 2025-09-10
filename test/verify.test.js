import { validateSchema, verifyHashes, verifySignature, verifySignatureAsync, verifyAnchor } from '../src/verify.js';
import { createMockSignature } from '../src/signature.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Test data
const validReceipt = {
  "id": "urn:receipt:test:001",
  "issued_at": "2025-01-08T10:00:00Z",
  "model_version": "test:model@1.0",
  "policy_version": "trust:standard@1.0",
  "input_hash": "sha256:82562f2a6e19613ec2a39e0bb198f1156d37240e4af948d2262a9c649a19b718",
  "output_hash": "sha256:775e645fa1ff940e652c9f7d2622c6526bb75920951990929f41518af6bf97b5",
  "timestamp": "2025-01-08T10:00:05Z",
  "proof_refs": [
    {
      "type": "ANCHOR",
      "network": "ethereum-sepolia",
      "tx": "0x1234567890abcdef",
      "finality_level": "final"
    }
  ],
  "trustscore": 85,
  "signature": "did:web:example.org#k1 sig:mock-signature"
};

const invalidReceipt = {
  "id": "urn:receipt:test:002",
  "issued_at": "invalid-date",
  "model_version": "test:model@1.0",
  "policy_version": "trust:standard@1.0",
  "input_hash": "invalid-hash",
  "output_hash": "sha256:validhash",
  "timestamp": "2025-01-08T10:00:05Z",
  "proof_refs": [],
  "trustscore": 150,
  "signature": "invalid-signature"
};

// Test schema validation
console.log('Testing schema validation...');

const validResult = validateSchema(validReceipt);
console.log('Valid receipt:', validResult.ok ? 'PASS' : 'FAIL');
if (!validResult.ok) {
  console.log('Errors:', validResult.errors);
}

const invalidResult = validateSchema(invalidReceipt);
console.log('Invalid receipt:', !invalidResult.ok ? 'PASS' : 'FAIL');
if (invalidResult.ok) {
  console.log('Should have failed but passed');
}

// Test hash verification
console.log('\nTesting hash verification...');

// Create temporary test files
const testInput = 'This is test input content';
const testOutput = 'This is test output content';
const inputPath = path.join(__dirname, 'test-input.txt');
const outputPath = path.join(__dirname, 'test-output.txt');

fs.writeFileSync(inputPath, testInput);
fs.writeFileSync(outputPath, testOutput);

// Test with correct hashes
const correctHashes = verifyHashes({
  receipt: validReceipt,
  inputPath: inputPath,
  outputPath: outputPath
});

console.log('Hash verification (correct):', correctHashes.ok ? 'PASS' : 'FAIL');
if (!correctHashes.ok) {
  console.log('Details:', correctHashes.details);
}

// Test with incorrect hashes
const incorrectHashes = verifyHashes({
  receipt: { ...validReceipt, input_hash: 'sha256:wronghash' },
  inputPath: inputPath,
  outputPath: outputPath
});

console.log('Hash verification (incorrect):', !incorrectHashes.ok ? 'PASS' : 'FAIL');

// Test anchor verification
console.log('\nTesting anchor verification...');

const validAnchor = verifyAnchor(validReceipt);
console.log('Valid anchor:', validAnchor.ok ? 'PASS' : 'FAIL');

const invalidAnchor = verifyAnchor({ ...validReceipt, proof_refs: [] });
console.log('Invalid anchor:', !invalidAnchor.ok ? 'PASS' : 'FAIL');

// Test signature verification
console.log('\nTesting signature verification...');

const signatureResult = verifySignature(validReceipt);
console.log('Signature verification (sync):', signatureResult.ok ? 'PASS' : 'FAIL');
console.log('Reason:', signatureResult.reason);

// Test async signature verification
(async () => {
  const asyncSignatureResult = await verifySignatureAsync(validReceipt);
  console.log('Signature verification (async):', asyncSignatureResult.ok ? 'PASS' : 'FAIL');
  console.log('Reason:', asyncSignatureResult.reason);
  
  // Test mock signature creation
  const mockSignature = createMockSignature(validReceipt);
  console.log('Mock signature created:', mockSignature ? 'PASS' : 'FAIL');
  console.log('Mock signature:', mockSignature);
  
  // Cleanup
  fs.unlinkSync(inputPath);
  fs.unlinkSync(outputPath);
  
  console.log('\nAll tests completed!');
})();
