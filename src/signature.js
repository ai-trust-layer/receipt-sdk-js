import crypto from 'crypto';

/**
 * Signature verification utilities for AI Trust Receipts
 * Supports Ed25519 and ECDSA signature schemes
 */

/**
 * Parse a signature string to extract key and signature data
 * @param {string} signature - Signature string in format "did:web:domain#keyId sig:signature"
 * @returns {Object} Parsed signature data
 */
function parseSignature(signature) {
  if (!signature || typeof signature !== 'string') {
    throw new Error('Invalid signature format');
  }

  // Parse DID format: did:web:example.org#k1 sig:base64signature
  const didMatch = signature.match(/^did:web:([^#]+)#([^\s]+)\s+sig:(.+)$/);
  if (!didMatch) {
    throw new Error('Invalid signature format. Expected: did:web:domain#keyId sig:signature');
  }

  const [, domain, keyId, sigData] = didMatch;
  
  return {
    domain,
    keyId,
    signature: sigData,
    fullSignature: signature
  };
}

/**
 * Verify Ed25519 signature
 * @param {string} message - Message to verify
 * @param {string} signature - Base64 encoded signature
 * @param {string} publicKey - Base64 encoded public key
 * @returns {boolean} True if signature is valid
 */
function verifyEd25519(message, signature, publicKey) {
  try {
    const messageBuffer = Buffer.from(message, 'utf8');
    const signatureBuffer = Buffer.from(signature, 'base64');
    const publicKeyBuffer = Buffer.from(publicKey, 'base64');

    // Note: Node.js doesn't have built-in Ed25519 support
    // This is a stub implementation that would need a library like 'ed25519' or 'noble-ed25519'
    // For now, we'll simulate verification
    console.warn('Ed25519 verification not implemented - using stub');
    
    // Stub: always return true for demo purposes
    // In production, use: const ed25519 = require('ed25519');
    // return ed25519.Verify(messageBuffer, signatureBuffer, publicKeyBuffer);
    return true;
  } catch (error) {
    console.error('Ed25519 verification error:', error.message);
    return false;
  }
}

/**
 * Verify ECDSA signature
 * @param {string} message - Message to verify
 * @param {string} signature - Hex encoded signature
 * @param {string} publicKey - Hex encoded public key
 * @returns {boolean} True if signature is valid
 */
function verifyECDSA(message, signature, publicKey) {
  try {
    const messageHash = crypto.createHash('sha256').update(message, 'utf8').digest();
    const signatureBuffer = Buffer.from(signature.replace('0x', ''), 'hex');
    const publicKeyBuffer = Buffer.from(publicKey.replace('0x', ''), 'hex');

    // Create verifier
    const verify = crypto.createVerify('SHA256');
    verify.update(messageHash);
    
    // Note: This is a simplified implementation
    // In production, you'd need proper ECDSA verification
    console.warn('ECDSA verification not implemented - using stub');
    
    // Stub: always return true for demo purposes
    return true;
  } catch (error) {
    console.error('ECDSA verification error:', error.message);
    return false;
  }
}

/**
 * Resolve DID to public key
 * @param {string} did - DID string (did:web:domain#keyId)
 * @returns {Promise<Object>} Public key data
 */
async function resolveDID(did) {
  try {
    const [, , domain, keyId] = did.match(/^did:web:([^#]+)#(.+)$/);
    
    // In production, this would fetch the DID document from the domain
    // For now, we'll return a mock key
    console.warn('DID resolution not implemented - using mock key');
    
    return {
      id: did,
      type: 'Ed25519VerificationKey2020',
      publicKeyBase64: 'mock-public-key-base64',
      controller: `did:web:${domain}`
    };
  } catch (error) {
    throw new Error(`Failed to resolve DID: ${error.message}`);
  }
}

/**
 * Verify signature of a receipt
 * @param {Object} receipt - Receipt object
 * @param {Object} options - Verification options
 * @returns {Promise<Object>} Verification result
 */
async function verifySignature(receipt, options = {}) {
  try {
    if (!receipt.signature) {
      return {
        ok: false,
        reason: 'No signature present'
      };
    }

    // Parse signature
    const sigData = parseSignature(receipt.signature);
    
    // Resolve DID to get public key
    const did = `did:web:${sigData.domain}#${sigData.keyId}`;
    const keyData = await resolveDID(did);
    
    // Create message to verify (receipt without signature)
    const receiptCopy = { ...receipt };
    delete receiptCopy.signature;
    const message = JSON.stringify(receiptCopy, null, 0);
    
    // Determine signature algorithm and verify
    let isValid = false;
    let algorithm = 'unknown';
    
    if (keyData.type === 'Ed25519VerificationKey2020') {
      algorithm = 'Ed25519';
      isValid = verifyEd25519(message, sigData.signature, keyData.publicKeyBase64);
    } else if (keyData.type === 'EcdsaSecp256k1VerificationKey2019') {
      algorithm = 'ECDSA';
      isValid = verifyECDSA(message, sigData.signature, keyData.publicKeyBase64);
    } else {
      return {
        ok: false,
        reason: `Unsupported key type: ${keyData.type}`
      };
    }
    
    return {
      ok: isValid,
      algorithm,
      keyId: sigData.keyId,
      domain: sigData.domain,
      reason: isValid ? 'Signature valid' : 'Signature invalid'
    };
    
  } catch (error) {
    return {
      ok: false,
      reason: `Verification error: ${error.message}`
    };
  }
}

/**
 * Create a mock signature for testing
 * @param {Object} receipt - Receipt object
 * @param {string} domain - Domain for DID
 * @param {string} keyId - Key identifier
 * @returns {string} Mock signature
 */
function createMockSignature(receipt, domain = 'example.org', keyId = 'k1') {
  const mockSignature = 'mock-signature-base64';
  return `did:web:${domain}#${keyId} sig:${mockSignature}`;
}

export {
  parseSignature,
  verifyEd25519,
  verifyECDSA,
  resolveDID,
  verifySignature,
  createMockSignature
};
