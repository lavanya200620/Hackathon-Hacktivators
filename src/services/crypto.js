import nacl from 'tweetnacl';
import naclUtil from 'tweetnacl-util';

/**
 * Convert ArrayBuffer or Uint8Array to Hex String
 */
export function bufferToHex(buffer) {
  const byteArray = new Uint8Array(buffer);
  return Array.from(byteArray)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Convert Hex String to Uint8Array
 */
export function hexToUint8Array(hexString) {
  const cleanHex = hexString.replace(/^0x/, '');
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < cleanHex.length; i += 2) {
    bytes[i / 2] = parseInt(cleanHex.substr(i, 2), 16);
  }
  return bytes;
}

/**
 * Calculate SHA-256 Hash using browser Web Crypto API
 * Works with File, Blob, ArrayBuffer, Uint8Array or String
 */
export async function calculateSHA256(input) {
  let buffer;

  if (input instanceof File || input instanceof Blob) {
    buffer = await input.arrayBuffer();
  } else if (typeof input === 'string') {
    const encoder = new TextEncoder();
    buffer = encoder.encode(input).buffer;
  } else if (input instanceof Uint8Array) {
    buffer = input.buffer;
  } else if (input instanceof ArrayBuffer) {
    buffer = input;
  } else {
    throw new Error('Unsupported input type for SHA-256 hash');
  }

  const hashBuffer = await window.crypto.subtle.digest('SHA-256', buffer);
  return bufferToHex(hashBuffer);
}

/**
 * Key Management for Ed25519 Signing
 * Generates an Ed25519 keypair and persists the user's active keypair in localStorage
 */
const KEYPAIR_STORAGE_KEY = 'sourcemark_ed25519_keypair';

export function getOrCreateKeyPair() {
  try {
    const stored = localStorage.getItem(KEYPAIR_STORAGE_KEY);
    if (stored) {
      const parsed = JSON.parse(stored);
      return {
        publicKey: hexToUint8Array(parsed.publicKeyHex),
        secretKey: hexToUint8Array(parsed.secretKeyHex),
        publicKeyHex: parsed.publicKeyHex,
        keyId: parsed.keyId,
        createdAt: parsed.createdAt,
      };
    }
  } catch (e) {
    console.warn('Failed to parse stored keypair, generating fresh pair:', e);
  }

  // Generate new cryptographic keypair using Ed25519
  const keyPair = nacl.sign.keyPair();
  const publicKeyHex = bufferToHex(keyPair.publicKey);
  const secretKeyHex = bufferToHex(keyPair.secretKey);
  const keyId = `ED25519-${publicKeyHex.substring(0, 8).toUpperCase()}`;
  const createdAt = new Date().toISOString();

  const data = {
    publicKeyHex,
    secretKeyHex,
    keyId,
    createdAt,
  };

  try {
    localStorage.setItem(KEYPAIR_STORAGE_KEY, JSON.stringify(data));
  } catch (e) {
    console.error('Failed to save keypair in localStorage:', e);
  }

  return {
    publicKey: keyPair.publicKey,
    secretKey: keyPair.secretKey,
    publicKeyHex,
    keyId,
    createdAt,
  };
}

/**
 * Sign a SHA-256 fingerprint using Ed25519
 * @param {string} hashHex - 64-character hex hash string
 * @returns {object} { signatureHex, publicKeyHex, keyId, timestamp }
 */
export function signFingerprint(hashHex) {
  const { secretKey, publicKeyHex, keyId } = getOrCreateKeyPair();
  const messageBytes = hexToUint8Array(hashHex);
  
  // Detached Ed25519 signature
  const signatureBytes = nacl.sign.detached(messageBytes, secretKey);
  const signatureHex = bufferToHex(signatureBytes);

  return {
    signatureHex,
    publicKeyHex,
    keyId,
    algorithm: 'Ed25519 / SHA-256',
    timestamp: new Date().toISOString(),
  };
}

/**
 * Cryptographically verify an Ed25519 signature against a SHA-256 fingerprint
 * @param {string} hashHex - The SHA-256 fingerprint hex
 * @param {string} signatureHex - The Ed25519 detached signature hex
 * @param {string} publicKeyHex - The signer's Ed25519 public key hex
 * @returns {boolean} true if signature is mathematically valid, false otherwise
 */
export function verifyFingerprintSignature(hashHex, signatureHex, publicKeyHex) {
  try {
    const messageBytes = hexToUint8Array(hashHex);
    const signatureBytes = hexToUint8Array(signatureHex);
    const publicKeyBytes = hexToUint8Array(publicKeyHex);

    if (signatureBytes.length !== 64 || publicKeyBytes.length !== 32) {
      return false;
    }

    return nacl.sign.detached.verify(messageBytes, signatureBytes, publicKeyBytes);
  } catch (err) {
    console.error('Signature verification error:', err);
    return false;
  }
}

/**
 * Compute block/event hash for tamper-evident ledger (Hash Chaining)
 * Hash = SHA-256(eventId + eventType + prevHash + timestamp + payloadHash)
 */
export async function calculateLedgerBlockHash(eventData, previousHash) {
  const payloadString = JSON.stringify({
    eventId: eventData.id,
    type: eventData.type,
    prevHash: previousHash || '0000000000000000000000000000000000000000000000000000000000000000',
    timestamp: eventData.timestamp,
    payload: eventData.payload,
  });

  return await calculateSHA256(payloadString);
}

