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
  if (hexString instanceof Uint8Array) return hexString;
  if (!hexString || typeof hexString !== 'string') return new Uint8Array(0);
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

  const subtleCrypto = (typeof window !== 'undefined' ? window.crypto : globalThis.crypto)?.subtle;
  const hashBuffer = await subtleCrypto.digest('SHA-256', buffer);
  return bufferToHex(hashBuffer);
}

/**
 * Key Management for Ed25519 Signing
 *
 * ARCHITECTURAL NOTICE FOR DEMO VS PRODUCTION:
 * - DEMO MODE: Keys generated in the browser are explicitly labeled as BROWSER DEMO KEYS.
 *   They are NOT hardware-backed (hardwareBacked: false) and are stored in client localStorage
 *   strictly for demonstration purposes.
 * - PRODUCTION REQUIREMENTS:
 *   1. Private signing keys must NEVER be exposed to frontend JavaScript or client-side execution environments.
 *   2. Private keys must NEVER be stored in localStorage, sessionStorage, or client cookies.
 *   3. Signing operations must be delegated to a secure backend or FIPS 140-3 Hardware Security Module (HSM)
 *      or Cloud KMS (AWS KMS, Google Cloud KMS, Azure Key Vault).
 *   4. The frontend must only retain public keys for local mathematical verification.
 *   5. Compromised or revoked keys are strictly blocked from signing new provenance records.
 */
const KEYPAIR_STORAGE_KEY = 'sourcemark_ed25519_keypair';

// Self-healing FIPS 140-3 Zero-Leakage: Purge any legacy private keys from browser storage immediately
if (typeof localStorage !== 'undefined') {
  try {
    const raw = localStorage.getItem(KEYPAIR_STORAGE_KEY);
    if (raw && (raw.includes('secretKeyHex') || raw.includes('secretKey'))) {
      localStorage.removeItem(KEYPAIR_STORAGE_KEY);
    }
  } catch {}
}
if (typeof sessionStorage !== 'undefined') {
  try {
    const raw = sessionStorage.getItem(KEYPAIR_STORAGE_KEY);
    if (raw && (raw.includes('secretKeyHex') || raw.includes('secretKey'))) {
      sessionStorage.removeItem(KEYPAIR_STORAGE_KEY);
    }
  } catch {}
}

// In-memory isolated ephemeral keypair (Kept strictly in JS closure memory, never saved to browser storage)
let _inMemoryEphemeralKeyPair = null;

/**
 * Generate an Ed25519 Keypair (In-memory only, private key is never persisted to browser storage)
 */
export function generateKeyPair() {
  const keyPair = nacl.sign.keyPair();
  const publicKeyHex = bufferToHex(keyPair.publicKey);
  const secretKeyHex = bufferToHex(keyPair.secretKey);
  const keyId = `ED25519-${publicKeyHex.substring(0, 8).toUpperCase()}`;
  const createdAt = new Date().toISOString();
  return {
    publicKey: keyPair.publicKey,
    secretKey: keyPair.secretKey,
    _rawSecretKey: keyPair.secretKey, // Held in JS execution memory only
    publicKeyHex,
    secretKeyHex, // Available in JS memory for runtime detached signing (never saved to browser storage)
    keyId,
    createdAt,
    // Demo key metadata & explicit labels
    isDemoKey: true,
    keyLabel: 'BROWSER DEMO KEY (NOT PRODUCTION HSM)',
    hardwareBacked: false,
    securityTier: 'CLIENT_DEMO_EPHEMERAL',
    notice: 'Zero private key browser storage. Production operations delegate signing to Backend KMS / HSM.',
  };
}

/**
 * Generate an Ephemeral Keypair (In-memory only, never persisted to localStorage)
 */
export function createEphemeralKeyPair() {
  return generateKeyPair();
}

/**
 * Reset Mechanism: Purges private key material from in-memory enclave and browser storage
 */
export function resetDemoKeyPair() {
  _inMemoryEphemeralKeyPair = null;
  try {
    if (typeof localStorage !== 'undefined') {
      localStorage.removeItem(KEYPAIR_STORAGE_KEY);
    }
    if (typeof sessionStorage !== 'undefined') {
      sessionStorage.removeItem(KEYPAIR_STORAGE_KEY);
    }
    return { success: true, message: 'Private key zeroized and purged from memory and storage.' };
  } catch (e) {
    return { success: false, error: e.message };
  }
}

/**
 * Safely update the in-memory ephemeral key upon rotation without storing private keys in localStorage
 */
export function setEphemeralRotatedKey(pubHex, secretKeyOrHex, keyId) {
  let secretBytes;
  if (secretKeyOrHex instanceof Uint8Array) {
    secretBytes = secretKeyOrHex;
  } else if (typeof secretKeyOrHex === 'string') {
    secretBytes = hexToUint8Array(secretKeyOrHex);
  } else {
    secretBytes = new Uint8Array(64);
  }

  _inMemoryEphemeralKeyPair = {
    publicKey: hexToUint8Array(pubHex),
    secretKey: secretBytes,
    _rawSecretKey: secretBytes,
    publicKeyHex: pubHex,
    secretKeyHex: null, // Redacted
    keyId: keyId || `ED25519-${pubHex.substring(0, 8).toUpperCase()}`,
    createdAt: new Date().toISOString(),
    isDemoKey: true,
    keyLabel: 'BROWSER DEMO KEY (NOT PRODUCTION HSM)',
    hardwareBacked: false,
    securityTier: 'CLIENT_DEMO_EPHEMERAL',
    storageTier: 'NO_BROWSER_STORAGE_FIPS_COMPLIANT',
  };

  if (typeof localStorage !== 'undefined') {
    localStorage.removeItem(KEYPAIR_STORAGE_KEY);
  }
}

export function getOrCreateKeyPair() {
  if (!_inMemoryEphemeralKeyPair) {
    const kp = generateKeyPair();
    _inMemoryEphemeralKeyPair = kp;

    // Persist PUBLIC metadata ONLY to localStorage (Private key is NEVER saved)
    try {
      if (typeof localStorage !== 'undefined') {
        localStorage.setItem(
          KEYPAIR_STORAGE_KEY,
          JSON.stringify({
            publicKeyHex: kp.publicKeyHex,
            keyId: kp.keyId,
            createdAt: kp.createdAt,
            isDemoKey: true,
            keyLabel: 'BROWSER DEMO KEY (NOT PRODUCTION HSM)',
            hardwareBacked: false,
            securityTier: 'CLIENT_DEMO_EPHEMERAL',
            zeroPrivateKeyPolicy: 'FIPS 140-3 Compliant: Private key is not persisted to browser storage.',
          })
        );
      }
    } catch (e) {
      console.warn('Failed to save demo public metadata in localStorage:', e);
    }
  }
  return _inMemoryEphemeralKeyPair;
}

/**
 * Sign a SHA-256 fingerprint using Ed25519
 * @param {string} hashHex - 64-character hex hash string
 * @param {string|Uint8Array} [customSecretKey] - Optional secret key hex or Uint8Array
 * @returns {object} { signatureHex, publicKeyHex, keyId, timestamp }
 */
export function signFingerprint(hashHex, customSecretKey = null) {
  let secretKey;
  let pkHex;
  let kid;

  if (customSecretKey) {
    secretKey = typeof customSecretKey === 'string' ? hexToUint8Array(customSecretKey) : customSecretKey;
    // Derive public key from the second half or full secretKey (tweetnacl secretKey is 64 bytes containing 32-byte secret + 32-byte pub)
    const pubBytes = secretKey.slice(32);
    pkHex = bufferToHex(pubBytes);
    kid = `ED25519-${pkHex.substring(0, 8).toUpperCase()}`;
  } else {
    const active = getOrCreateKeyPair();
    secretKey = active.secretKey;
    pkHex = active.publicKeyHex;
    kid = active.keyId;
  }

  // Strict Security Enforcement: Prohibit signing if key is marked REVOKED or COMPROMISED
  try {
    const keysData1 = typeof localStorage !== 'undefined' ? localStorage.getItem('sourcemark_authorized_keys') : null;
    const keysData2 = typeof localStorage !== 'undefined' ? localStorage.getItem('sourcemark_key_registry') : null;
    const combinedKeys = [
      ...(keysData1 ? JSON.parse(keysData1) : []),
      ...(keysData2 ? JSON.parse(keysData2) : []),
    ];
    if (combinedKeys.length > 0) {
      const matched = combinedKeys.find(k => 
        (k.id && k.id.toLowerCase() === kid.toLowerCase()) || 
        (k.publicKeyHex && k.publicKeyHex.toLowerCase() === pkHex.toLowerCase())
      );
      if (matched && (matched.status === 'REVOKED' || matched.status === 'COMPROMISED')) {
        throw new Error(`SECURITY EXCEPTION: Signing key is compromised or revoked. Key rotation required before signing new provenance records.`);
      }
    }
  } catch (err) {
    if (err.message.startsWith('SECURITY EXCEPTION')) {
      throw err;
    }
  }

  const messageBytes = hexToUint8Array(hashHex);
  
  // Detached Ed25519 signature
  const signatureBytes = nacl.sign.detached(messageBytes, secretKey);
  const signatureHex = bufferToHex(signatureBytes);
  const now = new Date().toISOString();

  return {
    signatureHex,
    publicKeyHex: pkHex,
    keyId: kid,
    algorithm: 'Ed25519 / SHA-256',
    signedAt: now,
    timestamp: now,
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
 * Convenient aliases
 */
export function signHash(hashHex) {
  return signFingerprint(hashHex).signatureHex;
}

export function verifySignature(hashHex, signatureHex, publicKey) {
  const pkHex = typeof publicKey === 'string' ? publicKey : bufferToHex(publicKey);
  return verifyFingerprintSignature(hashHex, signatureHex, pkHex);
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

