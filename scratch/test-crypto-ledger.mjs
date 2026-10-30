import nacl from 'tweetnacl';
import crypto from 'crypto';

// Hex utils
function bufferToHex(buffer) {
  const byteArray = new Uint8Array(buffer);
  return Array.from(byteArray)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function hexToUint8Array(hexString) {
  const cleanHex = hexString.replace(/^0x/, '');
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < cleanHex.length; i += 2) {
    bytes[i / 2] = parseInt(cleanHex.substr(i, 2), 16);
  }
  return bytes;
}

console.log('--- TEST 1: Ed25519 Key Generation ---');
const keyPair = nacl.sign.keyPair();
const publicKeyHex = bufferToHex(keyPair.publicKey);
const secretKeyHex = bufferToHex(keyPair.secretKey);
console.log('Public Key length (bytes):', keyPair.publicKey.length, '(hex chars):', publicKeyHex.length);
console.log('Secret Key length (bytes):', keyPair.secretKey.length, '(hex chars):', secretKeyHex.length);
const keyGenPass = keyPair.publicKey.length === 32 && keyPair.secretKey.length === 64;
console.log('KeyGen Valid:', keyGenPass);

console.log('\n--- TEST 2: Real SHA-256 Hashing ---');
const testPayload = 'Satellite Recon Orbital Stream 42';
const realNodeHash = crypto.createHash('sha256').update(testPayload).digest('hex');
console.log('Node crypto SHA-256:', realNodeHash);

console.log('\n--- TEST 3: Ed25519 Detached Signature Creation & Verification ---');
const messageBytes = hexToUint8Array(realNodeHash);
const signatureBytes = nacl.sign.detached(messageBytes, keyPair.secretKey);
const signatureHex = bufferToHex(signatureBytes);
console.log('Signature length (bytes):', signatureBytes.length, '(hex chars):', signatureHex.length);

const isSigValid = nacl.sign.detached.verify(messageBytes, signatureBytes, keyPair.publicKey);
console.log('Signature Valid on original hash:', isSigValid);

console.log('\n--- TEST 4: Verification Failure on Altered Hash / Signature / Key ---');
const alteredHash = realNodeHash.substring(0, 62) + 'ff';
const alteredMessageBytes = hexToUint8Array(alteredHash);
const isAlteredSigValid = nacl.sign.detached.verify(alteredMessageBytes, signatureBytes, keyPair.publicKey);
console.log('Signature Valid on altered hash (should be false):', isAlteredSigValid);

// Corrupted signature
const corruptedSig = signatureHex.substring(0, 126) + '00';
const isCorruptedSigValid = nacl.sign.detached.verify(messageBytes, hexToUint8Array(corruptedSig), keyPair.publicKey);
console.log('Signature Valid with corrupted signature (should be false):', isCorruptedSigValid);

// Wrong public key
const otherKeyPair = nacl.sign.keyPair();
const isWrongKeyValid = nacl.sign.detached.verify(messageBytes, signatureBytes, otherKeyPair.publicKey);
console.log('Signature Valid with wrong public key (should be false):', isWrongKeyValid);

console.log('\n--- TEST 5: Hash Chaining & Tamper Detection ---');
// Let's test calculateLedgerBlockHash logic
function calculateLedgerBlockHashMock(eventData, previousHash) {
  const payloadString = JSON.stringify({
    eventId: eventData.id,
    type: eventData.type,
    prevHash: previousHash || '0000000000000000000000000000000000000000000000000000000000000000',
    timestamp: eventData.timestamp,
    payload: eventData.payload,
  });
  return crypto.createHash('sha256').update(payloadString).digest('hex');
}

const block1 = {
  id: 'BLK-0001',
  type: 'GENESIS',
  timestamp: '2026-10-20T00:00:00.000Z',
  prevHash: '0000000000000000000000000000000000000000000000000000000000000000',
  payload: { operator: 'SourceMark Master Node v2.4' }
};
block1.currentHash = calculateLedgerBlockHashMock(block1, block1.prevHash);

const block2 = {
  id: 'BLK-0002',
  type: 'REGISTER',
  timestamp: '2026-10-24T09:15:22.000Z',
  prevHash: block1.currentHash,
  payload: { sourceId: 'SRC-98214', fingerprint: realNodeHash }
};
block2.currentHash = calculateLedgerBlockHashMock(block2, block2.prevHash);

const block3 = {
  id: 'BLK-0003',
  type: 'VERIFY_ORIGINAL',
  timestamp: '2026-10-25T14:10:05.000Z',
  prevHash: block2.currentHash,
  payload: { sourceId: 'SRC-98214', verdict: 'ORIGINAL' }
};
block3.currentHash = calculateLedgerBlockHashMock(block3, block3.prevHash);

const chain = [block1, block2, block3];

function validateChain(blocks) {
  for (let i = 0; i < blocks.length; i++) {
    const curr = blocks[i];
    const prev = i > 0 ? blocks[i - 1] : null;
    if (prev && curr.prevHash !== prev.currentHash) {
      return { isValid: false, brokenAt: curr.id, reason: 'Broken prevHash link' };
    }
    const computed = calculateLedgerBlockHashMock(curr, curr.prevHash);
    if (computed !== curr.currentHash) {
      return { isValid: false, brokenAt: curr.id, reason: 'Recomputed hash mismatch (payload tampered)' };
    }
  }
  return { isValid: true };
}

console.log('Initial Pristine Chain Valid:', validateChain(chain));

// Tamper block 2 payload
chain[1].payload.sourceId = 'SRC-HACKED-99999';
console.log('After Tampering Block 2 Payload:', validateChain(chain));

