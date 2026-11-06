/**
 * SourceMark – PKI Trust Registry & SRC-35253 Verification Investigation Suite
 *
 * Specifically tests:
 * 1. Reproduction & Fix of SRC-35253 (Registered source with active demo key)
 * 2. Case A: Valid signature with trusted key (ORIGINAL / VERIFIED)
 * 3. Case B: Valid signature with unknown/uncatalogued key (REQUIRES_INVESTIGATION)
 * 4. Case C: Invalid signature (SIGNATURE_INVALID)
 * 5. Case D: Revoked key (COMPROMISED_KEY / Signing blocked)
 */

import { apiService } from '../src/services/api.js';
import { keySecurityService } from '../src/services/keySecurity.js';
import { ledgerStorage } from '../src/services/ledgerStorage.js';
import { 
  generateKeyPair, 
  signFingerprint, 
  verifyFingerprintSignature,
  getOrCreateKeyPair,
  bufferToHex,
  hexToUint8Array
} from '../src/services/crypto.js';
import nacl from 'tweetnacl';

// Setup mock browser localStorage for Node.js
const mockStore = {};
global.localStorage = {
  getItem: (key) => mockStore[key] || null,
  setItem: (key, val) => { mockStore[key] = String(val); },
  removeItem: (key) => { delete mockStore[key]; },
  clear: () => { Object.keys(mockStore).forEach(k => delete mockStore[k]); }
};

async function runInvestigationTests() {
  console.log('================================================================');
  console.log('  SOURCEMARK PKI TRUST REGISTRY & SRC-35253 AUDIT SUITE         ');
  console.log('================================================================\n');

  ledgerStorage.resetLedger();
  keySecurityService.resetToDefaults();

  const testResults = [];
  const logTest = (num, name, expected, actual, pass, detail) => {
    testResults.push({ num, name, expected, actual, pass });
    const mark = pass ? '✓ PASS' : '✗ FAIL';
    console.log(`[Test ${num}] ${name}`);
    console.log(`   Expected: ${expected}`);
    console.log(`   Actual:   ${actual}`);
    console.log(`   Detail:   ${detail}`);
    console.log(`   Result:   ${mark}\n`);
  };

  // --------------------------------------------------------------------------
  // TEST 1: Source ID SRC-35253 Reproduction & Verification
  // --------------------------------------------------------------------------
  {
    // 1. Simulate the exact workflow of Register.jsx for SRC-35253
    const fileHash = '3525335253352533525335253352533525335253352533525335253352533525';
    const activeDemoKey = getOrCreateKeyPair(); // Browser active demo keypair
    const sigInfo = signFingerprint(fileHash); // Uses activeDemoKey

    // 2. Independently verify Ed25519 signature using registered public key and original file hash
    const isMathValid = verifyFingerprintSignature(fileHash, sigInfo.signatureHex, sigInfo.publicKeyHex);

    // 3. Register source via apiService.registerSource
    const regPayload = {
      id: 'SRC-35253',
      fileName: 'satellite_recon_35253.jpg',
      fileType: 'image/jpeg',
      fileSize: 1048576,
      fileSizeFormatted: '1 MB',
      sha256: fileHash,
      signature: sigInfo.signatureHex,
      publicKey: sigInfo.publicKeyHex,
      keyId: sigInfo.keyId,
      creator: 'Dr. Evelyn Vance (Chief Geoint Analyst)',
      creatorId: 'AGY-USR-0042',
      signedAt: sigInfo.signedAt,
      signatureTimestamp: sigInfo.signedAt,
    };

    const regResponse = await apiService.registerSource(regPayload);

    // 4. Verify the source via apiService.verifySource
    const verifyResponse = await apiService.verifySource(fileHash, 'SRC-35253');

    // Expected: Signature is mathematically valid AND key is now catalogued as ACTIVE -> verdict: ORIGINAL
    const pass1 = isMathValid === true && 
                  regResponse.success === true &&
                  verifyResponse.signatureValid === true &&
                  verifyResponse.keyStatus === 'ACTIVE' &&
                  verifyResponse.verdict === 'ORIGINAL';

    logTest(
      1,
      'Source ID SRC-35253 Verification (Registered with Active Demo Key)',
      'isMathValid: true, keyStatus: ACTIVE, verdict: ORIGINAL',
      `isMathValid: ${isMathValid}, keyStatus: ${verifyResponse.keyStatus}, verdict: ${verifyResponse.verdict}`,
      pass1,
      `Key ${sigInfo.keyId} successfully catalogued in Public Key Trust Registry upon registration. Mathematical signature & key trust confirmed.`
    );
  }

  // --------------------------------------------------------------------------
  // TEST 2: Valid signature with trusted key (Pre-configured catalogued authority)
  // --------------------------------------------------------------------------
  {
    // Use Dr. Evelyn Vance's pre-catalogued key ED25519-2A71A707
    const trustedKeyId = 'ED25519-2A71A707';
    const trustedKey = keySecurityService.getKeyById(trustedKeyId);
    
    // Create an authentic test keypair and catalog it as trusted
    const trustedKp = generateKeyPair();
    const cataloguedKey = keySecurityService.registerKey({
      id: 'ED25519-TRUSTED-AUDIT',
      publicKeyHex: trustedKp.publicKeyHex,
      owner: 'SecOps Cryptographic Lead',
      role: 'Master Key Authority',
      status: 'ACTIVE',
    });

    const fileHash2 = '2222222222222222222222222222222222222222222222222222222222222222';
    const sig2 = signFingerprint(fileHash2, trustedKp.secretKeyHex).signatureHex;

    ledgerStorage.addSource({
      id: 'SRC-TRUSTED-KEY-02',
      fileName: 'trusted_authority_document.pdf',
      sha256: fileHash2,
      signature: sig2,
      publicKey: trustedKp.publicKeyHex,
      keyId: cataloguedKey.id,
      creator: 'SecOps Cryptographic Lead',
      status: 'ACTIVE_REGISTERED',
    });

    const verifyRes2 = await apiService.verifySource(fileHash2, 'SRC-TRUSTED-KEY-02');
    const pass2 = verifyRes2.signatureValid === true && 
                  verifyRes2.keyStatus === 'ACTIVE' && 
                  verifyRes2.verdict === 'ORIGINAL';

    logTest(
      2,
      'Valid Signature with Trusted Key',
      'signatureValid: true, keyStatus: ACTIVE, verdict: ORIGINAL',
      `signatureValid: ${verifyRes2.signatureValid}, keyStatus: ${verifyRes2.keyStatus}, verdict: ${verifyRes2.verdict}`,
      pass2,
      'Cryptographically authentic signature with active catalogued key returns ORIGINAL.'
    );
  }

  // --------------------------------------------------------------------------
  // TEST 3: Valid signature with unknown/uncatalogued key
  // --------------------------------------------------------------------------
  {
    // Generate an external rogue/uncatalogued keypair that is NEVER registered in key registry
    const unknownKp = nacl.sign.keyPair();
    const unknownPubHex = bufferToHex(unknownKp.publicKey);
    const unknownSecHex = bufferToHex(unknownKp.secretKey);

    const fileHash3 = '3333333333333333333333333333333333333333333333333333333333333333';
    // Generate a valid mathematical Ed25519 detached signature with the unknown key
    const msgBytes = hexToUint8Array(fileHash3);
    const sigBytes = nacl.sign.detached(msgBytes, unknownKp.secretKey);
    const sig3 = bufferToHex(sigBytes);

    // Confirm that the signature itself is mathematically authentic under Curve25519
    const isMathValid3 = nacl.sign.detached.verify(msgBytes, sigBytes, unknownKp.publicKey);

    // Add source with this unknown key directly to storage (simulating external uncatalogued submission)
    ledgerStorage.addSource({
      id: 'SRC-UNKNOWN-KEY-03',
      fileName: 'uncatalogued_origin_file.pdf',
      sha256: fileHash3,
      signature: sig3,
      publicKey: unknownPubHex,
      keyId: `ED25519-${unknownPubHex.substring(0, 8).toUpperCase()}`,
      creator: 'Unregistered Foreign Signer',
      status: 'ACTIVE_REGISTERED',
    });

    const verifyRes3 = await apiService.verifySource(fileHash3, 'SRC-UNKNOWN-KEY-03');
    
    // Mathematical signature is valid, BUT key trust fails -> verdict must be REQUIRES_INVESTIGATION
    const pass3 = isMathValid3 === true &&
                  verifyRes3.signatureValid === true &&
                  verifyRes3.keyStatus === 'MISSING_OR_UNAVAILABLE' &&
                  verifyRes3.verdict === 'REQUIRES_INVESTIGATION' &&
                  verifyRes3.details.includes('uncatalogued in public key trust registry');

    logTest(
      3,
      'Valid Signature with Unknown/Uncatalogued Key',
      'signatureValid: true, keyStatus: MISSING_OR_UNAVAILABLE, verdict: REQUIRES_INVESTIGATION',
      `signatureValid: ${verifyRes3.signatureValid}, keyStatus: ${verifyRes3.keyStatus}, verdict: ${verifyRes3.verdict}`,
      pass3,
      'System correctly distinguishes cryptographic validity from key trust: signature math passes, but uncatalogued key is quarantined.'
    );
  }

  // --------------------------------------------------------------------------
  // TEST 4: Invalid signature (Altered hash or forged signature)
  // --------------------------------------------------------------------------
  {
    // Use active demo key with altered signature bytes
    const activeDemoKey = getOrCreateKeyPair();
    const fileHash4 = '4444444444444444444444444444444444444444444444444444444444444444';
    // Forged signature
    const forgedSig = '00000000000000000000000000000000000000000000000000000000000000001111111111111111111111111111111111111111111111111111111111111111';

    ledgerStorage.addSource({
      id: 'SRC-FORGED-SIG-04',
      fileName: 'tampered_signature_payload.pdf',
      sha256: fileHash4,
      signature: forgedSig,
      publicKey: activeDemoKey.publicKeyHex,
      keyId: activeDemoKey.keyId,
      creator: 'Adversary',
      status: 'ACTIVE_REGISTERED',
    });

    const verifyRes4 = await apiService.verifySource(fileHash4, 'SRC-FORGED-SIG-04');
    const pass4 = verifyRes4.signatureValid === false &&
                  verifyRes4.verdict === 'SIGNATURE_INVALID';

    logTest(
      4,
      'Invalid Signature (Mathematical signature failure)',
      'signatureValid: false, verdict: SIGNATURE_INVALID',
      `signatureValid: ${verifyRes4.signatureValid}, verdict: ${verifyRes4.verdict}`,
      pass4,
      'Signature verification mathematically rejected forged signature bitstream.'
    );
  }

  // --------------------------------------------------------------------------
  // TEST 5: Revoked key (Attempt to verify post-revocation signature)
  // --------------------------------------------------------------------------
  {
    const revokedKp = generateKeyPair();
    const revokedKeyId = 'KEY-REVOKED-AUDIT-05';
    const nowIso = new Date().toISOString();

    keySecurityService.saveKeys([
      ...keySecurityService.getKeys(),
      {
        id: revokedKeyId,
        publicKeyHex: revokedKp.publicKeyHex,
        owner: 'Terminated Officer',
        role: 'Ex-Employee Authority',
        status: 'REVOKED',
        createdAt: new Date(Date.now() - 86400000).toISOString(),
        compromisedAt: nowIso,
        revokedAt: nowIso,
        replacementKeyId: null,
      }
    ]);

    // Sign detached raw bytes
    const fileHash5 = '5555555555555555555555555555555555555555555555555555555555555555';
    const sigBytes5 = nacl.sign.detached(hexToUint8Array(fileHash5), revokedKp.secretKey);
    const sig5 = bufferToHex(sigBytes5);

    ledgerStorage.addSource({
      id: 'SRC-REVOKED-KEY-05',
      fileName: 'revoked_signer_file.pdf',
      sha256: fileHash5,
      signature: sig5,
      publicKey: revokedKp.publicKeyHex,
      keyId: revokedKeyId,
      creator: 'Terminated Officer',
      signedAt: nowIso,
      status: 'ACTIVE_REGISTERED',
    });

    const verifyRes5 = await apiService.verifySource(fileHash5, 'SRC-REVOKED-KEY-05');
    const pass5 = verifyRes5.verdict === 'COMPROMISED_KEY' &&
                  (verifyRes5.keyStatus === 'REVOKED' || verifyRes5.keyStatus === 'POST_COMPROMISE_BREACH');

    logTest(
      5,
      'Revoked Key Verification',
      'keyStatus: REVOKED/POST_COMPROMISE_BREACH, verdict: COMPROMISED_KEY',
      `keyStatus: ${verifyRes5.keyStatus}, verdict: ${verifyRes5.verdict}`,
      pass5,
      'Signatures created using revoked keys are immediately flagged as COMPROMISED_KEY.'
    );
  }

  console.log('----------------------------------------------------------------');
  const allPass = testResults.every(t => t.pass);
  console.log(`TOTAL PKI TESTS: ${testResults.length}`);
  console.log(`PASSED: ${testResults.filter(t => t.pass).length}`);
  console.log(`FAILED: ${testResults.filter(t => !t.pass).length}`);
  console.log(`OVERALL PKI AUDIT STATUS: ${allPass ? 'ALL TESTS PASSED (5/5)' : 'FAILURES DETECTED'}`);
  console.log('================================================================');

  if (!allPass) process.exit(1);
}

runInvestigationTests().catch(err => {
  console.error(err);
  process.exit(1);
});

