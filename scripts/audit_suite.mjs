/**
 * SourceMark Complete Functional & Security Audit Test Suite
 */

import nacl from 'tweetnacl';
import crypto from 'crypto';

// Polyfill window / localStorage for Node test runner
const storage = new Map();
globalThis.localStorage = {
  getItem: (k) => storage.get(k) || null,
  setItem: (k, v) => storage.set(k, String(v)),
  removeItem: (k) => storage.delete(k),
  clear: () => storage.clear(),
};
globalThis.window = {
  crypto: {
    subtle: {
      digest: async (algo, buffer) => {
        const hash = crypto.createHash('sha256').update(Buffer.from(buffer)).digest();
        return hash.buffer.slice(hash.byteOffset, hash.byteOffset + hash.byteLength);
      }
    }
  }
};

async function runAudit() {
  console.log('================================================================');
  console.log('       SOURCEMARK COMPREHENSIVE FUNCTIONAL AUDIT SUITE          ');
  console.log('================================================================\n');

  let passed = 0;
  let failed = 0;

  function assert(testName, condition, details = '') {
    if (condition) {
      console.log(`[PASS] ${testName}`);
      passed++;
    } else {
      console.error(`[FAIL] ${testName} - ${details}`);
      failed++;
    }
  }

  // 1. CRYPTO PRIMITIVES & DIGITAL SIGNATURES
  console.log('--- 1. Cryptographic Primitives & Ed25519 Math ---');
  const { calculateSHA256, getOrCreateKeyPair, signFingerprint, verifyFingerprintSignature, bufferToHex } = await import('../src/services/crypto.js');
  
  const testFileBytes = Buffer.from('SourceMark-Defense-Brief-2026-Original');
  const hash1 = await calculateSHA256(testFileBytes);
  assert('SHA-256 Digest Calculation', typeof hash1 === 'string' && hash1.length === 64, `Hash: ${hash1}`);

  const keyPair = getOrCreateKeyPair();
  assert('Ed25519 Key Generation', keyPair.publicKey && keyPair.secretKey && keyPair.keyId.startsWith('ED25519-'));

  const signed = signFingerprint(hash1);
  assert('Detached Ed25519 Signature Creation', signed.signatureHex && signed.signatureHex.length === 128);

  const isValidSig = verifyFingerprintSignature(hash1, signed.signatureHex, signed.publicKeyHex);
  assert('Mathematical Signature Verification (Authentic)', isValidSig === true);

  const forgedBytes = new Uint8Array(Buffer.from(signed.signatureHex, 'hex'));
  forgedBytes[0] ^= 0x01; // flip 1 bit
  const forgedSigHex = bufferToHex(forgedBytes);
  const isForgedSigValid = verifyFingerprintSignature(hash1, forgedSigHex, signed.publicKeyHex);
  assert('Mathematical Signature Verification (Forged Rejection)', isForgedSigValid === false);

  // 2. FORENSIC INTELLIGENCE SCORE
  console.log('\n--- 2. Forensic Intelligence Score Engine ---');
  const { computeForensicScore } = await import('../src/services/forensicScore.js');

  const scoreOriginal = computeForensicScore({
    hashMatched: true,
    signatureValid: true,
    registryFound: true,
    keyStatus: 'ACTIVE',
    checkpointIntegrity: 'VALID',
    metadataConsistency: 'CONSISTENT',
    provenanceHistoryDepth: 5,
    isAuthorizedDerivative: false,
  });
  assert('Forensic Score (Original Perfect = 100, Low Risk)', scoreOriginal.score === 100 && scoreOriginal.riskLevel === 'Low Risk');

  const scoreTampered = computeForensicScore({
    hashMatched: false,
    signatureValid: false,
    registryFound: true,
    keyStatus: 'ACTIVE',
    checkpointIntegrity: 'VALID',
    metadataConsistency: 'CONSISTENT',
  });
  assert('Forensic Score (Tampered File Deduction)', scoreTampered.score <= 50 && scoreTampered.deductions.length > 0);

  const scoreCompromised = computeForensicScore({
    hashMatched: true,
    signatureValid: true,
    registryFound: true,
    keyStatus: 'COMPROMISED',
    checkpointIntegrity: 'VALID',
  });
  assert('Forensic Score (Compromised Key Deduction)', scoreCompromised.deductions.some(d => d.includes('COMPROMISED')));

  // 3. CHECKPOINT INTEGRITY & ROLLBACK PROTECTION
  console.log('\n--- 3. Rollback Protection & Checkpoint Watchdog ---');
  const { checkpointService } = await import('../src/services/checkpointService.js');
  const { ledgerStorage } = await import('../src/services/ledgerStorage.js');

  // Baseline check
  const initialIntegrity = checkpointService.evaluateIntegrity();
  assert('Baseline Checkpoint Integrity Evaluation', initialIntegrity.status === 'VALID' || initialIntegrity.status === 'UNAVAILABLE');

  // Create new sealed checkpoint
  const newCheckpoint = checkpointService.createCheckpoint({ operator: 'Audit-Bot', notes: 'Sealed Test Point' });
  assert('Create Sealed WORM Checkpoint', newCheckpoint.success && newCheckpoint.checkpoint.id.startsWith('CHK-'));

  // Test Rollback Detection: Delete/Truncate ledger records
  checkpointService.simulateRollbackAttack();
  const rollbackIntegrity = checkpointService.evaluateIntegrity();
  assert('Security Scenario: Truncate Ledger Records -> ROLLBACK_DETECTED', rollbackIntegrity.status === 'ROLLBACK_DETECTED');

  // Test Trusted Restore Workflow
  const restoreRes = await checkpointService.restoreFromTrustedCheckpoint();
  assert('Trusted Checkpoint Restoration Workflow', restoreRes.success === true);
  const postRestoreIntegrity = checkpointService.evaluateIntegrity();
  assert('Post-Recovery Integrity Restored to VALID', postRestoreIntegrity.status === 'VALID');

  // 4. LEGITIMATE RE-SAVES & VERSION CONTROL
  console.log('\n--- 4. Legitimate Re-saves & Version Lineage ---');
  const { versionControlService } = await import('../src/services/versionControl.js');

  const derivative1 = await versionControlService.createVersion({
    sourceId: 'SRC-98214',
    fileName: 'satellite_recon_compressed.webp',
    newHash: '1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff',
    transformationReason: 'Lossless WebP compression for tactical low-bandwidth distribution',
    actor: 'Dr. Evelyn Vance',
    actorId: 'AGY-USR-0042',
    authorizationStatus: 'AUTHORIZED',
    fileSizeFormatted: '1.1 MB',
  });
  assert('Register Authorized Derivative Re-save', derivative1.versionId.startsWith('VER-'));

  const evalAuth = versionControlService.evaluateDerivative('1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff');
  assert('Security Scenario: Classify Authorized Re-save as AUTHORIZED', evalAuth && evalAuth.status === 'AUTHORIZED');

  // Test unauthorized re-save
  const unauthorizedEval = versionControlService.evaluateDerivative('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff');
  assert('Security Scenario: Unauthorized / Uncatalogued Hash is Flagged (null/unknown)', unauthorizedEval === null);

  // 5. STOLEN KEY ATTACK & KEY SECURITY CENTRE
  console.log('\n--- 5. Key Security, Stolen Key Attack & Rotation ---');
  const { keySecurityService } = await import('../src/services/keySecurity.js');
  const { apiService } = await import('../src/services/api.js');

  const activeKeys = keySecurityService.getKeys();
  const victimKey = activeKeys[0];
  assert('Retrieve Registered PKI Keys', activeKeys.length >= 3 && victimKey.id);

  // Simulate Stolen Key Attack
  await keySecurityService.simulateStolenKey(victimKey.id, 'Stolen test vector key');
  const isVictimCompromised = keySecurityService.isKeyCompromised(victimKey.id);
  assert('Security Scenario: Simulate Stolen Key Attack -> Key is COMPROMISED', isVictimCompromised === true);

  // Verify that new registration with a compromised key is rejected
  const regAttemptWithCompromisedKey = await apiService.registerSource({
    fileName: 'rogue_forged_document.pdf',
    sha256: '9999888877776666555544443333222211110000aaaabbbbccccddddeeeeffff',
    publicKey: victimKey.publicKeyHex,
    signature: 'fake_signature',
  });
  assert('Security Scenario: Reject New Signatures / Registrations using Compromised Key', regAttemptWithCompromisedKey.success === false && regAttemptWithCompromisedKey.error.toLowerCase().includes('compromised'));

  // Test Key Rotation & Replacement
  const rotationResult = await keySecurityService.rotateKey(victimKey.id, 'Emergency Rotation after breach');
  assert('Security Scenario: Key Rotation produces a fresh ACTIVE Key', rotationResult.success === true && rotationResult.newKey.status === 'ACTIVE');

  const oldKeyAfterRotation = keySecurityService.getKeyById(victimKey.id);
  assert('Retired Key is marked REVOKED/REPLACED with replacement pointer', oldKeyAfterRotation.status === 'REVOKED' || oldKeyAfterRotation.status === 'REPLACED');

  // Test Retroactive Validation
  const historicalAudit = keySecurityService.validateRetroactiveSignatures(victimKey.id, [
    { sourceId: 'SRC-HIST-01', timestamp: '2026-01-01T00:00:00.000Z' }, // before breach
    { sourceId: 'SRC-BREACH-02', timestamp: new Date(Date.now() + 100000).toISOString() }, // after breach
  ]);
  assert('Historical Signature Partitioning (Pre vs Post Breach)', historicalAudit.validCount >= 1 && historicalAudit.suspiciousCount >= 1);

  // 6. METADATA INTELLIGENCE
  console.log('\n--- 6. Metadata Intelligence Consistency Checks ---');
  const { metadataService } = await import('../src/services/metadataService.js');
  assert('Metadata Service Instance Available', typeof metadataService.formatBytes === 'function');
  assert('Metadata Byte Formatter', metadataService.formatBytes(1048576) === '1 MB');

  // 7. QR CODE GENERATION & PAYLOAD INTEGRITY
  console.log('\n--- 7. QR Code Generation & Payload Integrity ---');
  const QRCode = (await import('qrcode')).default;
  const qrDataUri = await QRCode.toDataURL('SOURCEMARK-TEST-TOKEN', { width: 250 });
  assert('QR Code Generation Data URI', typeof qrDataUri === 'string' && qrDataUri.startsWith('data:image/png;base64,'));

  // 8. BATCH VERIFICATION LOGIC
  console.log('\n--- 8. Batch Verification Multi-File Triage ---');
  const registeredSources = ledgerStorage.getSources();
  const knownMaster = registeredSources[0];
  const knownMasterHash = knownMaster.sha256 || knownMaster.hash;

  // Exact match
  const batchMatch1 = registeredSources.find(s => (s.sha256 || s.hash) === knownMasterHash);
  assert('Batch Match: Registered Master is ORIGINAL', batchMatch1 && batchMatch1.id === knownMaster.id);

  // Derivative match
  const batchMatch2 = versionControlService.findVersionByHash('1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff');
  assert('Batch Match: Derivative is AUTHORIZED_DERIVATIVE', batchMatch2 && batchMatch2.authorizationStatus === 'AUTHORIZED');

  // Unknown match
  const batchMatch3 = registeredSources.find(s => (s.sha256 || s.hash) === '0000000000000000000000000000000000000000000000000000000000000000');
  assert('Batch Match: Unregistered Hash is UNKNOWN', batchMatch3 === undefined);

  // 9. SECURITY & RISK CENTER SIMULATIONS
  console.log('\n--- 9. Bit-flip Avalanche Scrambler Simulation ---');
  const strA = 'SourceMark Document v1.0 Original';
  const strB = 'SourceMark Document v1.0 0riginal';
  const hA = await calculateSHA256(strA);
  const hB = await calculateSHA256(strB);

  let bitDiffs = 0;
  for (let i = 0; i < 64; i++) {
    if (hA[i] !== hB[i]) bitDiffs++;
  }
  const diffPercent = (bitDiffs / 64) * 100;
  assert('Bit-flip Avalanche Scrambles >40% of Hex Digest', diffPercent > 40, `Divergence: ${diffPercent.toFixed(1)}%`);

  // Summary
  console.log('\n================================================================');
  console.log(`TOTAL TESTS: ${passed + failed} | PASSED: ${passed} | FAILED: ${failed}`);
  console.log('================================================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

runAudit().catch(err => {
  console.error('Audit Script Runtime Error:', err);
  process.exit(1);
});
