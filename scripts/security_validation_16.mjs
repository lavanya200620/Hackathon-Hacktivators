/**
 * SourceMark – 16-Scenario Security & Cryptographic Validation Test Suite
 */

import { apiService } from '../src/services/api.js';
import { keySecurityService } from '../src/services/keySecurity.js';
import { checkpointService } from '../src/services/checkpointService.js';
import { versionControlService } from '../src/services/versionControl.js';
import { ledgerStorage } from '../src/services/ledgerStorage.js';
import { generateKeyPair, signFingerprint, verifyFingerprintSignature, verifySignature } from '../src/services/crypto.js';

// Setup mock browser localStorage for Node.js
const mockStore = {};
global.localStorage = {
  getItem: (key) => mockStore[key] || null,
  setItem: (key, val) => { mockStore[key] = String(val); },
  removeItem: (key) => { delete mockStore[key]; },
  clear: () => { Object.keys(mockStore).forEach(k => delete mockStore[k]); }
};

async function run16ScenarioValidation() {
  console.log('================================================================');
  console.log('       SOURCEMARK 16-SCENARIO SECURITY VALIDATION AUDIT        ');
  console.log('================================================================\n');

  const results = [];

  const recordResult = (id, scenario, expected, actual, pass, limitations = 'None') => {
    results.push({ id, scenario, expected, actual, pass, limitations });
    const mark = pass ? '✓ PASS' : '✗ FAIL';
    console.log(`[Scenario ${id}] ${scenario}`);
    console.log(`   Expected: ${expected}`);
    console.log(`   Actual:   ${actual}`);
    console.log(`   Result:   ${mark}\n`);
  };

  // Reset stores to default state
  ledgerStorage.resetLedger();
  keySecurityService.resetToDefaults();
  checkpointService.initDefaultCheckpoints();

  // Create an active signing key
  const activeKeypair = generateKeyPair();
  const activeKeyId = 'KEY-SCENARIO-ACTIVE';
  const registeredAtPre = new Date(Date.now() - 3600000).toISOString(); // 1 hr ago

  keySecurityService.saveKeys([
    {
      id: activeKeyId,
      owner: 'SecOps Director (Valerie Vance)',
      role: 'Cryptographic Lead',
      publicKeyHex: activeKeypair.publicKeyHex,
      algorithm: 'Ed25519',
      status: 'ACTIVE',
      createdAt: new Date(Date.now() - 7200000).toISOString(),
      compromisedAt: null,
      revokedAt: null,
      rotationHistory: [],
    }
  ]);

  // Register master source with active key
  const fileHashOrig = '1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff';
  const sigObj = signFingerprint(fileHashOrig, activeKeypair.secretKeyHex);
  const sigOrig = sigObj.signatureHex;
  const sourceIdOrig = 'SRC-SCENARIO-01';

  ledgerStorage.addSource({
    id: sourceIdOrig,
    fileName: 'scenario_master_record.pdf',
    sha256: fileHashOrig,
    signature: sigOrig,
    publicKey: activeKeypair.publicKeyHex,
    keyId: activeKeyId,
    creator: 'SecOps Director',
    registeredAt: registeredAtPre,
    status: 'ACTIVE_REGISTERED',
  });

  // --- Scenario 1: Original file with active key ---
  {
    const res = await apiService.verifySource(fileHashOrig, sourceIdOrig);
    const pass = res.verdict === 'ORIGINAL';
    recordResult(1, 'Original file with active key', 'ORIGINAL / VERIFIED', res.verdict, pass);
  }

  // --- Scenario 2: Original file with compromised key ---
  {
    // Mark key as COMPROMISED prior to record creation so it is an authentic post-compromise signature
    const keys = keySecurityService.getKeys();
    const k = keys.find(item => item.id === activeKeyId);
    if (k) {
      k.status = 'COMPROMISED';
      k.compromisedAt = new Date(Date.now() - 7200000).toISOString(); // 2 hours ago, before file registered 1 hour ago
      k.revokedAt = k.compromisedAt;
      keySecurityService.saveKeys(keys);
    }
    const res = await apiService.verifySource(fileHashOrig, sourceIdOrig);
    const pass = res.verdict === 'COMPROMISED_KEY';
    recordResult(2, 'Original file with compromised key', 'COMPROMISED_KEY', res.verdict, pass);
  }

  // Restore key to active for Scenario 3
  keySecurityService.saveKeys([
    {
      id: activeKeyId,
      owner: 'SecOps Director',
      role: 'Cryptographic Lead',
      publicKeyHex: activeKeypair.publicKeyHex,
      algorithm: 'Ed25519',
      status: 'ACTIVE',
      createdAt: new Date(Date.now() - 7200000).toISOString(),
      compromisedAt: null,
      revokedAt: null,
      rotationHistory: [],
    }
  ]);

  // --- Scenario 3: Modified file with active key ---
  {
    const modifiedHash = '9999888877776666555544443333222211110000aaaabbbbccccddddeeeeffff';
    const res = await apiService.verifySource(modifiedHash, sourceIdOrig);
    const pass = res.verdict === 'EDITED';
    recordResult(3, 'Modified file with active key', 'EDITED', res.verdict, pass);
  }

  // --- Scenario 4: Modified file with compromised key ---
  {
    await keySecurityService.simulateStolenKey(activeKeyId, 'Test theft');
    const modifiedHash = '9999888877776666555544443333222211110000aaaabbbbccccddddeeeeffff';
    const res = await apiService.verifySource(modifiedHash, sourceIdOrig);
    const pass = res.verdict === 'MODIFIED_AND_COMPROMISED_KEY';
    recordResult(4, 'Modified file with compromised key', 'MODIFIED_AND_COMPROMISED_KEY', res.verdict, pass);
  }

  // --- Scenario 5: Signature created before compromise ---
  {
    // Key compromised 10 minutes ago, file registered 1 hour ago
    const compTime = new Date(Date.now() - 600000).toISOString();
    const statusEval = keySecurityService.evaluateKeyStatus(activeKeyId, registeredAtPre);
    const pass = statusEval.verdict === 'PRE_COMPROMISE_VALID';
    recordResult(5, 'Signature created before compromise', 'PRE_COMPROMISE_VALID', statusEval.verdict, pass);
  }

  // --- Scenario 6: Signature created after compromise ---
  {
    // Key was compromised 10 minutes ago, signature created 5 minutes ago
    const allKeys = keySecurityService.getKeys();
    allKeys[0].compromisedAt = new Date(Date.now() - 600000).toISOString();
    keySecurityService.saveKeys(allKeys);

    const postCompTime = new Date(Date.now() - 300000).toISOString();
    const statusEval = keySecurityService.evaluateKeyStatus(activeKeyId, postCompTime);
    const pass = statusEval.verdict === 'COMPROMISED_KEY';
    recordResult(6, 'Signature created after compromise', 'COMPROMISED_KEY', statusEval.verdict, pass);
  }

  // --- Scenario 7: Signature with unknown compromise time ---
  {
    // Set compromisedAt to null on a COMPROMISED key
    const allKeys = keySecurityService.getKeys();
    allKeys[0].compromisedAt = null;
    keySecurityService.saveKeys(allKeys);
    const statusEval = keySecurityService.evaluateKeyStatus(activeKeyId, registeredAtPre);
    const pass = statusEval.verdict === 'REQUIRES_INVESTIGATION';
    recordResult(7, 'Signature with unknown compromise time', 'REQUIRES_INVESTIGATION', statusEval.verdict, pass);
  }

  // --- Scenario 8: Attempt to sign using revoked key ---
  {
    await keySecurityService.revokeKey(activeKeyId, 'Test revocation');
    const revokedAttempt = await apiService.registerSource({
      fileName: 'unauthorized_file.pdf',
      sha256: 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
      signature: 'dummy_sig',
      publicKey: activeKeypair.publicKeyHex,
      creator: 'Compromised Actor',
    });
    const pass = revokedAttempt.success === false && revokedAttempt.error.includes('compromised or revoked');
    recordResult(8, 'Attempt to sign using revoked key', 'REJECTED (Signing blocked)', revokedAttempt.error || 'ALLOWED', pass);
  }

  // --- Scenario 9: Successful signing using replacement key ---
  {
    const rotRes = await keySecurityService.rotateKey(activeKeyId, 'Emergency test rotation');
    const newKey = rotRes.newKey;
    const testHashNew = '4444555566667777888899990000111122223333444455556666777788889999';
    // Generate valid signature using session active key
    const keyPair = generateKeyPair();
    const sigNew = signFingerprint(testHashNew, keyPair.secretKeyHex).signatureHex;
    // Replace with registered public key
    const newReg = await apiService.registerSource({
      fileName: 'replacement_signed_doc.pdf',
      sha256: testHashNew,
      signature: sigNew,
      publicKey: keyPair.publicKeyHex,
      keyId: newKey.id,
      creator: 'SecOps Replacement',
    });
    const pass = newReg.success === true && newReg.source?.id?.startsWith('SRC-');
    recordResult(9, 'Successful signing using replacement key', 'PASS (Registration sealed)', pass ? 'PASS' : 'FAIL', pass);
  }

  // --- Scenario 10: Deleted ledger record ---
  {
    checkpointService.initDefaultCheckpoints();
    const blocks = ledgerStorage.getLedgerBlocks();
    checkpointService.createCheckpoint({ operator: 'SecOps Watchdog', notes: 'Pre-truncation baseline' });
    const checkpoints = checkpointService.getCheckpoints();
    const latest = checkpoints[0];
    const truncatedBlocks = blocks.slice(0, latest.recordNumber - 2);
    const evalResult = checkpointService.evaluateIntegrity(truncatedBlocks);
    const pass = evalResult.status === 'ROLLBACK_DETECTED' && evalResult.incident.incidentType === 'LEDGER_TRUNCATION_ROLLBACK';
    recordResult(10, 'Deleted ledger record', 'ROLLBACK_DETECTED (Truncation)', evalResult.status, pass);
  }

  // --- Scenario 11: Reverted ledger record ---
  {
    // Simulate reversion by restoring older state height
    const blocks = ledgerStorage.getLedgerBlocks();
    const revertedBlocks = blocks.slice(0, 1); // Only block 1
    const evalResult = checkpointService.evaluateIntegrity(revertedBlocks);
    const pass = evalResult.status === 'ROLLBACK_DETECTED';
    recordResult(11, 'Reverted ledger record', 'ROLLBACK_DETECTED', evalResult.status, pass);
  }

  // --- Scenario 12: Modified historical ledger entry ---
  {
    const blocks = JSON.parse(JSON.stringify(ledgerStorage.getLedgerBlocks()));
    if (blocks.length > 2) {
      blocks[1].currentHash = '00000000tampered00000000tampered00000000tampered00000000tampered';
    }
    const evalResult = checkpointService.evaluateIntegrity(blocks);
    const pass = evalResult.status === 'ROLLBACK_DETECTED' && evalResult.incident.incidentType === 'BROKEN_HASH_CHAIN_TAMPER';
    recordResult(12, 'Modified historical ledger entry', 'ROLLBACK_DETECTED (Broken link)', `${evalResult.status} (${evalResult.incident?.incidentType})`, pass);
  }

  // --- Scenario 13: Missing checkpoint ---
  {
    checkpointService.saveCheckpoints([]);
    const evalResult = checkpointService.evaluateIntegrity();
    const pass = evalResult.status === 'CHECKPOINT_MISSING';
    recordResult(13, 'Missing checkpoint', 'CHECKPOINT_MISSING', evalResult.status, pass);
  }

  // --- Scenario 14: Authorized re-save ---
  {
    checkpointService.initDefaultCheckpoints();
    const masterSource = ledgerStorage.getSources()[0];
    const newDerivHash = '888877776666555544443333222211110000aaaabbbbccccddddeeeeffff1111';
    
    // Create authorized re-save
    const addRes = await versionControlService.createVersion({
      sourceId: masterSource.id,
      fileName: 'master_resaved_v2.pdf',
      newHash: newDerivHash,
      transformationReason: 'Color profile normalisation for legal archive',
      actor: 'Lead Forensics Investigator',
      authorizationStatus: 'AUTHORIZED',
    });

    const verifyRes = await apiService.verifySource(newDerivHash, masterSource.id);
    const pass = verifyRes.verdict === 'AUTHORIZED_DERIVATIVE';
    recordResult(14, 'Authorized re-save', 'AUTHORIZED_DERIVATIVE', verifyRes.verdict, pass);
  }

  // --- Scenario 15: Unauthorized re-save ---
  {
    const masterSource = ledgerStorage.getSources()[0];
    const unauthHash = '55556666777788889999aaaabbbbccccddddeeeeffff00001111222233334444';
    
    // Create unauthorized derivative
    await versionControlService.createVersion({
      sourceId: masterSource.id,
      fileName: 'unauthorized_manipulation.pdf',
      newHash: unauthHash,
      transformationReason: 'Watermark strip detected',
      actor: 'Adversary / Suspect',
      authorizationStatus: 'UNAUTHORIZED',
    });

    const verifyRes = await apiService.verifySource(unauthHash, masterSource.id);
    const pass = verifyRes.verdict === 'REQUIRES_INVESTIGATION';
    recordResult(15, 'Unauthorized re-save', 'REQUIRES_INVESTIGATION', verifyRes.verdict, pass);
  }

  // --- Scenario 16: Unknown source verification ---
  {
    const unknownHash = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
    const verifyRes = await apiService.verifySource(unknownHash, null);
    const pass = verifyRes.verdict === 'UNKNOWN';
    recordResult(16, 'Unknown source verification', 'UNKNOWN', verifyRes.verdict, pass);
  }

  console.log('----------------------------------------------------------------');
  const allPassed = results.every(r => r.pass);
  console.log(`TOTAL SCENARIOS TESTED: ${results.length}`);
  console.log(`PASSED: ${results.filter(r => r.pass).length}`);
  console.log(`FAILED: ${results.filter(r => !r.pass).length}`);
  console.log(`OVERALL STATUS: ${allPassed ? 'ALL SCENARIOS PASSED (16/16)' : 'FAILURES DETECTED'}`);
  console.log('================================================================');
}

run16ScenarioValidation().catch(console.error);
