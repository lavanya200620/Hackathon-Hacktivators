/**
 * SourceMark – Final Checkpoint and Private Key Security Audit Suite
 *
 * Explicitly tests all 10 required security scenarios:
 * 1. Valid cryptographically verified checkpoint
 * 2. Fabricated checkpoint object
 * 3. Modified checkpoint hash
 * 4. Invalid checkpoint signature
 * 5. Missing checkpoint authority
 * 6. Missing trusted timestamp
 * 7. Browser-generated timestamp
 * 8. Compromised signing key
 * 9. Attempt to use revoked key
 * 10. Demo private-key storage and reset
 */

import { apiService } from '../src/services/api.js';
import { keySecurityService } from '../src/services/keySecurity.js';
import { checkpointService, TRUSTED_CHECKPOINT_AUTHORITIES } from '../src/services/checkpointService.js';
import { ledgerStorage } from '../src/services/ledgerStorage.js';
import { 
  generateKeyPair, 
  signFingerprint, 
  getOrCreateKeyPair, 
  resetDemoKeyPair,
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

async function runFinalSecurityAudit() {
  console.log('================================================================');
  console.log('  SOURCEMARK FINAL CHECKPOINT & PRIVATE KEY SECURITY AUDIT      ');
  console.log('================================================================\n');

  ledgerStorage.resetLedger();
  keySecurityService.resetToDefaults();
  checkpointService.initDefaultCheckpoints();

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

  // Timeline anchors
  const now = Date.now();
  const tPreBreach   = new Date(now - 2 * 3600000).toISOString();
  const tCompromise  = new Date(now - 1 * 3600000).toISOString();
  const tPostBreach  = new Date(now - 10 * 60000).toISOString();

  // Master keypair for test sources
  const authorKp = generateKeyPair();
  const authorKeyId = 'KEY-AUDIT-AUTHOR-01';

  keySecurityService.saveKeys([
    {
      id: authorKeyId,
      owner: 'SecOps Director',
      role: 'Cryptographic Lead',
      publicKeyHex: authorKp.publicKeyHex,
      algorithm: 'Ed25519',
      status: 'ACTIVE',
      createdAt: new Date(now - 4 * 3600000).toISOString(),
      compromisedAt: null,
      revokedAt: null,
      rotationHistory: [],
    }
  ]);

  // --------------------------------------------------------------------------
  // TEST 1: Valid cryptographically verified checkpoint
  // --------------------------------------------------------------------------
  {
    const chkData = {
      id: 'CHK-SEALED-001',
      recordNumber: 8,
      latestHash: '8888888888888888888888888888888888888888888888888888888888888888',
      timestamp: tPreBreach,
      prevCheckpointHash: '0000000000000000000000000000000000000000000000000000000000000000',
    };

    const signedProof = checkpointService.createSignedCheckpointProof(chkData);
    const evalResult = checkpointService.verifyCheckpointProof(signedProof);
    
    // Also test that simulated checkpoint claiming isDemoCheckpoint: false cannot bypass isProductionGrade check
    const simulatedBypassAttempt = {
      ...signedProof,
      isDemoCheckpoint: false, // Attempt to claim production status
    };
    const bypassEval = checkpointService.verifyCheckpointProof(simulatedBypassAttempt);

    const pass = evalResult.isTrusted === true && 
                 evalResult.status === 'TRUSTED_LEDGER_PROOF' &&
                 evalResult.isProductionGrade === false &&
                 bypassEval.isProductionGrade === false;

    logTest(
      1,
      'Valid Cryptographically Verified Checkpoint & isProductionGrade Guard',
      'isTrusted: true, status: TRUSTED_LEDGER_PROOF, isProductionGrade: false',
      `isTrusted: ${evalResult.isTrusted}, status: ${evalResult.status}, isProductionGrade: ${evalResult.isProductionGrade} (Bypass attempt: ${bypassEval.isProductionGrade})`,
      pass,
      `Cryptographically verified against ${evalResult.authority}. isProductionGrade strictly blocked for browser-local/simulated anchors.`
    );
  }

  // --------------------------------------------------------------------------
  // TEST 2: Fabricated checkpoint object
  // --------------------------------------------------------------------------
  {
    const fabricatedProof = {
      checkpointId: 'CHK-FABRICATED-999',
      blockHash: '9182049182049182049182049182049182049182049182049182049182049182',
      blockNumber: 6,
      timestamp: tPreBreach,
    };

    const evalResult = checkpointService.verifyCheckpointProof(fabricatedProof);
    const pass = evalResult.isTrusted === false && 
                 evalResult.status === 'UNVERIFIED_CHECKPOINT' && 
                 evalResult.subStatus === 'MISSING_CHECKPOINT_AUTHORITY';

    logTest(
      2,
      'Fabricated Checkpoint Object (Fields exist, but no authority or signature)',
      'isTrusted: false, status: UNVERIFIED_CHECKPOINT, subStatus: MISSING_CHECKPOINT_AUTHORITY',
      `isTrusted: ${evalResult.isTrusted}, status: ${evalResult.status}, subStatus: ${evalResult.subStatus}`,
      pass,
      'System refused to trust checkpoint merely because fields exist.'
    );
  }

  // --------------------------------------------------------------------------
  // TEST 3: Modified checkpoint hash
  // --------------------------------------------------------------------------
  {
    const chkData = {
      id: 'CHK-TAMPER-003',
      recordNumber: 10,
      latestHash: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      timestamp: tPreBreach,
    };

    const validProof = checkpointService.createSignedCheckpointProof(chkData);
    // Adversary modifies the checkpoint hash after authority signature was generated
    const tamperedProof = {
      ...validProof,
      checkpointHash: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      latestHash: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    };

    const evalResult = checkpointService.verifyCheckpointProof(tamperedProof);
    const pass = evalResult.isTrusted === false && 
                 evalResult.status === 'UNVERIFIED_CHECKPOINT' &&
                 evalResult.subStatus === 'INVALID_CHECKPOINT_SIGNATURE';

    logTest(
      3,
      'Modified Checkpoint Hash (Bitstream altered after authority sealing)',
      'isTrusted: false, status: UNVERIFIED_CHECKPOINT, subStatus: INVALID_CHECKPOINT_SIGNATURE',
      `isTrusted: ${evalResult.isTrusted}, status: ${evalResult.status}, subStatus: ${evalResult.subStatus}`,
      pass,
      'Signature verification detected tamper divergence in canonical payload.'
    );
  }

  // --------------------------------------------------------------------------
  // TEST 4: Invalid checkpoint signature
  // --------------------------------------------------------------------------
  {
    const chkData = {
      id: 'CHK-FORGED-SIG-004',
      recordNumber: 12,
      latestHash: 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
      timestamp: tPreBreach,
    };

    const validProof = checkpointService.createSignedCheckpointProof(chkData);
    // Inject corrupt signature bytes
    const forgedProof = {
      ...validProof,
      signature: '00000000000000000000000000000000000000000000000000000000000000001111111111111111111111111111111111111111111111111111111111111111',
    };

    const evalResult = checkpointService.verifyCheckpointProof(forgedProof);
    const pass = evalResult.isTrusted === false && 
                 evalResult.status === 'UNVERIFIED_CHECKPOINT' &&
                 evalResult.subStatus === 'INVALID_CHECKPOINT_SIGNATURE';

    logTest(
      4,
      'Invalid Checkpoint Signature',
      'isTrusted: false, status: UNVERIFIED_CHECKPOINT, subStatus: INVALID_CHECKPOINT_SIGNATURE',
      `isTrusted: ${evalResult.isTrusted}, status: ${evalResult.status}, subStatus: ${evalResult.subStatus}`,
      pass,
      'Ed25519 detached verification rejected forged signature.'
    );
  }

  // --------------------------------------------------------------------------
  // TEST 5: Missing checkpoint authority
  // --------------------------------------------------------------------------
  {
    const chkData = {
      id: 'CHK-UNAUTH-005',
      recordNumber: 14,
      latestHash: 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
      timestamp: tPreBreach,
    };

    const validProof = checkpointService.createSignedCheckpointProof(chkData);
    const unauthProof = {
      ...validProof,
      authorityId: 'ROGUE-UNREGISTERED-AUTHORITY-XYZ',
      authority: 'Rogue Authority',
    };

    const evalResult = checkpointService.verifyCheckpointProof(unauthProof);
    const pass = evalResult.isTrusted === false && 
                 evalResult.status === 'UNVERIFIED_CHECKPOINT' &&
                 evalResult.subStatus === 'UNAUTHORIZED_CHECKPOINT_AUTHORITY';

    logTest(
      5,
      'Missing or Unauthorized Checkpoint Authority',
      'isTrusted: false, status: UNVERIFIED_CHECKPOINT, subStatus: UNAUTHORIZED_CHECKPOINT_AUTHORITY',
      `isTrusted: ${evalResult.isTrusted}, status: ${evalResult.status}, subStatus: ${evalResult.subStatus}`,
      pass,
      'Authority rejected as uncatalogued in SourceMark PKI trust root.'
    );
  }

  // --------------------------------------------------------------------------
  // TEST 6: Missing trusted timestamp
  // --------------------------------------------------------------------------
  {
    const hash6 = '6666666666666666666666666666666666666666666666666666666666666666';
    // Document was signed during normal operations
    const sig6 = signFingerprint(hash6, authorKp.secretKeyHex).signatureHex;

    // Key is subsequently reported COMPROMISED
    const keys = keySecurityService.getKeys();
    const k = keys.find(item => item.id === authorKeyId);
    k.status = 'COMPROMISED';
    k.compromisedAt = tCompromise;
    k.revokedAt = tCompromise;
    keySecurityService.saveKeys(keys);

    const src6 = ledgerStorage.addSource({
      id: 'SRC-TEST-MISSING-TIME-06',
      fileName: 'no_time_evidence.bin',
      sha256: hash6,
      signature: sig6,
      publicKey: authorKp.publicKeyHex,
      keyId: authorKeyId,
      creator: 'Audit Target',
      signedAt: null,
      registeredAt: null,
      tsaToken: null,
      ledgerProof: null,
      status: 'ACTIVE_REGISTERED',
    });

    const res6 = await apiService.verifySource(hash6, src6.id);
    const pass6 = res6.verdict === 'REQUIRES_INVESTIGATION' && res6.subVerdict === 'UNKNOWN_SIGNING_TIME';

    logTest(
      6,
      'Missing Trusted Timestamp (Zero temporal evidence against compromised key)',
      'REQUIRES_INVESTIGATION (UNKNOWN_SIGNING_TIME)',
      `${res6.verdict}${res6.subVerdict ? ` (${res6.subVerdict})` : ''}`,
      pass6,
      'System refused to presume pre-compromise validity without trusted evidence.'
    );
  }

  // --------------------------------------------------------------------------
  // TEST 7: Browser-generated timestamp
  // --------------------------------------------------------------------------
  {
    const hash7 = '7777777777777777777777777777777777777777777777777777777777777777';
    // Use detached raw nacl signature or sign prior to compromise
    const sigBytes7 = nacl.sign.detached(hexToUint8Array(hash7), authorKp.secretKey);
    const sig7 = bufferToHex(sigBytes7);

    const src7 = ledgerStorage.addSource({
      id: 'SRC-TEST-BROWSER-TIME-07',
      fileName: 'browser_claimed_prebreach.pdf',
      sha256: hash7,
      signature: sig7,
      publicKey: authorKp.publicKeyHex,
      keyId: authorKeyId,
      creator: 'Client Browser',
      signedAt: tPreBreach, // Claims pre-breach time in plain metadata
      registeredAt: tPostBreach,
      tsaToken: null,
      ledgerProof: null,
      status: 'ACTIVE_REGISTERED',
    });

    const res7 = await apiService.verifySource(hash7, src7.id);
    const pass7 = res7.verdict === 'REQUIRES_INVESTIGATION' && res7.subVerdict === 'UNKNOWN_SIGNING_TIME';

    logTest(
      7,
      'Browser-Generated Timestamp (Untrusted client signedAt metadata)',
      'REQUIRES_INVESTIGATION (UNKNOWN_SIGNING_TIME)',
      `${res7.verdict}${res7.subVerdict ? ` (${res7.subVerdict})` : ''}`,
      pass7,
      'Browser metadata rejected as untrusted; quarantined to REQUIRES_INVESTIGATION.'
    );
  }

  // --------------------------------------------------------------------------
  // TEST 8: Compromised signing key
  // --------------------------------------------------------------------------
  {
    const hash8 = '8888888888888888888888888888888888888888888888888888888888888888';
    const sigBytes8 = nacl.sign.detached(hexToUint8Array(hash8), authorKp.secretKey);
    const sig8 = bufferToHex(sigBytes8);

    const src8 = ledgerStorage.addSource({
      id: 'SRC-TEST-POST-COMPROMISE-08',
      fileName: 'post_compromise_document.pdf',
      sha256: hash8,
      signature: sig8,
      publicKey: authorKp.publicKeyHex,
      keyId: authorKeyId,
      creator: 'Intruder',
      signedAt: tPostBreach, // Timestamped AFTER key compromise
      registeredAt: tPostBreach,
      tsaToken: {
        authority: 'DigiCert Qualified RFC 3161 TSA Server #1',
        timestamp: tPostBreach,
        tokenHash: hash8,
        status: 'VERIFIED',
      },
      status: 'ACTIVE_REGISTERED',
    });

    const res8 = await apiService.verifySource(hash8, src8.id);
    const pass8 = res8.verdict === 'COMPROMISED_KEY';

    logTest(
      8,
      'Compromised Signing Key (Post-compromise signature)',
      'COMPROMISED_KEY',
      res8.verdict,
      pass8,
      'Asset signed after known key compromise time correctly flagged as COMPROMISED_KEY.'
    );
  }

  // --------------------------------------------------------------------------
  // TEST 9: Attempt to use revoked key
  // --------------------------------------------------------------------------
  {
    let signingBlocked = false;
    let exceptionMessage = '';

    try {
      // Attempting to sign using authorKp (which is currently marked COMPROMISED / REVOKED)
      signFingerprint('9999999999999999999999999999999999999999999999999999999999999999', authorKp.secretKeyHex);
    } catch (e) {
      if (e.message.includes('SECURITY EXCEPTION')) {
        signingBlocked = true;
        exceptionMessage = e.message;
      }
    }

    logTest(
      9,
      'Attempt to Use Revoked Key (Signing operation blocked)',
      'SECURITY EXCEPTION (Signing blocked)',
      signingBlocked ? exceptionMessage : 'Signing was permitted (SECURITY VIOLATION)',
      signingBlocked,
      'Cryptographic engine strictly blocked new signing operations for revoked key.'
    );
  }

  // --------------------------------------------------------------------------
  // TEST 10: Demo private-key storage and reset
  // --------------------------------------------------------------------------
  {
    // 1. Generate demo key
    const demoKp = getOrCreateKeyPair();
    const isCorrectlyLabeled = demoKp.isDemoKey === true && 
                               demoKp.hardwareBacked === false && 
                               demoKp.keyLabel === 'BROWSER DEMO KEY (NOT PRODUCTION HSM)';

    const storedBefore = global.localStorage.getItem('sourcemark_ed25519_keypair');
    const isStored = !!storedBefore;

    // 2. Call reset mechanism
    const resetResult = resetDemoKeyPair();
    const storedAfter = global.localStorage.getItem('sourcemark_ed25519_keypair');
    const isPurged = storedAfter === null;

    const pass10 = isCorrectlyLabeled && isStored && resetResult.success && isPurged;

    logTest(
      10,
      'Demo Private-Key Storage and Reset Mechanism',
      'Labeled as DEMO KEY, hardwareBacked: false, purged on reset',
      `Labeled: ${isCorrectlyLabeled}, Stored: ${isStored}, Purged: ${isPurged}`,
      pass10,
      'Demo keys are clearly labeled, never claim hardware backing, and can be cleanly purged.'
    );
  }

  console.log('----------------------------------------------------------------');
  const allPass = testResults.every(t => t.pass);
  console.log(`TOTAL SECURITY TESTS: ${testResults.length}`);
  console.log(`PASSED: ${testResults.filter(t => t.pass).length}`);
  console.log(`FAILED: ${testResults.filter(t => !t.pass).length}`);
  console.log(`OVERALL STATUS: ${allPass ? 'ALL 10 SECURITY AUDIT TESTS PASSED' : 'FAILURES DETECTED'}`);
  console.log('================================================================');

  if (!allPass) process.exit(1);
}

runFinalSecurityAudit().catch(err => {
  console.error(err);
  process.exit(1);
});
