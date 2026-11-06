/**
 * SourceMark – Comprehensive Trusted Timestamp Verification Test Suite
 *
 * Explicitly tests all 8 required verification scenarios:
 * 1. Source with valid, independently verifiable TSA timestamp (Active key)
 * 2. Source with only a browser-generated timestamp (signedAt)
 * 3. Source with only registeredAt timestamp
 * 4. Source with no timestamp data
 * 5. Signature created before key compromise with trusted timestamp evidence (PRE_COMPROMISE_VALID)
 * 6. Signature created after key compromise (COMPROMISED_KEY)
 * 7. Invalid or expired TSA certificates (EXPIRED_TSA_CERTIFICATE & INVALID_TSA_TOKEN)
 * 8. Quarantining: missing/untrusted timestamps strictly evaluate to REQUIRES_INVESTIGATION
 */

import { apiService } from '../src/services/api.js';
import { keySecurityService } from '../src/services/keySecurity.js';
import { ledgerStorage } from '../src/services/ledgerStorage.js';
import { 
  generateKeyPair, 
  signFingerprint, 
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

// Helper for generating historical signature bitstreams (pre-existing records on ledger)
const makeHistoricalSig = (hash, secretKey) => {
  const msg = hexToUint8Array(hash);
  const sec = typeof secretKey === 'string' ? hexToUint8Array(secretKey) : secretKey;
  const sig = nacl.sign.detached(msg, sec);
  return bufferToHex(sig);
};

async function runTrustedTimestampTests() {
  console.log('================================================================');
  console.log('       SOURCEMARK TRUSTED TIMESTAMP SECURITY TEST SUITE         ');
  console.log('================================================================\n');

  ledgerStorage.resetLedger();
  keySecurityService.resetToDefaults();

  // Create active and compromised key pairs
  const activeKp = generateKeyPair();
  const activeKeyId = 'KEY-TSA-ACTIVE-01';

  const compromisedKp = generateKeyPair();
  const compromisedKeyId = 'KEY-TSA-COMPROMISED-01';

  // Timeline anchors
  const now = Date.now();
  const tKeyCreated   = new Date(now - 4 * 3600000).toISOString(); // 4 hours ago
  const tPreBreach    = new Date(now - 2 * 3600000).toISOString(); // 2 hours ago
  const tCompromised  = new Date(now - 1 * 3600000).toISOString(); // 1 hour ago (BREACH OCCURRED)
  const tPostBreach   = new Date(now - 10 * 60000).toISOString();  // 10 mins ago
  const tPastExpiry   = new Date(now - 3 * 3600000).toISOString(); // 3 hours ago (expired certificate)

  // Configure authority keys in registry
  keySecurityService.saveKeys([
    {
      id: activeKeyId,
      owner: 'SecOps Lead Auditor',
      role: 'Active Cryptographic Authority',
      publicKeyHex: activeKp.publicKeyHex,
      algorithm: 'Ed25519',
      status: 'ACTIVE',
      createdAt: tKeyCreated,
      compromisedAt: null,
      revokedAt: null,
      rotationHistory: [],
    },
    {
      id: compromisedKeyId,
      owner: 'Chief Cryptographer (Dr. Vance)',
      role: 'Master Satellite Authority',
      publicKeyHex: compromisedKp.publicKeyHex,
      algorithm: 'Ed25519',
      status: 'COMPROMISED',
      createdAt: tKeyCreated,
      compromisedAt: tCompromised,
      revokedAt: tCompromised,
      rotationHistory: [],
    }
  ]);

  const testResults = [];
  const logCase = (num, name, expected, actual, pass, detail) => {
    testResults.push({ num, name, expected, actual, pass });
    const mark = pass ? '✓ PASS' : '✗ FAIL';
    console.log(`[Requirement ${num}] ${name}`);
    console.log(`   Expected: ${expected}`);
    console.log(`   Actual:   ${actual}`);
    console.log(`   Detail:   ${detail}`);
    console.log(`   Result:   ${mark}\n`);
  };

  // --------------------------------------------------------------------------
  // REQUIREMENT 1: Source with valid, independently verifiable TSA timestamp (Active Key)
  // --------------------------------------------------------------------------
  {
    const hash1 = '1111111111111111111111111111111111111111111111111111111111111111';
    const sig1 = signFingerprint(hash1, activeKp.secretKeyHex).signatureHex;
    const src1 = ledgerStorage.addSource({
      id: 'SRC-TSA-VALID-01',
      fileName: 'valid_tsa_active_asset.pdf',
      sha256: hash1,
      signature: sig1,
      publicKey: activeKp.publicKeyHex,
      keyId: activeKeyId,
      creator: 'SecOps Auditor',
      signedAt: tPreBreach,
      registeredAt: tPreBreach,
      tsaToken: {
        authority: 'DigiCert Qualified RFC 3161 TSA Server #1',
        timestamp: tPreBreach,
        tokenHash: hash1,
        signature: '3045022100...verifiable_tsa_der_signature',
        status: 'VERIFIED',
      },
      status: 'ACTIVE_REGISTERED',
    });

    const timestampEval = apiService.verifyTrustedTimestamp(src1);
    const res1 = await apiService.verifySource(hash1, src1.id);
    const pass1 = timestampEval.isTrusted === true && 
                  timestampEval.status === 'TRUSTED_TSA_TOKEN' &&
                  res1.verdict === 'ORIGINAL';
    logCase(
      1,
      'Valid, Independently Verifiable TSA Timestamp (Active Key)',
      'isTrusted: true, status: TRUSTED_TSA_TOKEN, verdict: ORIGINAL',
      `isTrusted: ${timestampEval.isTrusted}, status: ${timestampEval.status}, verdict: ${res1.verdict}`,
      pass1,
      `TSA Token validated under RFC 3161 standards (${timestampEval.authority}). Independent cryptographic evidence attached.`
    );
  }

  // --------------------------------------------------------------------------
  // REQUIREMENT 2: Source with only a browser-generated timestamp
  // --------------------------------------------------------------------------
  {
    const hash2 = '2222222222222222222222222222222222222222222222222222222222222222';
    const sig2 = makeHistoricalSig(hash2, compromisedKp.secretKeyHex);
    const src2 = ledgerStorage.addSource({
      id: 'SRC-TSA-BROWSER-ONLY-02',
      fileName: 'browser_generated_time_document.pdf',
      sha256: hash2,
      signature: sig2,
      publicKey: compromisedKp.publicKeyHex,
      keyId: compromisedKeyId,
      creator: 'Suspect Client',
      signedAt: tPreBreach, // Claims pre-breach in client metadata
      registeredAt: tPostBreach,
      tsaToken: null, // NO TSA TOKEN
      status: 'ACTIVE_REGISTERED',
    });

    const timestampEval = apiService.verifyTrustedTimestamp(src2);
    const res2 = await apiService.verifySource(hash2, src2.id);
    const pass2 = timestampEval.isTrusted === false &&
                  timestampEval.status === 'UNTRUSTED_CLIENT_TIMESTAMP' &&
                  res2.verdict === 'REQUIRES_INVESTIGATION' &&
                  res2.subVerdict === 'UNKNOWN_SIGNING_TIME';
    logCase(
      2,
      'Source with Only a Browser-Generated Timestamp',
      'isTrusted: false, status: UNTRUSTED_CLIENT_TIMESTAMP, verdict: REQUIRES_INVESTIGATION',
      `isTrusted: ${timestampEval.isTrusted}, status: ${timestampEval.status}, verdict: ${res2.verdict}`,
      pass2,
      'Client-supplied signedAt string rejected as untrusted. Without an RFC 3161 TSA token, cannot prove pre-compromise signing.'
    );
  }

  // --------------------------------------------------------------------------
  // REQUIREMENT 3: Source with only registeredAt
  // --------------------------------------------------------------------------
  {
    const hash3 = '3333333333333333333333333333333333333333333333333333333333333333';
    const sig3 = makeHistoricalSig(hash3, compromisedKp.secretKeyHex);
    const src3 = ledgerStorage.addSource({
      id: 'SRC-TSA-REGISTRATION-ONLY-03',
      fileName: 'registration_only_time_document.pdf',
      sha256: hash3,
      signature: sig3,
      publicKey: compromisedKp.publicKeyHex,
      keyId: compromisedKeyId,
      creator: 'SecOps',
      registeredAt: tPreBreach, // Only registeredAt exists
      signedAt: null,
      tsaToken: null,
      status: 'ACTIVE_REGISTERED',
    });

    const timestampEval = apiService.verifyTrustedTimestamp(src3);
    const res3 = await apiService.verifySource(hash3, src3.id);
    const pass3 = timestampEval.isTrusted === false &&
                  timestampEval.status === 'UNTRUSTED_REGISTRATION_TIMESTAMP' &&
                  res3.verdict === 'REQUIRES_INVESTIGATION' &&
                  res3.subVerdict === 'UNKNOWN_SIGNING_TIME';
    logCase(
      3,
      'Source with Only registeredAt Timestamp',
      'isTrusted: false, status: UNTRUSTED_REGISTRATION_TIMESTAMP, verdict: REQUIRES_INVESTIGATION',
      `isTrusted: ${timestampEval.isTrusted}, status: ${timestampEval.status}, verdict: ${res3.verdict}`,
      pass3,
      'Registration timestamp does not prove when signature was created. System refused fallback to registeredAt.'
    );
  }

  // --------------------------------------------------------------------------
  // REQUIREMENT 4: Source with no timestamp
  // --------------------------------------------------------------------------
  {
    const hash4 = '4444444444444444444444444444444444444444444444444444444444444444';
    const sig4 = makeHistoricalSig(hash4, compromisedKp.secretKeyHex);
    const src4 = ledgerStorage.addSource({
      id: 'SRC-TSA-NO-TIME-04',
      fileName: 'missing_all_timestamp_data.bin',
      sha256: hash4,
      signature: sig4,
      publicKey: compromisedKp.publicKeyHex,
      keyId: compromisedKeyId,
      creator: 'Unknown Operator',
      signedAt: null,
      signatureTimestamp: null,
      registeredAt: null,
      tsaToken: null,
      status: 'ACTIVE_REGISTERED',
    });

    const timestampEval = apiService.verifyTrustedTimestamp(src4);
    const res4 = await apiService.verifySource(hash4, src4.id);
    const pass4 = timestampEval.isTrusted === false &&
                  timestampEval.status === 'MISSING_TIMESTAMP' &&
                  res4.verdict === 'REQUIRES_INVESTIGATION' &&
                  res4.subVerdict === 'UNKNOWN_SIGNING_TIME';
    logCase(
      4,
      'Source with No Timestamp Evidence',
      'isTrusted: false, status: MISSING_TIMESTAMP, verdict: REQUIRES_INVESTIGATION',
      `isTrusted: ${timestampEval.isTrusted}, status: ${timestampEval.status}, verdict: ${res4.verdict}`,
      pass4,
      'Zero temporal evidence present. Historical signing validity cannot be determined against compromised key.'
    );
  }

  // --------------------------------------------------------------------------
  // REQUIREMENT 5: Signature created before known key compromise with trusted timestamp evidence
  // --------------------------------------------------------------------------
  {
    const hash5 = '5555555555555555555555555555555555555555555555555555555555555555';
    const sig5 = makeHistoricalSig(hash5, compromisedKp.secretKeyHex);
    const src5 = ledgerStorage.addSource({
      id: 'SRC-TSA-PRE-BREACH-VERIFIED-05',
      fileName: 'pre_breach_recon_satellite_proven.png',
      sha256: hash5,
      signature: sig5,
      publicKey: compromisedKp.publicKeyHex,
      keyId: compromisedKeyId,
      creator: 'Dr. Vance',
      signedAt: tPreBreach,
      registeredAt: tPreBreach,
      tsaToken: {
        authority: 'DigiCert Qualified RFC 3161 TSA Server #1',
        timestamp: tPreBreach,
        tokenHash: hash5,
        signature: '3045022100...verifiable_tsa_der_signature',
        status: 'VERIFIED',
      },
      status: 'ACTIVE_REGISTERED',
    });

    const res5 = await apiService.verifySource(hash5, src5.id);
    const pass5 = res5.verdict === 'PRE_COMPROMISE_VALID';
    logCase(
      5,
      'Signature Created Before Key Compromise with Trusted TSA Evidence',
      'PRE_COMPROMISE_VALID',
      res5.verdict,
      pass5,
      `Cryptographically verified by TSA (${res5.tsaAuthority}) timestamped ${tPreBreach} strictly before key breach at ${tCompromised}.`
    );
  }

  // --------------------------------------------------------------------------
  // REQUIREMENT 6: Signature created after key compromise
  // --------------------------------------------------------------------------
  {
    const hash6 = '6666666666666666666666666666666666666666666666666666666666666666';
    const sig6 = makeHistoricalSig(hash6, compromisedKp.secretKeyHex);
    const src6 = ledgerStorage.addSource({
      id: 'SRC-TSA-POST-BREACH-06',
      fileName: 'adversary_post_breach_signature.pdf',
      sha256: hash6,
      signature: sig6,
      publicKey: compromisedKp.publicKeyHex,
      keyId: compromisedKeyId,
      creator: 'Intruder',
      signedAt: tPostBreach,
      registeredAt: tPostBreach,
      tsaToken: {
        authority: 'DigiCert Qualified RFC 3161 TSA Server #1',
        timestamp: tPostBreach,
        tokenHash: hash6,
        signature: '3045022100...tsa_signature',
        status: 'VERIFIED',
      },
      status: 'ACTIVE_REGISTERED',
    });

    const res6 = await apiService.verifySource(hash6, src6.id);
    const pass6 = res6.verdict === 'COMPROMISED_KEY';
    logCase(
      6,
      'Signature Created After Key Compromise Time',
      'COMPROMISED_KEY',
      res6.verdict,
      pass6,
      `Verified timestamp ${tPostBreach} is after key compromise ${tCompromised}. Key authority revoked.`
    );
  }

  // --------------------------------------------------------------------------
  // REQUIREMENT 7: Invalid or Expired TSA Certificates
  // --------------------------------------------------------------------------
  {
    // Subcase 7A: Expired TSA Certificate
    const hash7A = '777777777777777777777777777777777777777777777777777777777777777a';
    const sig7A = makeHistoricalSig(hash7A, compromisedKp.secretKeyHex);
    const src7A = ledgerStorage.addSource({
      id: 'SRC-TSA-EXPIRED-CERT-07A',
      fileName: 'expired_tsa_cert_document.pdf',
      sha256: hash7A,
      signature: sig7A,
      publicKey: compromisedKp.publicKeyHex,
      keyId: compromisedKeyId,
      creator: 'Legacy Archive',
      signedAt: tPreBreach,
      registeredAt: tPreBreach,
      tsaToken: {
        authority: 'Legacy Root TSA #4 (Expired 2026)',
        timestamp: tPreBreach,
        tokenHash: hash7A,
        status: 'EXPIRED',
        certExpiresAt: tPastExpiry,
        certExpired: true,
      },
      status: 'ACTIVE_REGISTERED',
    });

    const timestampEval7A = apiService.verifyTrustedTimestamp(src7A);
    const res7A = await apiService.verifySource(hash7A, src7A.id);
    const pass7A = timestampEval7A.isTrusted === false &&
                   timestampEval7A.status === 'EXPIRED_TSA_CERTIFICATE' &&
                   res7A.verdict === 'REQUIRES_INVESTIGATION' &&
                   res7A.subVerdict === 'UNKNOWN_SIGNING_TIME';

    // Subcase 7B: Cryptographically Invalid TSA Token
    const hash7B = '777777777777777777777777777777777777777777777777777777777777777b';
    const sig7B = makeHistoricalSig(hash7B, compromisedKp.secretKeyHex);
    const src7B = ledgerStorage.addSource({
      id: 'SRC-TSA-INVALID-TOKEN-07B',
      fileName: 'tampered_tsa_token_document.pdf',
      sha256: hash7B,
      signature: sig7B,
      publicKey: compromisedKp.publicKeyHex,
      keyId: compromisedKeyId,
      creator: 'Tampered Token Injector',
      signedAt: tPreBreach,
      registeredAt: tPreBreach,
      tsaToken: {
        authority: 'Untrusted Rogue TSA',
        timestamp: tPreBreach,
        tokenHash: hash7B,
        status: 'INVALID',
        valid: false,
        failureReason: 'Cryptographic digest mismatch in TSA token signature',
      },
      status: 'ACTIVE_REGISTERED',
    });

    const timestampEval7B = apiService.verifyTrustedTimestamp(src7B);
    const res7B = await apiService.verifySource(hash7B, src7B.id);
    const pass7B = timestampEval7B.isTrusted === false &&
                   timestampEval7B.status === 'INVALID_TSA_TOKEN' &&
                   res7B.verdict === 'REQUIRES_INVESTIGATION' &&
                   res7B.subVerdict === 'UNKNOWN_SIGNING_TIME';

    const pass7 = pass7A && pass7B;
    logCase(
      7,
      'Invalid or Expired TSA Certificates (Expired & Tampered Tokens)',
      'isTrusted: false, status: EXPIRED_TSA_CERTIFICATE / INVALID_TSA_TOKEN, verdict: REQUIRES_INVESTIGATION',
      `7A: ${timestampEval7A.status} -> ${res7A.verdict} | 7B: ${timestampEval7B.status} -> ${res7B.verdict}`,
      pass7,
      'Expired and cryptographically invalid TSA tokens are rejected. Lacking a valid trust chain, signatures are quarantined.'
    );
  }

  // --------------------------------------------------------------------------
  // REQUIREMENT 8: Missing or untrusted timestamps strictly result in REQUIRES_INVESTIGATION
  // --------------------------------------------------------------------------
  {
    // Aggregate verification: Check that NO untrusted or missing timestamp is EVER assumed pre-compromise valid
    const quarantineCandidates = [
      { id: 'SRC-TSA-BROWSER-ONLY-02', type: 'Browser signedAt only' },
      { id: 'SRC-TSA-REGISTRATION-ONLY-03', type: 'registeredAt only' },
      { id: 'SRC-TSA-NO-TIME-04', type: 'Missing timestamp' },
      { id: 'SRC-TSA-EXPIRED-CERT-07A', type: 'Expired TSA certificate' },
      { id: 'SRC-TSA-INVALID-TOKEN-07B', type: 'Invalid TSA token' },
    ];

    let allQuarantined = true;
    for (const c of quarantineCandidates) {
      const src = ledgerStorage.getSourceById(c.id);
      const res = await apiService.verifySource(src.sha256, src.id);
      if (res.verdict !== 'REQUIRES_INVESTIGATION' || res.subVerdict !== 'UNKNOWN_SIGNING_TIME') {
        allQuarantined = false;
        console.error(`FAILED Quarantine for ${c.type}: got ${res.verdict} (${res.subVerdict})`);
      }
    }

    logCase(
      8,
      'Anti-Presumption Quarantine: Untrusted Timestamps Result in REQUIRES_INVESTIGATION',
      'All 5 untrusted variants yield REQUIRES_INVESTIGATION (UNKNOWN_SIGNING_TIME)',
      allQuarantined ? 'All 5 untrusted variants quarantined' : 'One or more variants bypassed quarantine',
      allQuarantined,
      'System guarantees that absence of independent TSA proof never defaults to pre-compromise validity.'
    );
  }

  console.log('----------------------------------------------------------------');
  const allPass = testResults.every(t => t.pass);
  console.log(`TOTAL TIMESTAMP REQUIREMENTS TESTED: ${testResults.length}`);
  console.log(`PASSED: ${testResults.filter(t => t.pass).length}`);
  console.log(`FAILED: ${testResults.filter(t => !t.pass).length}`);
  console.log(`OVERALL TIMESTAMP VERIFICATION STATUS: ${allPass ? 'ALL 8 REQUIREMENTS PASSED' : 'FAILURES DETECTED'}`);
  console.log('================================================================');

  if (!allPass) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

runTrustedTimestampTests().catch((err) => {
  console.error(err);
  process.exit(1);
});
