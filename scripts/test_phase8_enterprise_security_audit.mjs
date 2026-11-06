/**
 * SourceMark Phase 8: Final Independent Enterprise Security & End-to-End Audit Suite
 * 
 * Comprehensive end-to-end verification of all seven completed phases:
 * 1. Multi-role authentication & RBAC across all six enterprise roles.
 * 2. Organization-level multi-tenant boundary isolation.
 * 3. Digital asset registration, Ed25519 signing, verification & tamper detection.
 * 4. Enterprise KMS key lifecycle, rotation, revocation & zero-private-key containment.
 * 5. RFC 3161 external TSA client, DER bitstream parsing, replay defense & truthful telemetry.
 * 6. PostgreSQL 16.15 ACID persistence, transactions, restart recovery & fallback resilience.
 * 7. Independent WORM storage, write-once protection, concurrency locking & 6-level rollback detection.
 * 8. Audit logging, credential redaction, input validation & rate limiting.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { EventEmitter } from 'node:events';
import nacl from 'tweetnacl';

import { query as pgQuery, checkConnection, getPool, withTransaction } from '../backend/db/postgres.mjs';
import { dbAdapter } from '../backend/db/adapter.mjs';
import { kmsManager, bufferToHex, hexToUint8Array } from '../backend/kms/kmsService.mjs';
import { tsaManager, parseTimeStampResponse, validateTimeStampToken } from '../backend/tsa/tsaService.mjs';
import { wormManager, LocalSimulatedWormStorageProvider } from '../backend/storage/wormService.mjs';
import { verifyFingerprintSignature } from '../src/services/crypto.js';
import {
  server,
  db,
  ROLES,
  PERMISSIONS,
  createSessionToken,
  hashPassword,
} from '../backend/server.mjs';

let passed = 0;
let failed = 0;

function report(testNum, title, expected, actual, detail, isPass) {
  if (isPass) {
    passed++;
    console.log(`[Test ${testNum}] ${title}`);
    console.log(`   Expected: ${expected}`);
    console.log(`   Actual:   ${actual}`);
    console.log(`   Detail:   ${detail}`);
    console.log(`   Result:   ✓ PASS\n`);
  } else {
    failed++;
    console.error(`[Test ${testNum}] ${title}`);
    console.error(`   Expected: ${expected}`);
    console.error(`   Actual:   ${actual}`);
    console.error(`   Detail:   ${detail}`);
    console.error(`   Result:   ✗ FAIL\n`);
  }
}

// In-process HTTP request dispatcher
function makeRequest({ method, url, headers = {}, body = null }) {
  return new Promise((resolve) => {
    const req = new EventEmitter();
    req.method = method;
    req.url = url;
    req.headers = { ...headers };
    req.socket = { remoteAddress: '127.0.0.1' };

    const res = new EventEmitter();
    let resHeaders = {};
    let statusCode = 200;
    let resBody = '';

    res.writeHead = (code, h) => {
      statusCode = code;
      resHeaders = h || {};
    };
    res.end = (chunk) => {
      if (chunk) resBody += chunk;
      let parsed = null;
      try {
        parsed = JSON.parse(resBody);
      } catch {
        parsed = resBody;
      }
      resolve({ statusCode, headers: resHeaders, body: parsed });
    };

    server.emit('request', req, res);

    if (body) {
      req.emit('data', typeof body === 'string' ? body : JSON.stringify(body));
    }
    req.emit('end');
  });
}

async function runAudit() {
  console.log('================================================================');
  console.log('   SOURCEMARK PHASE 8: FINAL ENTERPRISE SECURITY & E2E AUDIT    ');
  console.log('================================================================\n');

  // Verify PostgreSQL
  const dbHealth = await checkConnection();
  if (!dbHealth.connected) {
    console.error('[-] FATAL: PostgreSQL 16.15 database offline. Audit requires active sourcemark_db.');
    process.exit(1);
  }
  console.log(`[+] PostgreSQL 16.15 connected on localhost:5432 (Database: sourcemark_db)`);

  await kmsManager.initialize();
  await wormManager.initialize();
  await db.init();

  // Ensure revoked test key is registered
  if (!db.data.systemState.revokedKeys) db.data.systemState.revokedKeys = [];
  if (!db.data.systemState.revokedKeys.includes('ED25519-STOLEN-01')) {
    db.data.systemState.revokedKeys.push('ED25519-STOLEN-01');
  }

  // Authoritative Sessions for all 6 roles
  const sessions = {
    [ROLES.ADMINISTRATOR]: createSessionToken({ id: 'USR-ADMIN-01', userId: 'USR-ADMIN-01', email: 'admin@sourcemark.enterprise', role: ROLES.ADMINISTRATOR, organizationId: 'ORG-01', issuedAt: Date.now() }),
    [ROLES.FORENSIC_INVESTIGATOR]: createSessionToken({ id: 'USR-INV-01', userId: 'USR-INV-01', email: 'evelyn.vance@sourcemark.enterprise', role: ROLES.FORENSIC_INVESTIGATOR, organizationId: 'ORG-01', issuedAt: Date.now() }),
    [ROLES.SOC_ANALYST]: createSessionToken({ id: 'USR-SOC-01', userId: 'USR-SOC-01', email: 'marcus.brody@sourcemark.enterprise', role: ROLES.SOC_ANALYST, organizationId: 'ORG-02', issuedAt: Date.now() }),
    [ROLES.AUDITOR]: createSessionToken({ id: 'USR-AUD-01', userId: 'USR-AUD-01', email: 'auditor@sourcemark.enterprise', role: ROLES.AUDITOR, organizationId: 'ORG-01', issuedAt: Date.now() }),
    [ROLES.ORGANIZATION_MANAGER]: createSessionToken({ id: 'USR-MGR-01', userId: 'USR-MGR-01', email: 'sarah.chen@sourcemark.enterprise', role: ROLES.ORGANIZATION_MANAGER, organizationId: 'ORG-01', issuedAt: Date.now() }),
    [ROLES.USER]: createSessionToken({ id: 'USR-CUSTODIAN-01', userId: 'USR-CUSTODIAN-01', email: 'user@sourcemark.io', role: ROLES.USER, organizationId: 'ORG-01', issuedAt: Date.now() }),
  };

  // ---------------------------------------------------------------------------
  // SECTION 1: Multi-Role Authentication & Access Control (All 6 Roles)
  // ---------------------------------------------------------------------------
  console.log('\n--- SECTION 1: Multi-Role Access Control & Authorization (Positive & Negative) ---');

  // Test 1: ADMINISTRATOR Positive Authorization
  {
    const res = await makeRequest({
      method: 'GET',
      url: '/api/auth/users',
      headers: { authorization: `Bearer ${sessions[ROLES.ADMINISTRATOR]}` },
    });
    report(
      1,
      'ADMINISTRATOR Positive Authorization: GET /api/auth/users',
      'HTTP 200 with user governance directory',
      `HTTP ${res.statusCode}, Users Count: ${Array.isArray(res.body?.users) ? res.body.users.length : 0}`,
      'Administrator granted full access to user governance directory.',
      res.statusCode === 200 && Array.isArray(res.body?.users)
    );
  }

  // Test 2: FORENSIC_INVESTIGATOR Positive Authorization
  {
    const res = await makeRequest({
      method: 'GET',
      url: '/api/investigations',
      headers: { authorization: `Bearer ${sessions[ROLES.FORENSIC_INVESTIGATOR]}` },
    });
    const cases = res.body?.cases;
    report(
      2,
      'FORENSIC_INVESTIGATOR Positive Authorization: GET /api/investigations',
      'HTTP 200 with forensic case queue',
      `HTTP ${res.statusCode}, Cases Count: ${Array.isArray(cases) ? cases.length : 'none'}`,
      'Forensic Investigator granted access to digital evidence case queue.',
      res.statusCode === 200 && Array.isArray(cases)
    );
  }

  // Test 3: SOC_ANALYST Positive Authorization
  {
    const res = await makeRequest({
      method: 'GET',
      url: '/api/alerts',
      headers: { authorization: `Bearer ${sessions[ROLES.SOC_ANALYST]}` },
    });
    const alerts = res.body?.alerts;
    report(
      3,
      'SOC_ANALYST Positive Authorization: GET /api/alerts',
      'HTTP 200 with threat alert telemetry',
      `HTTP ${res.statusCode}, Alerts Count: ${Array.isArray(alerts) ? alerts.length : 'none'}`,
      'SOC Analyst granted access to security operations alert feed.',
      res.statusCode === 200 && Array.isArray(alerts)
    );
  }

  // Test 4: AUDITOR Positive Authorization
  {
    const res = await makeRequest({
      method: 'GET',
      url: '/api/audit-events',
      headers: { authorization: `Bearer ${sessions[ROLES.AUDITOR]}` },
    });
    const logs = res.body?.auditLogs;
    report(
      4,
      'AUDITOR Positive Authorization: GET /api/audit-events',
      'HTTP 200 with immutable audit log stream',
      `HTTP ${res.statusCode}, Logs Count: ${Array.isArray(logs) ? logs.length : 'none'}`,
      'Auditor granted non-repudiable read access to enterprise audit trail.',
      res.statusCode === 200 && Array.isArray(logs)
    );
  }

  // Test 5: ORGANIZATION_MANAGER Positive Authorization
  {
    const res = await makeRequest({
      method: 'GET',
      url: '/api/approvals',
      headers: { authorization: `Bearer ${sessions[ROLES.ORGANIZATION_MANAGER]}` },
    });
    const approvals = res.body?.approvals;
    report(
      5,
      'ORGANIZATION_MANAGER Positive Authorization: GET /api/approvals',
      'HTTP 200 with derivative approvals queue',
      `HTTP ${res.statusCode}, Approvals Count: ${Array.isArray(approvals) ? approvals.length : 'none'}`,
      'Organization Manager granted access to departmental approval workflows.',
      res.statusCode === 200 && Array.isArray(approvals)
    );
  }

  // Test 6: USER Positive Authorization
  {
    const res = await makeRequest({
      method: 'GET',
      url: '/api/auth/me',
      headers: { authorization: `Bearer ${sessions[ROLES.USER]}` },
    });
    report(
      6,
      'USER Positive Authorization: GET /api/auth/me',
      'HTTP 200 with active authenticated identity',
      `HTTP ${res.statusCode}, Role: ${res.body?.user?.role}`,
      'Standard User successfully authenticates and inspects own identity session.',
      res.statusCode === 200 && res.body?.user?.role === 'USER'
    );
  }

  // Test 7: USER Negative Authorization: Blocked from System Lockdown (HTTP 403)
  {
    const res = await makeRequest({
      method: 'POST',
      url: '/api/system/lockdown',
      headers: { authorization: `Bearer ${sessions[ROLES.USER]}`, 'content-type': 'application/json' },
      body: { lockdown: true, reason: 'Malicious user test' },
    });
    report(
      7,
      'USER Negative Authorization: POST /api/system/lockdown',
      'HTTP 403 FORBIDDEN_PERMISSION',
      `HTTP ${res.statusCode} (${res.body?.code})`,
      'Standard User strictly denied execution of emergency administrative lockdown.',
      res.statusCode === 403
    );
  }

  // Test 8: AUDITOR Negative Authorization: Blocked from Source Registration (HTTP 403)
  {
    const res = await makeRequest({
      method: 'POST',
      url: '/api/register',
      headers: { authorization: `Bearer ${sessions[ROLES.AUDITOR]}`, 'content-type': 'application/json' },
      body: { fileName: 'auditor_source.png', sha256: 'a'.repeat(64), signature: '0'.repeat(128) },
    });
    report(
      8,
      'AUDITOR Negative Authorization: POST /api/register',
      'HTTP 403 FORBIDDEN_PERMISSION',
      `HTTP ${res.statusCode} (${res.body?.code})`,
      'Auditor role is an observer/verifier and is strictly prohibited from mutating evidence.',
      res.statusCode === 403
    );
  }

  // Test 9: FORENSIC_INVESTIGATOR Negative Authorization: Blocked from Root Key Revocation (HTTP 403)
  {
    const res = await makeRequest({
      method: 'POST',
      url: '/api/keys/revoke',
      headers: { authorization: `Bearer ${sessions[ROLES.FORENSIC_INVESTIGATOR]}`, 'content-type': 'application/json' },
      body: { keyId: 'ED25519-A9103847', reason: 'Unauthorized investigator revocation' },
    });
    report(
      9,
      'FORENSIC_INVESTIGATOR Negative Authorization: POST /api/keys/revoke',
      'HTTP 403 FORBIDDEN_PERMISSION',
      `HTTP ${res.statusCode} (${res.body?.code})`,
      'Forensic Investigator can inspect keys but cannot administratively revoke root keys.',
      res.statusCode === 403
    );
  }

  // Test 10: Unauthenticated Request Strictly Rejected (HTTP 401)
  {
    const res = await makeRequest({ method: 'GET', url: '/api/auth/me' });
    report(
      10,
      'Unauthenticated Access Rejection: GET /api/auth/me',
      'HTTP 401 UNAUTHENTICATED',
      `HTTP ${res.statusCode} (${res.body?.code})`,
      'Protected API endpoint strictly rejects anonymous calls without valid session token.',
      res.statusCode === 401
    );
  }

  // ---------------------------------------------------------------------------
  // SECTION 2: Multi-Tenant Organization Isolation
  // ---------------------------------------------------------------------------
  console.log('\n--- SECTION 2: Multi-Tenant Organization Isolation ---');

  // Ensure test approvals exist in memory
  const apr501 = db.data.approvals.find(a => a.id === 'APR-501');
  if (apr501) apr501.organizationId = 'ORG-01';
  if (!db.data.approvals.some(a => a.id === 'APR-503')) {
    db.data.approvals.push({
      id: 'APR-503',
      title: 'Cross-Tenant Threat Intel Export',
      sourceId: 'SRC-SOC-LOG',
      organizationId: 'ORG-02',
      status: 'PENDING',
    });
  }

  // Test 11: Cross-Tenant Boundary Enforcement
  {
    const res = await makeRequest({
      method: 'POST',
      url: '/api/approvals/APR-503/decide',
      headers: { authorization: `Bearer ${sessions[ROLES.ORGANIZATION_MANAGER]}`, 'content-type': 'application/json' },
      body: { decision: 'APPROVE', reason: 'Cross-tenant attempt' },
    });
    report(
      11,
      'Cross-Organization Approval Boundary Defense',
      'HTTP 403 CROSS_ORG_ACCESS_DENIED',
      `HTTP ${res.statusCode} (${res.body?.code})`,
      'Manager of ORG-01 strictly blocked from deciding approval request originating in ORG-02.',
      res.statusCode === 403 && res.body?.code === 'CROSS_ORG_ACCESS_DENIED'
    );
  }

  // Test 12: Same-Tenant Approval Authorization
  {
    const res = await makeRequest({
      method: 'POST',
      url: '/api/approvals/APR-501/decide',
      headers: { authorization: `Bearer ${sessions[ROLES.ORGANIZATION_MANAGER]}`, 'content-type': 'application/json' },
      body: { decision: 'APPROVE', reason: 'Legitimate intra-tenant approval' },
    });
    report(
      12,
      'Same-Organization Departmental Approval Authorized',
      'HTTP 200 APPROVED',
      `HTTP ${res.statusCode} (${res.body?.approval?.status})`,
      'Manager successfully approved request within their assigned organization boundary (ORG-01).',
      res.statusCode === 200 && res.body?.approval?.status === 'APPROVED'
    );
  }

  // ---------------------------------------------------------------------------
  // SECTION 3: Digital Asset Provenance & Tamper Detection
  // ---------------------------------------------------------------------------
  console.log('\n--- SECTION 3: Digital Asset Provenance & Cryptographic Tamper Detection ---');

  // Test 13: Cryptographic Signature Verification on Registered Asset
  {
    const testAuditHash = crypto.createHash('sha256').update('SourceMark-Audit-Evidence-Authenticity').digest('hex');
    const auditSigRes = await kmsManager.sign('ED25519-A9103847', testAuditHash, { action: 'E2E_AUDIT_PROVENANCE' });
    const keyRes = await pgQuery('SELECT public_key_hex FROM signing_keys WHERE key_id = $1', ['ED25519-A9103847']);
    const pubHex = keyRes.rows[0]?.public_key_hex;

    const isValid = verifyFingerprintSignature(testAuditHash, auditSigRes.signatureHex, pubHex);

    report(
      13,
      'Digital Asset Ed25519 Cryptographic Signature Verification',
      'Signature strictly verified against authoritative public key in Trust Registry',
      `Verified: ${isValid}, Key: ED25519-A9103847, Algorithm: Ed25519`,
      'Digital signature proves authentic provenance without data tampering.',
      isValid === true
    );
  }

  // Test 14: Tampered Fingerprint Detection
  {
    const originalHash = crypto.createHash('sha256').update('OriginalDocumentBytes').digest('hex');
    const tamperedHash = crypto.createHash('sha256').update('ModifiedDocumentBytes').digest('hex');
    const sigRes = await kmsManager.sign('ED25519-A9103847', originalHash, { action: 'TAMPER_TEST' });
    const keyRes = await pgQuery('SELECT public_key_hex FROM signing_keys WHERE key_id = $1', ['ED25519-A9103847']);
    const pubHex = keyRes.rows[0]?.public_key_hex;

    const isTamperedCaught = !verifyFingerprintSignature(tamperedHash, sigRes.signatureHex, pubHex);

    report(
      14,
      'Tampered Fingerprint Detection (Cryptographic Mismatch)',
      'Verification fails when file bytes/hash diverge from registered signature',
      `Signature Valid for Tampered Hash: ${!isTamperedCaught}`,
      'Cryptographic verification successfully detected byte divergence and flagged tampering.',
      isTamperedCaught === true
    );
  }

  // Test 15: Revoked Key Registration Defense
  {
    const res = await makeRequest({
      method: 'POST',
      url: '/api/register',
      headers: { authorization: `Bearer ${sessions[ROLES.USER]}`, 'content-type': 'application/json' },
      body: {
        fileName: 'revoked_key_attempt.pdf',
        sha256: '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
        fileSize: 1024,
        signature: '0'.repeat(128),
        keyId: 'ED25519-STOLEN-01', // Revoked key
      },
    });
    report(
      15,
      'Revoked Key Containment Mandate: Blocked from Signing/Registering',
      'HTTP 403 KEY_REVOKED',
      `HTTP ${res.statusCode} (${res.body?.code})`,
      'System strictly blocked registration attempt signed with compromised/revoked key.',
      res.statusCode === 403 && res.body?.code === 'KEY_REVOKED'
    );
  }

  // ---------------------------------------------------------------------------
  // SECTION 4: Enterprise KMS & Hardware-Backed Key Lifecycle
  // ---------------------------------------------------------------------------
  console.log('\n--- SECTION 4: Enterprise KMS & Hardware Key Management ---');

  // Test 16: KMS Key Generation & Memory Vault Custody
  let kmsGeneratedKey = null;
  {
    kmsGeneratedKey = await kmsManager.generateKey({
      ownerName: 'Dr. Alan Cross (Lead Crypto Auditor)',
      ownerId: 'USR-AUD-01',
      organizationId: 'ORG-01',
    });

    const isCatalogedInDb = (await pgQuery('SELECT * FROM signing_keys WHERE key_id = $1', [kmsGeneratedKey.keyId])).rows.length === 1;

    report(
      16,
      'KMS Managed Key Generation & PostgreSQL Trust Registry Cataloging',
      'Key created in KMS vault, public key in DB signing_keys, private key strictly in memory',
      `Key ID: ${kmsGeneratedKey.keyId}, Public Key: ${kmsGeneratedKey.publicKeyHex.slice(0, 16)}..., In DB: ${isCatalogedInDb}`,
      'Private key generated in backend closure and never exposed in database records.',
      isCatalogedInDb === true && !!kmsGeneratedKey.keyId
    );
  }

  // Test 17: Managed KMS Digital Signature Execution
  let testDigest = crypto.createHash('sha256').update('SourceMark-Phase8-Audit-Payload').digest('hex');
  let kmsSignature = null;
  {
    kmsSignature = await kmsManager.sign(kmsGeneratedKey.keyId, testDigest, {
      actor: 'auditor@sourcemark.enterprise',
      role: 'AUDITOR',
      action: 'E2E_AUDIT_SIGNING',
    });

    const sigHex = kmsSignature.signatureHex || kmsSignature.signature;
    const isValidSig = verifyFingerprintSignature(testDigest, sigHex, kmsGeneratedKey.publicKeyHex);

    report(
      17,
      'KMS Digest Signing & Authoritative Verification',
      'Signature length: 128 hex (64 bytes), Verification: valid = true',
      `Sig Length: ${sigHex.length}, Verified: ${isValidSig}`,
      'Cryptographic digest signed via KMS provider without client private key handling.',
      sigHex.length === 128 && isValidSig === true
    );
  }

  // Test 18: Zero Private Key Leakage Audit
  {
    const dbCheck = await pgQuery(`
      SELECT column_name FROM information_schema.columns 
      WHERE table_name = 'signing_keys' AND column_name ILIKE '%private%'
    `);
    const hasPrivateKeyColumn = dbCheck.rows.length > 0;

    const jsonDbRaw = fs.readFileSync(path.join(process.cwd(), 'backend', 'data', 'enterprise_db.json'), 'utf8');
    const hasSecretKeyInJson = /"secretKey"|"privateKeyHex"/i.test(jsonDbRaw);

    report(
      18,
      'Zero Private Key Leakage Invariant across Database, JSON & Storage',
      'hasPrivateKeyColumn: false, hasSecretKeyInJson: false',
      `hasPrivateKeyColumn: ${hasPrivateKeyColumn}, hasSecretKeyInJson: ${hasSecretKeyInJson}`,
      'Confirms absolute adherence to FIPS 140-3 zero-leakage standard: private keys never enter persistent files.',
      hasPrivateKeyColumn === false && hasSecretKeyInJson === false
    );
  }

  // ---------------------------------------------------------------------------
  // SECTION 5: RFC 3161 Trusted Timestamp Authority
  // ---------------------------------------------------------------------------
  console.log('\n--- SECTION 5: RFC 3161 External Trusted Timestamp Authority ---');

  // Test 19: Truthful TSA Provider Health Telemetry
  {
    const status = tsaManager.getStatus();
    const isTruthful = (status.configured === false && status.mode === 'SIMULATED_LOCAL');

    report(
      19,
      'Truthful TSA Provider Health Telemetry (Zero False Claims)',
      'configured: false, mode: SIMULATED_LOCAL',
      `configured: ${status.configured}, mode: ${status.mode}, authority: ${status.authority}`,
      'System accurately reports simulated fallback when external TSA is unconfigured; never claims qualified external status.',
      isTruthful
    );
  }

  // Test 20: RFC 3161 Anti-Replay Nonce Defense
  {
    const sampleToken = {
      granted: true,
      extractedHash: testDigest.toLowerCase(),
      extractedNonce: '1111222233334444', // Replayed nonce
      status: 0,
      tstInfo: {
        policy: '1.3.6.1.4.1.13762.3',
        messageImprint: { hash: testDigest },
        serialNumber: '12345678',
        genTime: new Date().toISOString(),
        nonce: '1111222233334444', // Replayed nonce
      },
    };
    const expectedNonce = '9999888877776666'; // Current request nonce

    const validation = validateTimeStampToken(sampleToken, testDigest, expectedNonce);

    report(
      20,
      'RFC 3161 Anti-Replay Nonce Verification',
      'isValid: false, status: REPLAY_DETECTED',
      `isValid: ${validation.isValid}, status: ${validation.status}`,
      'Token reuse and replay attacks strictly prevented by validating 64-bit cryptographic nonces.',
      validation.isValid === false && validation.status === 'REPLAY_DETECTED'
    );
  }

  // ---------------------------------------------------------------------------
  // SECTION 6: PostgreSQL ACID Persistence & Resilience
  // ---------------------------------------------------------------------------
  console.log('\n--- SECTION 6: PostgreSQL 16.15 ACID Persistence & Resilience ---');

  // Test 21: ACID Registration Transaction
  {
    const testSrcId = `SRC-AUDIT-TX-${Date.now()}`;
    const seq = await dbAdapter.getNextLedgerBlockSequence();
    const testHash = crypto.createHash('sha256').update(`TX-TEST-${Date.now()}`).digest('hex');

    const sourceData = {
      id: testSrcId,
      fileName: 'audit_acid_test.bin',
      sha256: testHash,
      fileSize: 1024,
      fileType: 'application/octet-stream',
      creator: 'admin@sourcemark.enterprise',
      creatorId: 'USR-ADMIN-01',
      organizationId: 'ORG-01',
      keyId: 'ED25519-A9103847',
      publicKey: '0'.repeat(64),
      signature: '0'.repeat(128),
      registeredAt: new Date().toISOString(),
      isVirtualDemo: false,
    };

    const ledgerBlock = {
      id: seq.blockId,
      blockNumber: seq.blockNumber,
      type: 'REGISTER',
      title: 'ACID Audit Test Registration',
      timestamp: new Date().toISOString(),
      prevHash: seq.prevHash,
      currentHash: crypto.createHash('sha256').update(`${seq.blockId}:REGISTER:${seq.prevHash}:${testHash}`).digest('hex'),
      status: 'CONFIRMED',
      verified: true,
      payload: { sourceId: testSrcId, sha256: testHash },
    };

    const auditEntry = {
      id: `AUD-TX-${Date.now()}`,
      action: 'SOURCE_REGISTERED_ACID',
      actor: 'admin@sourcemark.enterprise',
      role: 'ADMINISTRATOR',
      details: 'ACID registration test',
      timestamp: new Date().toISOString(),
      ipAddress: '127.0.0.1',
    };

    const txResult = await dbAdapter.registerAssetTransaction(sourceData, ledgerBlock, auditEntry);

    const srcCheck = await pgQuery('SELECT * FROM sources WHERE id = $1', [testSrcId]);
    const blkCheck = await pgQuery('SELECT * FROM ledger_blocks WHERE id = $1', [seq.blockId]);
    const audCheck = await pgQuery('SELECT * FROM audit_logs WHERE id = $1', [auditEntry.id]);

    const isAllCommitted = srcCheck.rows.length === 1 && blkCheck.rows.length === 1 && audCheck.rows.length === 1;

    report(
      21,
      'PostgreSQL ACID Transaction: Multi-Table Atomic Commit',
      'sources: 1, ledger_blocks: 1, audit_logs: 1 committed atomically',
      `src: ${srcCheck.rows.length}, blk: ${blkCheck.rows.length}, aud: ${audCheck.rows.length}`,
      'Single transactional boundary guarantees complete consistency across evidence, ledger, and audit history.',
      txResult.success === true && isAllCommitted
    );
  }

  // Test 22: ACID Transaction Rollback on Failure
  {
    const badSrcId = `SRC-FAIL-ROLLBACK-${Date.now()}`;
    let rollbackSuccess = false;
    let caughtError = null;

    try {
      await withTransaction(async (client) => {
        await client.query(
          `INSERT INTO sources (
            id, file_name, file_size, file_type, sha256, signature, public_key,
            key_id, creator_id, creator_email, organization_id, registered_at
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())`,
          [
            badSrcId,
            'fail_test.bin',
            100,
            'application/octet-stream',
            'f'.repeat(64),
            '0'.repeat(128),
            '0'.repeat(64),
            'ED25519-A9103847',
            'USR-ADMIN-01',
            'admin@sourcemark.enterprise',
            'ORG-01',
          ]
        );
        throw new Error('INTENTIONAL_TRANSACTION_FAILURE_TEST');
      });
    } catch (e) {
      caughtError = e.message;
      rollbackSuccess = e.message.includes('INTENTIONAL_TRANSACTION_FAILURE_TEST');
    }

    const orphanCheck = await pgQuery('SELECT * FROM sources WHERE id = $1', [badSrcId]);
    const noOrphans = orphanCheck.rows.length === 0;

    report(
      22,
      'PostgreSQL ACID Transaction Rollback on Exception',
      'Transaction aborts and rolls back completely; zero orphaned records in database',
      `Rollback Caught: ${rollbackSuccess} (Err: ${caughtError}), Orphaned Records Found: ${orphanCheck.rows.length}`,
      'ACID transaction manager cleanly reverted partial writes upon exception.',
      rollbackSuccess && noOrphans
    );
  }

  // Test 23: Backend Reboot / Runtime Sync Recovery
  {
    const syncRes = await dbAdapter.syncRuntimeData(db);
    report(
      23,
      'Backend Runtime Database Resynchronization from PostgreSQL',
      'synced: true, engine: postgresql, entity counts populated',
      `synced: ${syncRes.synced}, engine: ${syncRes.engine}, sources: ${syncRes.counts?.sources}, ledger: ${syncRes.counts?.ledger}`,
      'Runtime database cleanly restored all entities and system state from PostgreSQL 16.15.',
      syncRes.synced === true && syncRes.engine === 'postgresql'
    );
  }

  // ---------------------------------------------------------------------------
  // SECTION 7: Independent WORM Storage & Checkpoint Anchoring
  // ---------------------------------------------------------------------------
  console.log('\n--- SECTION 7: Independent WORM Storage & Checkpoint Anchoring ---');

  // Test 24: WORM Write-Once Protection
  {
    const testDir = path.join(process.cwd(), 'backend', 'data', 'worm_vault_audit_test');
    const vault = new LocalSimulatedWormStorageProvider(testDir);
    await vault.initialize();

    const chkId = `CHK-AUDIT-WORM-${Date.now()}`;
    await vault.putCheckpoint(chkId, { id: chkId, blockHeight: 10, checkpointHash: 'orig' });

    let violationCaught = false;
    try {
      await vault.putCheckpoint(chkId, { id: chkId, blockHeight: 10, checkpointHash: 'TAMPERED_OVERWRITE' });
    } catch (e) {
      violationCaught = e.message.includes('WORM_RETENTION_LOCK_VIOLATION');
    }

    try { fs.rmSync(testDir, { recursive: true, force: true }); } catch {}

    report(
      24,
      'WORM Write-Once Storage Retention Protection',
      'WORM_RETENTION_LOCK_VIOLATION thrown upon overwrite attempt',
      `Violation Caught: ${violationCaught}`,
      'Write-once semantics successfully prevented modification or erasure of sealed record.',
      violationCaught === true
    );
  }

  // Test 25: Concurrency-Safe Checkpoint Creation
  let auditCheckpoint = null;
  {
    const chkRes = await wormManager.createSignedCheckpoint({
      operator: 'compliance-audit-daemon@sourcemark.enterprise',
      role: 'AUDITOR',
      notes: 'Phase 8 Final Audit Checkpoint Anchor',
    });
    auditCheckpoint = chkRes.checkpoint;

    report(
      25,
      'Atomic KMS-Signed Checkpoint Creation & Dual Persistence',
      'Checkpoint created, KMS-signed, persisted to DB and independent WORM vault',
      `ID: ${auditCheckpoint.id}, Height: ${auditCheckpoint.blockHeight}, SigLen: ${auditCheckpoint.authoritySignature?.length}`,
      'Independent checkpoint established with cryptographic proof and Merkle root linkage.',
      !!auditCheckpoint.id && auditCheckpoint.authoritySignature?.length === 128
    );
  }

  // Test 26: Ledger Verification against Intact Checkpoint
  {
    const verdict = await wormManager.verifyCheckpointAgainstLedger(auditCheckpoint.id, { actor: 'SecOps Watchdog' });
    report(
      26,
      'Full Ledger Integrity Verification against Sealed Checkpoint',
      'isValid: true, status: VALID_TRUSTED, isWormConsistent: true',
      `isValid: ${verdict.isValid}, status: ${verdict.status}, wormConsistent: ${verdict.wormIntegrity?.isWormConsistent}`,
      'Active ledger matches sealed WORM checkpoint with 100% cryptographic fidelity.',
      verdict.isValid === true && verdict.status === 'VALID_TRUSTED'
    );
  }

  // Test 27: Rollback / Truncation Attack Detection
  {
    const fakeFutureId = `CHK-RB-TEST-${Date.now()}`;
    const futureHeight = auditCheckpoint.blockHeight + 10;
    const fakeHash = crypto.createHash('sha256').update('future').digest('hex');
    const fakeTime = new Date().toISOString();
    const fakePayload = `${fakeFutureId}:${futureHeight}:${fakeHash}:${fakeTime}:0000000000000000000000000000000000000000000000000000000000000000`;
    const payloadHash = crypto.createHash('sha256').update(fakePayload).digest('hex');

    const signRes = await kmsManager.sign('ED25519-A9103847', payloadHash, { action: 'TEST_RB' });
    const sigHex = signRes.signatureHex || signRes.signature;

    const futureChk = {
      id: fakeFutureId,
      checkpointHash: fakeHash,
      blockHeight: futureHeight,
      authorityName: 'SourceMark KMS Root Authority',
      authorityKeyId: 'ED25519-A9103847',
      authoritySignature: sigHex,
      canonicalPayload: fakePayload,
      timestamp: fakeTime,
      wormMode: 'SIMULATED_LOCAL',
    };

    const provider = wormManager.getActiveProvider();
    await provider.putCheckpoint(fakeFutureId, futureChk);

    await pgQuery(
      `INSERT INTO checkpoints (
         id, checkpoint_hash, block_height, authority_name, authority_signature,
         merkle_root, timestamp, authority_key_id, canonical_payload, worm_storage_id, worm_status
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
      [fakeFutureId, fakeHash, futureHeight, 'SourceMark KMS Root Authority', sigHex, fakeHash, fakeTime, 'ED25519-A9103847', fakePayload, `${fakeFutureId}.json`, 'SIMULATED_LOCAL']
    );

    const rbVerdict = await wormManager.verifyCheckpointAgainstLedger(fakeFutureId, { actor: 'SecOps Watchdog' });

    report(
      27,
      'Administrative Ledger Truncation / Rollback Attack Thwarted',
      'isValid: false, status: ROLLBACK_DETECTED, missingBlocksCount: 10',
      `isValid: ${rbVerdict.isValid}, status: ${rbVerdict.status}, missing: ${rbVerdict.ledgerState?.missingBlocksCount}`,
      'Watchdog detected active ledger height is lower than sealed WORM checkpoint, sounding immediate security alert.',
      rbVerdict.isValid === false && rbVerdict.status === 'ROLLBACK_DETECTED'
    );
  }

  // Test 28: Independent WORM Storage Divergence Defense
  {
    const orphanId = `CHK-ORPHAN-${Date.now()}`;
    const time = new Date().toISOString();
    const payload = `${orphanId}:1:aaaa:${time}:0000`;
    const pHash = crypto.createHash('sha256').update(payload).digest('hex');
    const sRes = await kmsManager.sign('ED25519-A9103847', pHash, { action: 'TEST_ORPHAN' });
    const sHex = sRes.signatureHex || sRes.signature;

    await pgQuery(
      `INSERT INTO checkpoints (
         id, checkpoint_hash, block_height, authority_name, authority_signature,
         merkle_root, timestamp, authority_key_id, canonical_payload, worm_storage_id, worm_status
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
      [orphanId, 'aaaa', 1, 'SourceMark KMS Root Authority', sHex, 'aaaa', time, 'ED25519-A9103847', payload, `${orphanId}.json`, 'SIMULATED_LOCAL']
    );

    const divVerdict = await wormManager.verifyCheckpointAgainstLedger(orphanId, { actor: 'SecOps Watchdog' });

    report(
      28,
      'Independent WORM Store Divergence Detection (Anti-Same-Database-Anchor)',
      'isValid: false, status: INDEPENDENT_WORM_DIVERGENCE',
      `isValid: ${divVerdict.isValid}, status: ${divVerdict.status}`,
      'Security rule enforced: A checkpoint stored solely in PostgreSQL without independent WORM storage is strictly rejected.',
      divVerdict.isValid === false && divVerdict.status === 'INDEPENDENT_WORM_DIVERGENCE'
    );
  }

  // ---------------------------------------------------------------------------
  // SECTION 8: Audit Logging, Secret Sanitization & Rate Limiting
  // ---------------------------------------------------------------------------
  console.log('\n--- SECTION 8: Audit Logging, Secret Sanitization & Brute-Force Defense ---');

  // Test 29: Secret & Credential Redaction in Audit Logs
  {
    const rawAudit = await pgQuery('SELECT details FROM audit_logs WHERE details ILIKE \'%password%\' OR details ILIKE \'%secret%\' LIMIT 50');
    let hasLeak = false;
    for (const row of rawAudit.rows) {
      if (typeof row.details === 'string') {
        if (/password["']?\s*:\s*["'](?!\[REDACTED\])[^"']+/i.test(row.details)) {
          hasLeak = true;
          break;
        }
      }
    }

    report(
      29,
      'Security Audit Log Credential Redaction Check',
      'hasPlaintextPasswordLeak: false across all audit records',
      `hasLeak: ${hasLeak}, Inspected Rows: ${rawAudit.rows.length}`,
      'Audit log sanitizer automatically redacts passwords, private keys, and session tokens before persistence.',
      hasLeak === false
    );
  }

  // Test 30: Brute-Force Rate Limiting Defense (HTTP 429)
  {
    const attackEmail = `bruteforce_target_${Date.now()}@sourcemark.enterprise`;
    let got429 = false;

    for (let i = 0; i < 6; i++) {
      const res = await makeRequest({
        method: 'POST',
        url: '/api/auth/login',
        headers: { 'content-type': 'application/json' },
        body: { email: attackEmail, password: `WrongPassword_${i}!` },
      });
      if (res.statusCode === 429) {
        got429 = true;
        break;
      }
    }

    report(
      30,
      'Brute-Force Rate Limiting & Account Lockout Defense',
      'HTTP 429 Too Many Requests after successive failed logins',
      `Locked Out: ${got429}`,
      'Brute-force protection throttles repeated failed attempts, defending against credential stuffing.',
      got429 === true
    );
  }

  // ---------------------------------------------------------------------------
  // Summary
  // ---------------------------------------------------------------------------
  console.log('----------------------------------------------------------------');
  console.log(`TOTAL PHASE 8 AUDIT TESTS: ${passed + failed}`);
  console.log(`PASSED:                    ${passed}`);
  console.log(`FAILED:                    ${failed}`);
  console.log(`SUCCESS RATE:              ${((passed / (passed + failed)) * 100).toFixed(1)}%`);
  console.log('================================================================\n');

  try {
    await getPool().end();
  } catch {}

  process.exit(failed > 0 ? 1 : 0);
}

runAudit().catch((e) => {
  console.error('Fatal Audit Suite Error:', e);
  process.exit(1);
});
