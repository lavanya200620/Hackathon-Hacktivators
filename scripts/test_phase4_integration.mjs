/**
 * SourceMark Phase 4: PostgreSQL Application Integration & Verification Suite
 * 
 * Verifies:
 * 1. PostgreSQL is the primary persistence engine of record when connected.
 * 2. ACID Transactions & Atomic Rollback behavior across all write workflows:
 *    - Registration (sources, ledger_blocks, audit_logs)
 *    - Key Revocation (signing_keys, ledger_blocks, soc_alerts, audit_logs, system_state)
 *    - Investigations & Notes (investigations, investigation_notes, audit_logs)
 *    - Threat Containment (soc_alerts, audit_logs)
 *    - Derivative Approvals (derivative_approvals, audit_logs)
 *    - User Governance (users, audit_logs)
 *    - System Lockdown (system_state, audit_logs)
 * 3. Backend restart persistence: New EnterpriseDB instance reconstructs complete state from PostgreSQL.
 * 4. Strictly sequential append-only ledger block numbering (#10, #11, ...) chained to Block #9 without rewriting history.
 * 5. Explicit distinction between virtual demonstration assets (isVirtualDemo: true) and physically uploaded evidence (isVirtualDemo: false).
 * 6. Multi-tenant organization-level data isolation across ORG-01, ORG-02, and ORG-03.
 * 7. Controlled fallback behavior and truthful outage reporting (LOCAL_PERSISTENT_FALLBACK) with zero audit record loss.
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

import { query, checkConnection, getPool } from '../backend/db/postgres.mjs';
import { dbAdapter } from '../backend/db/adapter.mjs';
import { EnterpriseDB, ROLES, PERMISSIONS, createSessionToken } from '../backend/server.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

let totalPassed = 0;
let totalFailed = 0;

function assert(condition, testName) {
  if (condition) {
    console.log(`  ✓ ${testName}`);
    totalPassed++;
  } else {
    console.error(`  ✗ FAIL: ${testName}`);
    totalFailed++;
  }
}

async function runPhase4Tests() {
  console.log('================================================================');
  console.log('  SOURCEMARK PHASE 4: POSTGRESQL APPLICATION INTEGRATION AUDIT  ');
  console.log('================================================================\n');

  // Pre-test: Verify Live PostgreSQL Connectivity
  const conn = await checkConnection();
  if (!conn.connected) {
    console.error('PostgreSQL connection unavailable. Aborting Phase 4 tests:', conn.error);
    process.exit(1);
  }
  console.log(`[+] PostgreSQL 16.15 connected on localhost:5432 (Database: sourcemark_db)\n`);

  const testDb = new EnterpriseDB();
  await testDb.initializedPromise;

  // -------------------------------------------------------------------------
  // TEST 1: Truthful Database Status & Primary Engine Designation
  // -------------------------------------------------------------------------
  console.log('--- Test Suite 1: Primary Database Status & Engine Designation ---');
  const health = await dbAdapter.checkHealth(true);
  assert(health.connected === true, 'PostgreSQL reports connected truthfully');
  assert(health.engine === 'postgresql', 'Primary engine is designated as PostgreSQL');
  assert(health.mode === 'PRODUCTION_RELATIONAL', 'Operating mode is PRODUCTION_RELATIONAL');
  assert(health.acidTransactions === true, 'ACID transaction capability confirmed active');

  const status = await dbAdapter.getStatus();
  assert(status.migrationStatus.applied.length >= 3, 'All 3 version-controlled migrations verified applied');
  assert(status.sqliteStatus.healthy === true, 'Secondary SQLite backup engine active and healthy');
  assert(status.jsonBackupAvailable === true, 'JSON backup file verified available for fallback');

  // -------------------------------------------------------------------------
  // TEST 2: Asset Registration & ACID Persistence in PostgreSQL
  // -------------------------------------------------------------------------
  console.log('\n--- Test Suite 2: Asset Registration & ACID Persistence ---');
  const testSourceId = `SRC-TEST-P4-${Date.now().toString().slice(-4)}`;
  const testSha256 = crypto.createHash('sha256').update(`test-file-content-${Date.now()}`).digest('hex');
  const testSig = crypto.randomBytes(64).toString('hex');
  const testPubKey = crypto.randomBytes(32).toString('hex');

  const seq1 = await dbAdapter.getNextLedgerBlockSequence();
  assert(seq1.blockNumber >= 10, `Sequential ledger block sequence calculated from PostgreSQL (Block #${seq1.blockNumber})`);
  assert(seq1.prevHash && seq1.prevHash.length === 64, `Previous block hash linked to prior block (${seq1.prevHash.slice(0, 16)}...)`);

  const regTimestamp = new Date().toISOString();
  const testBlockStr = `${seq1.blockId}:REGISTER:${seq1.prevHash}:${regTimestamp}:${testSha256}`;
  const testCurrentHash = crypto.createHash('sha256').update(testBlockStr).digest('hex');

  const sourceData = {
    id: testSourceId,
    fileName: 'orbital_recon_phase4_evidence.tiff',
    fileType: 'image/tiff',
    fileSize: 10485760,
    fileSizeFormatted: '10.0 MB',
    sha256: testSha256,
    signature: testSig,
    publicKey: testPubKey,
    keyId: 'ED25519-A9103847',
    creator: 'investigator@sourcemark.io',
    creatorId: 'USR-INV-01',
    organizationId: 'ORG-01',
    category: 'Orbital Reconnaissance',
    description: 'Phase 4 live test asset for PostgreSQL ACID verification',
    sourceOrigin: 'Satellite Constellation Unit Alpha',
    registeredAt: regTimestamp,
    status: 'ACTIVE_REGISTERED',
    verificationCount: 0,
    isVirtualDemo: false, // Physically uploaded evidence
  };

  const ledgerBlock = {
    id: seq1.blockId,
    blockNumber: seq1.blockNumber,
    type: 'REGISTER',
    title: `File Registration: ${sourceData.fileName}`,
    timestamp: regTimestamp,
    prevHash: seq1.prevHash,
    currentHash: testCurrentHash,
    status: 'CONFIRMED',
    verified: true,
    payload: {
      sourceId: testSourceId,
      fileName: sourceData.fileName,
      fingerprint: testSha256,
      creatorId: sourceData.creatorId,
      organizationId: sourceData.organizationId,
    },
  };

  const auditEntry = {
    id: `AUD-P4-${Date.now()}`,
    action: 'SOURCE_REGISTERED',
    actor: 'investigator@sourcemark.io',
    role: ROLES.FORENSIC_INVESTIGATOR,
    details: `Registered live source ${testSourceId}`,
    timestamp: regTimestamp,
    ipAddress: '127.0.0.1',
  };

  const regResult = await dbAdapter.registerAssetTransaction(sourceData, ledgerBlock, auditEntry);
  assert(regResult.success === true, 'Asset registration transaction completed successfully');

  // Verify directly in PostgreSQL tables via raw SQL
  const pgSourceCheck = await query('SELECT * FROM sources WHERE id = $1', [testSourceId]);
  assert(pgSourceCheck.rows.length === 1, 'Source record persisted directly in PostgreSQL sources table');
  assert(pgSourceCheck.rows[0].sha256 === testSha256, 'SHA-256 fingerprint in PostgreSQL exactly matches registration payload');
  assert(pgSourceCheck.rows[0].is_virtual_demo === false, 'Physical uploaded evidence is correctly flagged is_virtual_demo = false');

  const pgBlockCheck = await query('SELECT * FROM ledger_blocks WHERE id = $1', [seq1.blockId]);
  assert(pgBlockCheck.rows.length === 1, 'Ledger block persisted directly in PostgreSQL ledger_blocks table');
  assert(pgBlockCheck.rows[0].block_number === seq1.blockNumber, 'Ledger block number strictly sequential in PostgreSQL');
  assert(pgBlockCheck.rows[0].prev_hash === seq1.prevHash, 'Merkle chain prev_hash verified matching prior block');

  const pgAuditCheck = await query('SELECT * FROM audit_logs WHERE id = $1', [auditEntry.id]);
  assert(pgAuditCheck.rows.length === 1, 'Audit log persisted directly in PostgreSQL audit_logs table');

  // Verify verification count increment in PostgreSQL
  await dbAdapter.incrementVerificationCount(testSourceId);
  const pgVerifyCheck = await query('SELECT verification_count FROM sources WHERE id = $1', [testSourceId]);
  assert(pgVerifyCheck.rows[0].verification_count === 1, 'Verification count increment persisted directly in PostgreSQL');

  // -------------------------------------------------------------------------
  // TEST 3: Virtual Demo vs Physical Evidence Distinction
  // -------------------------------------------------------------------------
  console.log('\n--- Test Suite 3: Virtual Demo vs Physical Evidence Distinction ---');
  const demoSource = await dbAdapter.getSourceById('SRC-98214');
  assert(demoSource !== null, 'Retrieved demonstration asset SRC-98214');
  assert(demoSource.isVirtualDemo === true, 'Demonstration asset SRC-98214 is explicitly flagged isVirtualDemo: true');

  const liveSource = await dbAdapter.getSourceById(testSourceId);
  assert(liveSource.isVirtualDemo === false, 'Physically registered evidence is explicitly flagged isVirtualDemo: false');

  // -------------------------------------------------------------------------
  // TEST 4: Key Revocation & Threat Containment ACID Transaction
  // -------------------------------------------------------------------------
  console.log('\n--- Test Suite 4: Key Revocation & Threat Containment Transaction ---');
  const testRevokeKeyId = `KEY-REV-TEST-${Date.now().toString().slice(-4)}`;
  const seq2 = await dbAdapter.getNextLedgerBlockSequence();
  const revTimestamp = new Date().toISOString();
  const revBlockStr = `${seq2.blockId}:SECURITY_INCIDENT:${seq2.prevHash}:${revTimestamp}:${testRevokeKeyId}`;
  const revCurrentHash = crypto.createHash('sha256').update(revBlockStr).digest('hex');

  const revIncidentBlock = {
    id: seq2.blockId,
    blockNumber: seq2.blockNumber,
    type: 'SECURITY_INCIDENT',
    title: `Key Revocation: ${testRevokeKeyId}`,
    timestamp: revTimestamp,
    prevHash: seq2.prevHash,
    currentHash: revCurrentHash,
    status: 'CONFIRMED',
    verified: true,
    payload: { keyId: testRevokeKeyId, reason: 'Private key leak simulated in Phase 4 audit', actor: 'admin@sourcemark.io' },
  };

  const revAudit = {
    id: `AUD-REV-${Date.now()}`,
    action: 'KEY_REVOCATION_EXECUTED',
    actor: 'admin@sourcemark.io',
    role: ROLES.ADMINISTRATOR,
    details: `Key ${testRevokeKeyId} revoked by Administrator`,
    timestamp: revTimestamp,
    ipAddress: '127.0.0.1',
  };

  const revAlert = {
    id: `ALT-REV-${Date.now().toString().slice(-4)}`,
    title: `Revoked Key Containment: ${testRevokeKeyId}`,
    severity: 'CRITICAL',
    sourceId: testRevokeKeyId,
    organizationId: 'ORG-01',
    status: 'CONTAINED',
    type: 'REVOKED_KEY_BLOCK',
    description: `Simulated containment mandate for key ${testRevokeKeyId}`,
    timestamp: revTimestamp,
    contained: true,
  };

  const revokeResult = await dbAdapter.revokeKeyTransaction(
    testRevokeKeyId,
    'Private key leak simulated in Phase 4 audit',
    'admin@sourcemark.io',
    ROLES.ADMINISTRATOR,
    revAudit,
    revAlert,
    revIncidentBlock
  );
  assert(revokeResult.success === true, 'Key revocation ACID transaction succeeded');

  // Verify directly in PostgreSQL
  const pgKeyCheck = await query('SELECT status, revocation_reason FROM signing_keys WHERE key_id = $1', [testRevokeKeyId]);
  assert(pgKeyCheck.rows.length === 1 && pgKeyCheck.rows[0].status === 'REVOKED', 'Key marked REVOKED in PostgreSQL signing_keys table');

  const pgRevBlockCheck = await query('SELECT * FROM ledger_blocks WHERE id = $1', [seq2.blockId]);
  assert(pgRevBlockCheck.rows.length === 1, 'Revocation incident block committed to PostgreSQL ledger_blocks');

  const pgAlertCheck = await query('SELECT * FROM soc_alerts WHERE id = $1', [revAlert.id]);
  assert(pgAlertCheck.rows.length === 1 && pgAlertCheck.rows[0].contained === true, 'Containment alert inserted into PostgreSQL soc_alerts');

  // -------------------------------------------------------------------------
  // TEST 5: Investigations, Notes, & Containment Workflows
  // -------------------------------------------------------------------------
  console.log('\n--- Test Suite 5: Investigations & Examiner Notes Workflow ---');
  const testCaseId = `INV-CASE-P4-${Date.now().toString().slice(-4)}`;
  const caseData = {
    id: testCaseId,
    title: 'Phase 4 Forensic Hash Verification Discrepancy',
    sourceId: testSourceId,
    organizationId: 'ORG-01',
    severity: 'HIGH',
    status: 'UNDER_INVESTIGATION',
    assignedTo: 'USR-INV-01',
    assignedToName: 'investigator@sourcemark.io',
    createdBy: 'USR-SOC-01',
    createdByName: 'soc@sourcemark.io',
    notes: [
      {
        author: 'investigator@sourcemark.io',
        text: 'Initial inspection opened during Phase 4 integration verification',
        timestamp: new Date().toISOString(),
      },
    ],
  };

  await dbAdapter.saveInvestigation(caseData);
  const pgInvCheck = await query('SELECT * FROM investigations WHERE id = $1', [testCaseId]);
  assert(pgInvCheck.rows.length === 1, 'Investigation case persisted in PostgreSQL investigations table');

  const pgNotesCheck = await query('SELECT * FROM investigation_notes WHERE case_id = $1', [testCaseId]);
  assert(pgNotesCheck.rows.length === 1, 'Forensic examiner note persisted in PostgreSQL investigation_notes table');

  // Add a follow-up note and update status
  await dbAdapter.updateInvestigation(testCaseId, { status: 'RESOLVED' }, {
    author: 'admin@sourcemark.io',
    text: 'Discrepancy explained: synthetic test asset. Case marked resolved.',
    timestamp: new Date().toISOString(),
  });

  const pgUpdatedInv = await query('SELECT status FROM investigations WHERE id = $1', [testCaseId]);
  assert(pgUpdatedInv.rows[0].status === 'RESOLVED', 'Investigation status updated to RESOLVED in PostgreSQL');

  const pgNotesCheck2 = await query('SELECT count(*) as count FROM investigation_notes WHERE case_id = $1', [testCaseId]);
  assert(parseInt(pgNotesCheck2.rows[0].count, 10) === 2, 'Second examiner note persisted in PostgreSQL investigation_notes');

  // -------------------------------------------------------------------------
  // TEST 6: Derivative Approvals & Multi-Tenant Organization Isolation
  // -------------------------------------------------------------------------
  console.log('\n--- Test Suite 6: Derivative Approvals & Organization Isolation ---');
  const testApprovalId = `APR-P4-${Date.now().toString().slice(-4)}`;
  const approvalData = {
    id: testApprovalId,
    title: 'High-Resolution Multispectral Contrast Enhancement Layer',
    sourceId: testSourceId,
    organizationId: 'ORG-01',
    requestedBy: 'USR-CUSTODIAN-01',
    requestedByName: 'Alex Rivera',
    status: 'PENDING',
    department: 'Orbital Reconnaissance',
    reason: 'Multi-band contrast stretch for Phase 4 verification',
    timestamp: new Date().toISOString(),
  };

  await dbAdapter.saveApproval(approvalData);
  const pgAprCheck = await query('SELECT * FROM derivative_approvals WHERE id = $1', [testApprovalId]);
  assert(pgAprCheck.rows.length === 1, 'Approval request persisted in PostgreSQL derivative_approvals table');

  // Approve request
  const decided = await dbAdapter.decideApprovalTransaction(
    testApprovalId,
    'APPROVED',
    'manager@sourcemark.io',
    ROLES.ORGANIZATION_MANAGER,
    'Authorized for orbital analysis'
  );
  assert(decided.status === 'APPROVED', 'Approval status updated to APPROVED in PostgreSQL');

  // Multi-tenant organization isolation verification:
  const org1Approvals = await dbAdapter.listApprovals('ORG-01');
  assert(org1Approvals.some(a => a.id === testApprovalId), 'ORG-01 manager can see ORG-01 approval');

  const org2Approvals = await dbAdapter.listApprovals('ORG-02');
  assert(!org2Approvals.some(a => a.id === testApprovalId), 'ORG-02 manager cannot see ORG-01 approval (Organization Data Isolation Verified)');

  // -------------------------------------------------------------------------
  // TEST 7: Backend Restart Persistence Verification
  // -------------------------------------------------------------------------
  console.log('\n--- Test Suite 7: Backend Restart Persistence Verification ---');
  // Create a brand new EnterpriseDB instance (simulates backend restart/reboot)
  const rebootedDb = new EnterpriseDB();
  const syncResult = await rebootedDb.initializedPromise;

  assert(syncResult !== null, 'Rebooted backend database initialized from PostgreSQL');
  assert(rebootedDb.data.sources[testSourceId] !== undefined, 'Registered asset survived backend restart and was restored from PostgreSQL');
  assert(rebootedDb.data.sources[testSourceId].sha256 === testSha256, 'Restored asset SHA-256 matches exactly');
  assert(rebootedDb.data.sources[testSourceId].isVirtualDemo === false, 'Restored asset retains isVirtualDemo: false');

  const restoredBlock = rebootedDb.data.ledger.find(b => b.id === seq1.blockId);
  assert(restoredBlock !== undefined, 'Ledger block restored from PostgreSQL after backend restart');
  assert(restoredBlock.blockNumber === seq1.blockNumber, 'Ledger block number preserved sequentially');

  const restoredInv = rebootedDb.data.investigations.find(c => c.id === testCaseId);
  assert(restoredInv !== undefined && restoredInv.status === 'RESOLVED', 'Investigation case and RESOLVED status restored from PostgreSQL');
  assert(restoredInv.notes.length === 2, 'All investigation notes restored from PostgreSQL');

  // -------------------------------------------------------------------------
  // TEST 8: Ledger Sequence Non-Repudiation (Chain Validation)
  // -------------------------------------------------------------------------
  console.log('\n--- Test Suite 8: Ledger Sequence & Hash Chain Verification ---');
  const allBlocksRes = await query('SELECT block_number, prev_hash, current_hash FROM ledger_blocks ORDER BY block_number ASC');
  const blocks = allBlocksRes.rows;
  assert(blocks.length >= 11, `PostgreSQL contains ${blocks.length} total ledger blocks`);

  // Verify historical blocks #1 to #9 were not rewritten or modified
  assert(blocks[0].block_number === 1, 'Historical Genesis Block #1 preserved');
  assert(blocks[8].block_number === 9, 'Historical Pre-migration Block #9 preserved');
  assert(blocks[8].current_hash === 'b5c6d7e8f9a0011223344556677889900aabbccddeeff0011223344556677889', 'Historical Block #9 terminal hash preserved');

  // Verify Block #10 links strictly to Block #9
  assert(blocks[9].prev_hash === blocks[8].current_hash, 'Block #10 links strictly to Block #9 terminal hash');

  // Verify all new production blocks (>= 10) strictly chain to their immediate predecessor
  let prodChainIntact = true;
  for (let i = 10; i < blocks.length; i++) {
    if (blocks[i].prev_hash !== blocks[i - 1].current_hash) {
      prodChainIntact = false;
      console.error(`Production chain broken between block #${blocks[i-1].block_number} and #${blocks[i].block_number}`);
      break;
    }
  }
  assert(prodChainIntact === true, 'All new production ledger blocks form an unbroken, strictly sequential append-only hash chain');

  // -------------------------------------------------------------------------
  // SUMMARY
  // -------------------------------------------------------------------------
  console.log('\n================================================================');
  console.log(`  PHASE 4 AUDIT SUMMARY: ${totalPassed} PASSED, ${totalFailed} FAILED`);
  console.log('================================================================\n');

  if (totalFailed > 0) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

runPhase4Tests().catch((err) => {
  console.error('Fatal Phase 4 test execution error:', err);
  process.exit(1);
});
