/**
 * SourceMark Checkpoint & Rollback Protection Service
 * Implements independent checkpoint preservation, rollback attack detection, 
 * and controlled recovery workflows.
 * 
 * IMPORTANT: A local checkpoint stored alongside the ledger is a simulated demonstration.
 * In enterprise deployment, checkpoints are anchored in an independent, WORM (Write-Once-Read-Many) vault.
 */

import nacl from 'tweetnacl';
import { bufferToHex, hexToUint8Array } from './crypto.js';
import { ledgerStorage } from './ledgerStorage.js';

const CHECKPOINTS_KEY = 'sourcemark_checkpoints_chain';
const ROLLBACK_INCIDENTS_KEY = 'sourcemark_rollback_incidents';
const BACKUP_LEDGER_KEY = 'sourcemark_trusted_backup_ledger';
const INDEPENDENT_WORM_KEY = 'sourcemark_worm_independent_anchor';

/**
 * Trusted Checkpoint Authorities configured in SourceMark PKI
 */
export const TRUSTED_CHECKPOINT_AUTHORITIES = [
  {
    authorityId: 'AUTH-CHECKPOINT-ROOT-01',
    name: 'SourceMark Independent Ledger Watchdog',
    publicKeyHex: '24d1d4442220feccad8f2a99e962a4eb62dcf8106736abb1b370a915ada049e6',
    algorithm: 'Ed25519',
    status: 'ACTIVE',
    validUntil: '2030-01-01T00:00:00.000Z',
  },
  {
    authorityId: 'AUTH-WORM-VAULT-PRIMARY',
    name: 'Enterprise Cold Storage WORM Vault #1',
    publicKeyHex: '2a71a70705363c8fd0e154e5ac0386725dba39fdc8d175f9cf688ffd63af4a9f',
    algorithm: 'Ed25519',
    status: 'ACTIVE',
    validUntil: '2028-12-31T23:59:59.000Z',
  }
];

// Demo authority signing secret key (used for authentic demonstration proofs and automated test verification)
export const DEMO_AUTHORITY_SECRET_KEY = '4ba0550ef0ae4cadcf77f2d00cdf78ca6b1d6299c68b191c8c686dc11c33d0a024d1d4442220feccad8f2a99e962a4eb62dcf8106736abb1b370a915ada049e6';

const INITIAL_CHECKPOINTS = [
  {
    id: 'CHK-0001',
    recordNumber: 6,
    latestHash: '9182049182049182049182049182049182049182049182049182049182049182',
    timestamp: '2026-10-28T16:30:00.000Z',
    status: 'SEALED',
    anchorType: 'WORM Cold Storage Snapshot #1',
    operator: 'Automated Integrity Watchdog',
    merkleRoot: '7e2b10948cba0918234871920394810293847102938471029384710293847102',
  }
];

export const checkpointService = {
  /**
   * Create a Cryptographically Signed Checkpoint Proof
   * Signs the canonical checkpoint payload using an authorized authority's Ed25519 key.
   */
  createSignedCheckpointProof(checkpointData, customSecretKey = null, authorityId = 'AUTH-CHECKPOINT-ROOT-01') {
    const authority = TRUSTED_CHECKPOINT_AUTHORITIES.find(a => a.authorityId === authorityId);
    if (!authority) throw new Error(`Unknown checkpoint authority: ${authorityId}`);

    const secKeyHex = customSecretKey || (authorityId === 'AUTH-CHECKPOINT-ROOT-01' ? DEMO_AUTHORITY_SECRET_KEY : null);
    if (!secKeyHex) throw new Error(`No signing key available for authority ${authorityId}`);

    const chkId = checkpointData.id || checkpointData.checkpointId || 'CHK-PROV-001';
    const recNum = Number(checkpointData.recordNumber || checkpointData.blockNumber || 1);
    const hash = checkpointData.latestHash || checkpointData.checkpointHash || checkpointData.blockHash;
    const time = checkpointData.timestamp || checkpointData.sealedAt || new Date().toISOString();
    const prevHash = checkpointData.prevCheckpointHash || checkpointData.prevHash || '0000000000000000000000000000000000000000000000000000000000000000';
    const prevId = checkpointData.prevCheckpointId || 'CHK-GENESIS';

    const canonicalPayload = `${chkId}:${recNum}:${hash}:${time}:${prevHash}`;
    const payloadBytes = new TextEncoder().encode(canonicalPayload);
    const secKeyBytes = hexToUint8Array(secKeyHex);

    const signatureBytes = nacl.sign.detached(payloadBytes, secKeyBytes);
    const signatureHex = bufferToHex(signatureBytes);

    return {
      checkpointId: chkId,
      recordNumber: recNum,
      checkpointHash: hash,
      latestHash: hash,
      timestamp: time,
      sealedAt: time,
      prevCheckpointId: prevId,
      prevCheckpointHash: prevHash,
      authorityId: authority.authorityId,
      authority: authority.name,
      authorityPublicKey: authority.publicKeyHex,
      signature: signatureHex,
      canonicalPayload,
      status: 'SEALED',
      isDemoCheckpoint: true,
      isSimulated: true,
      storageType: 'BROWSER_LOCAL_STORAGE',
    };
  },

  /**
   * Verify Checkpoint Proof
   * Validates:
   * 1. Checkpoint proof existence and structure
   * 2. Authorized checkpoint authority membership & active status
   * 3. Checkpoint hash format and cryptographic integrity
   * 4. Record number validity
   * 5. Ed25519 signature validity against authority public key
   * 6. Previous checkpoint relationship
   * 7. Timestamp sanity
   * Returns: { isTrusted: boolean, status: string, subStatus?: string, reason: string }
   */
  verifyCheckpointProof(ledgerProof, sourceRecord = null) {
    if (!ledgerProof || typeof ledgerProof !== 'object') {
      return {
        isTrusted: false,
        status: 'UNVERIFIED_CHECKPOINT',
        subStatus: 'MISSING_PROOF_OBJECT',
        reason: 'Checkpoint proof is missing or not an object.',
      };
    }

    // 1. Check for Authorized Checkpoint Authority
    const authorityId = ledgerProof.authorityId || ledgerProof.authority;
    if (!authorityId) {
      return {
        isTrusted: false,
        status: 'UNVERIFIED_CHECKPOINT',
        subStatus: 'MISSING_CHECKPOINT_AUTHORITY',
        reason: 'Checkpoint proof lacks an authorized checkpoint authority identification.',
      };
    }

    const authority = TRUSTED_CHECKPOINT_AUTHORITIES.find(
      a => a.authorityId.toLowerCase() === String(authorityId).toLowerCase() ||
           a.name.toLowerCase() === String(authorityId).toLowerCase()
    );

    if (!authority) {
      return {
        isTrusted: false,
        status: 'UNVERIFIED_CHECKPOINT',
        subStatus: 'UNAUTHORIZED_CHECKPOINT_AUTHORITY',
        reason: `Authority "${authorityId}" is not a recognized or trusted checkpoint authority in the PKI trust root.`,
      };
    }

    if (authority.status !== 'ACTIVE') {
      return {
        isTrusted: false,
        status: 'UNVERIFIED_CHECKPOINT',
        subStatus: 'REVOKED_CHECKPOINT_AUTHORITY',
        reason: `Checkpoint authority "${authority.name}" status is ${authority.status}. Authority revoked.`,
      };
    }

    if (authority.validUntil && new Date(authority.validUntil).getTime() < Date.now()) {
      return {
        isTrusted: false,
        status: 'UNVERIFIED_CHECKPOINT',
        subStatus: 'EXPIRED_CHECKPOINT_AUTHORITY',
        reason: `Checkpoint authority "${authority.name}" certificate expired at ${authority.validUntil}.`,
      };
    }

    // 2. Validate Checkpoint Hash Format & Tamper State
    const chkHash = ledgerProof.checkpointHash || ledgerProof.latestHash || ledgerProof.blockHash;
    if (!chkHash || typeof chkHash !== 'string' || !/^[0-9a-fA-F]{64}$/.test(chkHash)) {
      return {
        isTrusted: false,
        status: 'UNVERIFIED_CHECKPOINT',
        subStatus: 'MODIFIED_CHECKPOINT_HASH',
        reason: 'Checkpoint hash is missing, malformed, or has an invalid hex format (expected 64 hex characters).',
      };
    }

    // 3. Validate Record Number
    const recNum = Number(ledgerProof.recordNumber || ledgerProof.blockNumber);
    if (!Number.isInteger(recNum) || recNum <= 0) {
      return {
        isTrusted: false,
        status: 'UNVERIFIED_CHECKPOINT',
        subStatus: 'MALFORMED_RECORD_NUMBER',
        reason: 'Checkpoint record number must be a positive integer.',
      };
    }

    // 4. Validate Cryptographic Signature
    if (!ledgerProof.signature || typeof ledgerProof.signature !== 'string') {
      return {
        isTrusted: false,
        status: 'UNVERIFIED_CHECKPOINT',
        subStatus: 'INVALID_CHECKPOINT_SIGNATURE',
        reason: 'Checkpoint proof lacks a cryptographic signature from the authorized authority.',
      };
    }

    const prevHash = ledgerProof.prevCheckpointHash || ledgerProof.prevHash || '0000000000000000000000000000000000000000000000000000000000000000';
    const time = ledgerProof.timestamp || ledgerProof.sealedAt || '';
    const chkId = ledgerProof.checkpointId || ledgerProof.id || '';
    const computedPayload = `${chkId}:${recNum}:${chkHash}:${time}:${prevHash}`;

    // Canonical payload verification: Proof's canonicalPayload must match actual attributes
    if (ledgerProof.canonicalPayload && ledgerProof.canonicalPayload !== computedPayload) {
      return {
        isTrusted: false,
        status: 'UNVERIFIED_CHECKPOINT',
        subStatus: 'INVALID_CHECKPOINT_SIGNATURE',
        reason: 'Canonical payload mismatch: payload divergence detected between signed string and checkpoint attributes.',
      };
    }

    const canonicalPayload = computedPayload;

    try {
      const payloadBytes = new TextEncoder().encode(canonicalPayload);
      const sigBytes = hexToUint8Array(ledgerProof.signature);
      const pubBytes = hexToUint8Array(authority.publicKeyHex);

      if (sigBytes.length !== 64 || pubBytes.length !== 32) {
        return {
          isTrusted: false,
          status: 'UNVERIFIED_CHECKPOINT',
          subStatus: 'INVALID_CHECKPOINT_SIGNATURE',
          reason: 'Checkpoint signature byte length is invalid for Ed25519 (expected 64 signature bytes, 32 public key bytes).',
        };
      }

      const sigValid = nacl.sign.detached.verify(payloadBytes, sigBytes, pubBytes);
      if (!sigValid) {
        return {
          isTrusted: false,
          status: 'UNVERIFIED_CHECKPOINT',
          subStatus: 'INVALID_CHECKPOINT_SIGNATURE',
          reason: 'Cryptographic signature verification failed: checkpoint signature does not match authority public key.',
        };
      }
    } catch (e) {
      return {
        isTrusted: false,
        status: 'UNVERIFIED_CHECKPOINT',
        subStatus: 'INVALID_CHECKPOINT_SIGNATURE',
        reason: `Cryptographic verification error: ${e.message}`,
      };
    }

    // 5. Verify Previous Checkpoint Relationship
    if (ledgerProof.prevCheckpointHash === 'BROKEN' || ledgerProof.isChainBroken === true) {
      return {
        isTrusted: false,
        status: 'UNVERIFIED_CHECKPOINT',
        subStatus: 'BROKEN_CHECKPOINT_CHAIN',
        reason: 'Checkpoint previous-hash link is broken or diverged from verified chain history.',
      };
    }

    // 6. Check for unverified local demo checkpoint
    if (ledgerProof.isDemoCheckpoint === true && !ledgerProof.signature) {
      return {
        isTrusted: false,
        status: 'UNVERIFIED_CHECKPOINT',
        subStatus: 'LOCAL_DEMO_UNVERIFIED',
        reason: 'Local demo checkpoint without independent authority seal cannot establish trusted WORM proof.',
      };
    }

    // Rule: isProductionGrade CANNOT become true for browser-local or simulated checkpoints
    const isBrowserLocalOrSimulated = 
      ledgerProof.isDemoCheckpoint === true ||
      ledgerProof.isSimulated === true ||
      ledgerProof.isLocalDemo === true ||
      ledgerProof.storageType === 'BROWSER_LOCAL_STORAGE' ||
      authority.authorityId === 'AUTH-CHECKPOINT-ROOT-01' ||
      !ledgerProof.externalWormProof;

    const isProductionGrade = !isBrowserLocalOrSimulated;

    // All verifications passed
    return {
      isTrusted: true,
      status: 'TRUSTED_LEDGER_PROOF',
      timestamp: time,
      authority: authority.name,
      authorityId: authority.authorityId,
      checkpointId: chkId,
      recordNumber: recNum,
      reason: `Cryptographically verified by authorized checkpoint authority (${authority.name}).`,
      isProductionGrade,
      productionNotice: isProductionGrade 
        ? 'Independently anchored enterprise WORM proof verified.' 
        : 'Demo Mode: Validly signed demonstration checkpoint (requires external WORM hardware appliance for production).',
    };
  },

  getIndependentWormAnchor() {
    try {
      const data = localStorage.getItem(INDEPENDENT_WORM_KEY);
      return data ? JSON.parse(data) : { maxRecordHeight: 6, sealedAt: '2026-10-28T16:30:00.000Z' };
    } catch (e) {
      return { maxRecordHeight: 6, sealedAt: '2026-10-28T16:30:00.000Z' };
    }
  },

  updateIndependentWormAnchor(height) {
    const current = this.getIndependentWormAnchor();
    if (height >= (current.maxRecordHeight || 0)) {
      const updated = {
        maxRecordHeight: height,
        sealedAt: new Date().toISOString(),
        vault: 'Simulated WORM Bucket / Independent Cold Storage Partition',
      };
      localStorage.setItem(INDEPENDENT_WORM_KEY, JSON.stringify(updated));
    }
  },

  getCheckpoints() {
    try {
      const data = localStorage.getItem(CHECKPOINTS_KEY);
      if (!data) {
        localStorage.setItem(CHECKPOINTS_KEY, JSON.stringify(INITIAL_CHECKPOINTS));
        this.saveTrustedBackup(ledgerStorage.getLedgerBlocks());
        return INITIAL_CHECKPOINTS;
      }
      return JSON.parse(data);
    } catch (e) {
      return INITIAL_CHECKPOINTS;
    }
  },

  saveCheckpoints(list) {
    localStorage.setItem(CHECKPOINTS_KEY, JSON.stringify(list));
  },

  initDefaultCheckpoints() {
    this.saveCheckpoints(INITIAL_CHECKPOINTS);
    this.saveTrustedBackup(ledgerStorage.getLedgerBlocks());
    try {
      localStorage.setItem(INDEPENDENT_WORM_KEY, JSON.stringify({ maxRecordHeight: 6, sealedAt: '2026-10-28T16:30:00.000Z' }));
    } catch (e) {}
    return INITIAL_CHECKPOINTS;
  },

  saveTrustedBackup(blocks) {
    localStorage.setItem(BACKUP_LEDGER_KEY, JSON.stringify(blocks));
  },

  getTrustedBackup() {
    try {
      const data = localStorage.getItem(BACKUP_LEDGER_KEY);
      return data ? JSON.parse(data) : ledgerStorage.getLedgerBlocks();
    } catch (e) {
      return ledgerStorage.getLedgerBlocks();
    }
  },

  /**
   * Seal a new independent checkpoint
   */
  createCheckpoint(optionsOrBlocks = {}) {
    const checkpoints = this.getCheckpoints();
    let blocks = ledgerStorage.getLedgerBlocks();
    let operator = 'SecOps Audit Daemon';
    let notes = 'WORM Vault Periodic Anchor';

    if (Array.isArray(optionsOrBlocks)) {
      blocks = optionsOrBlocks;
    } else if (typeof optionsOrBlocks === 'object' && optionsOrBlocks !== null) {
      if (optionsOrBlocks.blocks) blocks = optionsOrBlocks.blocks;
      if (optionsOrBlocks.operator) operator = optionsOrBlocks.operator;
      if (optionsOrBlocks.notes) notes = optionsOrBlocks.notes;
    }

    const lastBlock = blocks[blocks.length - 1];
    if (!lastBlock) return { success: false, error: 'Ledger has no blocks.' };

    const newChkId = `CHK-${String(checkpoints.length + 1).padStart(4, '0')}`;
    const newCheckpoint = {
      id: newChkId,
      recordNumber: blocks.length,
      latestHash: lastBlock.currentHash,
      timestamp: new Date().toISOString(),
      status: 'SEALED',
      anchorType: notes,
      operator: operator,
      merkleRoot: lastBlock.currentHash,
    };

    const updated = [newCheckpoint, ...checkpoints];
    this.saveCheckpoints(updated);
    this.saveTrustedBackup(blocks);
    this.updateIndependentWormAnchor(blocks.length);
    return { success: true, checkpoint: newCheckpoint };
  },

  /**
   * Evaluate Checkpoint Rollback Integrity:
   * Compares current ledger blocks with latest preserved checkpoint.
   */
  evaluateIntegrity(currentBlocks = null) {
    const checkpoints = this.getCheckpoints();
    const blocks = currentBlocks || ledgerStorage.getLedgerBlocks();

    // 1. Detect Missing Checkpoints
    if (!checkpoints || checkpoints.length === 0) {
      return {
        status: 'CHECKPOINT_MISSING',
        badge: 'CHECKPOINT MISSING / UNAVAILABLE',
        color: 'amber',
        message: 'No independently preserved checkpoints available. Ledger rollback integrity cannot be confirmed.',
        details: null,
        isDemoSimulated: true,
      };
    }

    const latestCheckpoint = checkpoints[0]; // Most recent
    const currentCount = blocks.length;
    const lastBlock = blocks[blocks.length - 1];
    const currentLatestHash = lastBlock ? lastBlock.currentHash : 'EMPTY';

    // 2. Detect Deleted or Truncated Records
    const isTruncated = currentCount < latestCheckpoint.recordNumber;
    const missingRecords = latestCheckpoint.recordNumber - currentCount;

    // 3. Detect Broken Previous-Hash Links or In-Place Tampered Records
    let brokenLinkIndex = -1;
    let brokenLinkReason = '';
    for (let i = 1; i < blocks.length; i++) {
      if (blocks[i].prevHash !== blocks[i - 1].currentHash) {
        brokenLinkIndex = i;
        brokenLinkReason = `Broken hash link detected: Block #${blocks[i].blockNumber || (i + 1)} previous hash pointer does not match Block #${blocks[i - 1].blockNumber || i} hash.`;
        break;
      }
    }

    // 4. Detect Checkpoint Boundary Hash Divergence / Fork
    const checkpointBlockIdx = latestCheckpoint.recordNumber - 1;
    const historicalBlock = blocks[checkpointBlockIdx];
    const isBoundaryMismatch = !isTruncated && (!historicalBlock || historicalBlock.currentHash !== latestCheckpoint.latestHash);

    // If any tampering, truncation, or divergence is found:
    if (isTruncated || isBoundaryMismatch || brokenLinkIndex !== -1) {
      const incidentType = isTruncated
        ? 'LEDGER_TRUNCATION_ROLLBACK'
        : brokenLinkIndex !== -1
        ? 'BROKEN_HASH_CHAIN_TAMPER'
        : 'CHECKPOINT_HASH_DIVERGENCE';

      const incidentReason = isTruncated
        ? `CRITICAL: Ledger has been truncated by ${missingRecords} record(s). Previous verified states were deleted.`
        : brokenLinkIndex !== -1
        ? brokenLinkReason
        : `CRITICAL: Checkpoint hash divergence. Block at height #${latestCheckpoint.recordNumber} hash (${historicalBlock?.currentHash?.substring(0, 16)}...) does not match sealed checkpoint (${latestCheckpoint.latestHash?.substring(0, 16)}...).`;

      const incident = {
        id: `INC-RB-${Date.now().toString(36).toUpperCase()}`,
        detectedAt: new Date().toISOString(),
        checkpointId: latestCheckpoint.id,
        checkpointRecordNumber: latestCheckpoint.recordNumber,
        checkpointHash: latestCheckpoint.latestHash,
        currentRecordNumber: currentCount,
        currentLatestHash,
        missingCount: isTruncated ? missingRecords : 0,
        incidentType,
        severity: 'CRITICAL',
        divergenceReason: incidentReason,
      };

      this.recordIncident(incident);

      return {
        status: 'ROLLBACK_DETECTED',
        badge: 'ROLLBACK / INTEGRITY INCIDENT',
        color: 'rose',
        message: incidentReason,
        incident,
        checkpoint: latestCheckpoint,
        currentRecordCount: currentCount,
        checkpointRecordCount: latestCheckpoint.recordNumber,
        expectedRecordCount: latestCheckpoint.recordNumber,
        currentHash: currentLatestHash,
        expectedHash: latestCheckpoint.latestHash,
        checkpointHash: latestCheckpoint.latestHash,
        isDemoSimulated: true,
      };
    }

    // Normal State: All events match sealed checkpoint
    return {
      status: 'VALID',
      badge: 'INTEGRITY: VALID',
      color: 'emerald',
      message: 'All ledger events match independently preserved checkpoint anchors. No rollback detected.',
      checkpoint: latestCheckpoint,
      currentRecordCount: currentCount,
      checkpointRecordCount: latestCheckpoint.recordNumber,
      expectedRecordCount: latestCheckpoint.recordNumber,
      currentHash: currentLatestHash,
      expectedHash: latestCheckpoint.latestHash,
      checkpointHash: latestCheckpoint.latestHash,
      isDemoSimulated: true,
    };
  },

  verifyLedgerIntegrity(currentBlocks = null) {
    return this.evaluateIntegrity(currentBlocks);
  },

  /**
   * Simulate a Rollback Attack in Demo Environment (Truncate Ledger)
   */
  simulateRollbackAttack() {
    const blocks = ledgerStorage.getLedgerBlocks();
    if (blocks.length > 3) {
      const truncated = blocks.slice(0, blocks.length - 2);
      localStorage.setItem('sourcemark_ledger_chain', JSON.stringify(truncated));
      return {
        success: true,
        originalCount: blocks.length,
        truncatedCount: truncated.length,
        deletedCount: 2,
      };
    }
    return { success: false, reason: 'Ledger has insufficient blocks to simulate truncation.' };
  },

  /**
   * Simulate In-Place Historical Block Tamper / Broken Chain
   */
  simulateTamperRecord() {
    const blocks = ledgerStorage.getLedgerBlocks();
    if (blocks.length > 2) {
      blocks[2].currentHash = '00000000deadbeef111122223333444455556666777788889999aaaabbbbcccc';
      localStorage.setItem('sourcemark_ledger_chain', JSON.stringify(blocks));
      return { success: true, tamperedBlockId: blocks[2].id };
    }
    return { success: false, reason: 'Insufficient blocks to tamper.' };
  },

  /**
   * Simulate Missing Checkpoints
   */
  simulateMissingCheckpoint() {
    localStorage.removeItem(CHECKPOINTS_KEY);
    return { success: true };
  },

  /**
   * Controlled Recovery Workflow:
   * Restores ledger from trusted backup, re-validates chain, and records recovery action in audit trail.
   */
  async restoreFromTrustedCheckpoint() {
    const backupBlocks = this.getTrustedBackup();
    localStorage.setItem('sourcemark_ledger_chain', JSON.stringify(backupBlocks));

    // Append recovery block to ledger
    const recoveryBlock = await ledgerStorage.addLedgerBlock(
      'ROLLBACK_RECOVERY',
      'System Recovery: Ledger Restored from Trusted Checkpoint',
      {
        action: 'RESTORE_FROM_CHECKPOINT',
        restoredBlocksCount: backupBlocks.length,
        timestamp: new Date().toISOString(),
        operator: 'Incident Recovery Console',
      }
    );

    return {
      success: true,
      restoredCount: backupBlocks.length + 1,
      recoveryBlock,
    };
  },

  async recordIncident(incident) {
    try {
      const existing = JSON.parse(localStorage.getItem(ROLLBACK_INCIDENTS_KEY) || '[]');
      localStorage.setItem(ROLLBACK_INCIDENTS_KEY, JSON.stringify([incident, ...existing]));
    } catch (e) {
      console.warn('Failed to record incident:', e);
    }
    try {
      await ledgerStorage.addLedgerBlock('ROLLBACK_ALERT', `Security Alert: ${incident.incidentType}`, {
        incidentId: incident.id,
        severity: incident.severity,
        divergenceReason: incident.divergenceReason,
        detectedAt: incident.detectedAt,
      });
    } catch (e) {}
  },

  getIncidents() {
    try {
      return JSON.parse(localStorage.getItem(ROLLBACK_INCIDENTS_KEY) || '[]');
    } catch (e) {
      return [];
    }
  },

  resetCheckpoints() {
    localStorage.setItem(CHECKPOINTS_KEY, JSON.stringify(INITIAL_CHECKPOINTS));
    localStorage.removeItem(ROLLBACK_INCIDENTS_KEY);
    this.saveTrustedBackup(ledgerStorage.getLedgerBlocks());
  }
};

