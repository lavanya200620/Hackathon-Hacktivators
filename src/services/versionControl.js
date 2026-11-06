/**
 * SourceMark Version Control & Legitimate Re-Save Service
 * Tracks authorized derivative versions (compression, re-save, redaction) 
 * without treating legitimate edits as malicious tampering.
 */

import { ledgerStorage } from './ledgerStorage.js';
import { signFingerprint } from './crypto.js';

const VERSIONS_KEY = 'sourcemark_version_derivatives';

const INITIAL_VERSIONS = [
  {
    versionId: 'VER-SRC98214-02',
    sourceId: 'SRC-98214',
    parentVersionId: 'ROOT',
    fileName: 'satellite_recon_orbital_07_optimized.webp',
    originalHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    newHash: '4f2d87e1a3b5c6d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3',
    transformationReason: 'Lossless WebP compression for tactical low-bandwidth edge deployment',
    actor: 'Marcus Vance (Senior Imagery Systems Engineer)',
    actorId: 'AGY-USR-0089',
    authorizationStatus: 'AUTHORIZED', // 'AUTHORIZED' | 'REJECTED' | 'PENDING_REVIEW'
    createdAt: '2026-10-27T10:15:00.000Z',
    fileSizeFormatted: '1.12 MB (52% reduction)',
    approvedBy: 'Dr. Evelyn Vance (Master Source Custodian)',
    notes: 'Preserves multispectral infrared sensor layers; bitstream delta approved.',
  },
  {
    versionId: 'VER-SRC55109-02',
    sourceId: 'SRC-55109',
    parentVersionId: 'ROOT',
    fileName: 'acquisition_term_sheet_final_redacted.pdf',
    originalHash: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
    newHash: '8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b',
    transformationReason: 'Public disclosure version with confidential banking routing numbers redacted',
    actor: 'Sarah Jenkins, Esq.',
    actorId: 'AGY-USR-0119',
    authorizationStatus: 'AUTHORIZED',
    createdAt: '2026-10-29T11:00:00.000Z',
    fileSizeFormatted: '1.74 MB',
    approvedBy: 'General Counsel Audit Committee',
    notes: 'Redacted according to SEC Section 13(d) filing protocol.',
  }
];

export const versionControlService = {
  getVersions() {
    try {
      const data = localStorage.getItem(VERSIONS_KEY);
      if (!data) {
        localStorage.setItem(VERSIONS_KEY, JSON.stringify(INITIAL_VERSIONS));
        return INITIAL_VERSIONS;
      }
      return JSON.parse(data);
    } catch (e) {
      return INITIAL_VERSIONS;
    }
  },

  getVersionsForSource(sourceId) {
    if (!sourceId) return [];
    const versions = this.getVersions();
    return versions.filter(v => v.sourceId && v.sourceId.toLowerCase() === sourceId.trim().toLowerCase());
  },

  findVersionByHash(hash) {
    if (!hash) return null;
    const cleanHash = typeof hash === 'string' ? hash.trim().toLowerCase() : '';
    const versions = this.getVersions();
    return versions.find(v => v.newHash && v.newHash.toLowerCase() === cleanHash);
  },

  /**
   * Register a legitimate re-saved derivative version
   */
  async createVersion({
    sourceId,
    fileName,
    newHash,
    transformationReason,
    actor,
    actorId,
    authorizationStatus = 'AUTHORIZED',
    fileSizeFormatted,
    notes = '',
  }) {
    const parentSource = ledgerStorage.getSourceById(sourceId);
    if (!parentSource) {
      throw new Error(`Master Source ID ${sourceId} not found in provenance registry.`);
    }

    const versions = this.getVersions();
    const sourceVersions = versions.filter(v => v.sourceId === sourceId);
    const versionNumber = sourceVersions.length + 2; // +1 root, +1 next
    const versionId = `VER-${sourceId.replace('SRC-', '')}-${String(versionNumber).padStart(2, '0')}`;
    const now = new Date().toISOString();
    let versionSig = { signatureHex: null, publicKeyHex: null, keyId: null };
    try {
      versionSig = signFingerprint(newHash);
    } catch (e) {
      console.warn('Could not generate derivative signature:', e);
    }

    const newVersion = {
      versionId,
      sourceId,
      parentVersionId: sourceVersions.length > 0 ? sourceVersions[sourceVersions.length - 1].versionId : 'ROOT',
      fileName,
      originalHash: parentSource.sha256 || parentSource.hash,
      newHash,
      transformationReason,
      actor,
      actorId,
      authorizationStatus,
      signature: versionSig.signatureHex,
      publicKey: versionSig.publicKeyHex,
      keyId: versionSig.keyId,
      createdAt: now,
      fileSizeFormatted: fileSizeFormatted || 'Unknown size',
      approvedBy: authorizationStatus === 'AUTHORIZED' ? `${actor} (Authorized Editor)` : 'Pending Approval',
      notes,
    };

    const updated = [newVersion, ...versions];
    localStorage.setItem(VERSIONS_KEY, JSON.stringify(updated));

    // Append to audit ledger
    await ledgerStorage.addLedgerBlock(
      authorizationStatus === 'AUTHORIZED' ? 'AUTHORIZED_DERIVATIVE' : 'DERIVATIVE_PENDING',
      `Version Created: ${versionId} for ${sourceId}`,
      {
        versionId,
        sourceId,
        newHash,
        transformationReason,
        status: authorizationStatus,
        operator: actor,
      }
    );

    return newVersion;
  },

  registerDerivative(data) {
    return this.createVersion(data);
  },

  /**
   * Evaluate whether a file hash is an authorized derivative
   */
  evaluateDerivative(hash, sourceId = null) {
    // 1. Direct lookup by hash
    let matchedVersion = this.findVersionByHash(hash);

    // 2. If sourceId given, filter to that source
    if (sourceId && matchedVersion && matchedVersion.sourceId !== sourceId) {
      matchedVersion = null;
    }

    if (!matchedVersion) return null;

    return {
      isDerivative: true,
      status: matchedVersion.authorizationStatus,
      version: matchedVersion,
    };
  },

  resetVersions() {
    localStorage.setItem(VERSIONS_KEY, JSON.stringify(INITIAL_VERSIONS));
    return INITIAL_VERSIONS;
  }
};

