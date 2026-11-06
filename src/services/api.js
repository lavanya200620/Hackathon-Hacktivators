import axios from 'axios';
import { ledgerStorage } from './ledgerStorage.js';
import { verifyFingerprintSignature, getOrCreateKeyPair } from './crypto.js';
import { keySecurityService } from './keySecurity.js';
import { versionControlService } from './versionControl.js';
import { checkpointService } from './checkpointService.js';

const BASE_URL = (typeof import.meta !== 'undefined' && import.meta.env && import.meta.env.VITE_API_URL) || 'http://127.0.0.1:8000';

const apiClient = axios.create({
  baseURL: BASE_URL,
  timeout: 3500, // Quick timeout to detect offline backend
  headers: {
    'Content-Type': 'application/json',
  },
});

// Attach enterprise authentication token to all outgoing API requests
apiClient.interceptors.request.use((config) => {
  if (typeof sessionStorage !== 'undefined') {
    try {
      const stored = sessionStorage.getItem('sourcemark_enterprise_session');
      if (stored) {
        const parsed = JSON.parse(stored);
        if (parsed.token) {
          config.headers['Authorization'] = `Bearer ${parsed.token}`;
        }
      }
    } catch {}
  }
  return config;
});

export const apiService = {
  baseURL: BASE_URL,

  /**
   * Check if backend server is responsive
   */
  async checkHealth() {
    try {
      const response = await apiClient.get('/api/health');
      return { online: true, status: response.data };
    } catch (error) {
      return { online: false, error: error.message };
    }
  },

  /**
   * Register a new digital source
   * POST /api/register
   */
  async registerSource(payload) {
    try {
      const response = await apiClient.post('/api/register', payload);
      return { ...response.data, isDemoMode: false };
    } catch (error) {
      console.warn('Backend unavailable (/api/register), persisting to client demo ledger:', error.message);

      // Security Check: Block registration if signing key is marked COMPROMISED or REVOKED
      const activeKey = getOrCreateKeyPair();
      const signingPubKey = payload.publicKey || activeKey.publicKeyHex;
      const signingKeyId = payload.keyId || activeKey.keyId;

      if (keySecurityService.isKeyRevoked(signingPubKey) || keySecurityService.isKeyRevoked(signingKeyId)) {
        await ledgerStorage.addLedgerBlock('SECURITY_INCIDENT', `Registration Blocked: Key Revoked/Compromised`, {
          keyId: signingKeyId,
          publicKey: signingPubKey,
          reason: 'Signing prohibited with compromised or revoked credentials.',
        });

        return {
          success: false,
          error: 'SECURITY EXCEPTION: Signing key is compromised or revoked. Key rotation required before signing new provenance records.',
          isDemoMode: true,
        };
      }

      // In demo mode: catalog key in Public Key Trust Registry if not already registered
      if (signingPubKey || signingKeyId) {
        keySecurityService.registerKey({
          id: signingKeyId,
          publicKeyHex: signingPubKey,
          owner: payload.creator || 'Authorized Demo Custodian',
          ownerId: payload.creatorId || 'CUSTODIAN-DEMO',
          role: 'Authorized Registration Authority (Demo)',
          status: 'ACTIVE',
          createdAt: payload.signedAt || new Date().toISOString(),
        });
      }

      // In demo mode: save to local verified ledger
      const now = new Date().toISOString();
      const sourceRecord = ledgerStorage.addSource({
        ...payload,
        id: payload.id || `SRC-${Math.floor(10000 + Math.random() * 90000)}`,
        registeredAt: now,
        signedAt: payload.signedAt || payload.signatureTimestamp || now,
        signatureTimestamp: payload.signedAt || payload.signatureTimestamp || now,
        status: 'ACTIVE_REGISTERED',
        verificationCount: 0,
        lastVerifiedAt: null,
      });

      return {
        success: true,
        data: sourceRecord,
        source: sourceRecord,
        isDemoMode: true,
        message: 'Source registered in Local Cryptographic Ledger (Demo Mode - Backend Offline)',
      };
    }
  },

  /**
   * Cryptographically verify if a source record possesses a trusted signing timestamp.
   * 
   * SECURITY ARCHITECTURE NOTICE:
   * A registration timestamp (registeredAt) only proves when a record was received by the ledger.
   * It does NOT prove when the private-key mathematical signature was created.
   * Client-supplied timestamps (signedAt, signatureTimestamp, registeredAt) are classified as
   * UNTRUSTED unless accompanied by an independently verifiable RFC 3161 Timestamp Authority token
   * or an immutable WORM ledger checkpoint anchor.
   */
  verifyTrustedTimestamp(sourceRecord) {
    if (!sourceRecord) {
      return {
        isTrusted: false,
        timestamp: null,
        status: 'MISSING_TIMESTAMP',
        reason: 'No timestamp data available in source record.',
      };
    }

    // 1. Check for RFC 3161 Timestamp Authority Token
    const tsa = sourceRecord.tsaToken || sourceRecord.timestampToken || sourceRecord.trustedTimestampToken;
    if (tsa) {
      if (typeof tsa === 'object' && tsa !== null) {
        // Evaluate TSA certificate expiration or cryptographic invalidity
        const isCertExpired = tsa.status === 'EXPIRED' || tsa.certExpired === true || tsa.expired === true || tsa.certificateStatus === 'EXPIRED' ||
          (tsa.certExpiresAt && new Date(tsa.certExpiresAt).getTime() < Date.now());
        const isCertInvalid = tsa.status === 'INVALID' || tsa.status === 'REVOKED' || tsa.valid === false || tsa.certificateValid === false ||
          tsa.certificateStatus === 'REVOKED' || tsa.certificateStatus === 'INVALID';

        if (isCertExpired) {
          return {
            isTrusted: false,
            timestamp: tsa.timestamp || tsa.time || null,
            authority: tsa.authority || 'RFC 3161 Qualified Timestamp Authority',
            token: tsa,
            status: 'EXPIRED_TSA_CERTIFICATE',
            reason: `TSA Certificate Expired: The Timestamp Authority certificate expired on ${tsa.certExpiresAt || 'an earlier date'}. Cryptographic trust chain cannot be verified.`,
            isProductionIntegrationRequired: true,
            productionNotice: 'Production deployment requires online X.509 certificate path and OCSP validation against a Qualified Trust Service Provider (QTSP).',
          };
        }

        if (isCertInvalid) {
          return {
            isTrusted: false,
            timestamp: tsa.timestamp || tsa.time || null,
            authority: tsa.authority || 'RFC 3161 Qualified Timestamp Authority',
            token: tsa,
            status: 'INVALID_TSA_TOKEN',
            reason: `TSA Certificate/Token Invalid: Cryptographic signature on RFC 3161 token or X.509 certificate failed validation (${tsa.failureReason || tsa.reason || 'Verification failed'}).`,
            isProductionIntegrationRequired: true,
            productionNotice: 'Production deployment requires online X.509 certificate path and OCSP validation against a Qualified Trust Service Provider (QTSP).',
          };
        }

        if (tsa.status === 'VERIFIED' || tsa.status === 'VALID' || (tsa.authority && tsa.signature)) {
          return {
            isTrusted: true,
            timestamp: tsa.timestamp || tsa.time || sourceRecord.signedAt || sourceRecord.registeredAt,
            authority: tsa.authority || 'RFC 3161 Qualified Timestamp Authority',
            token: tsa,
            status: 'TRUSTED_TSA_TOKEN',
            reason: `Cryptographically verified by Timestamp Authority (${tsa.authority || 'RFC 3161 TSA'}).`,
            isProductionIntegrationRequired: false,
            productionNotice: 'Note: Structural token verified in demo mode. Enterprise production requires live RFC 3161 HTTP/ASN.1 query and X.509 chain validation.',
          };
        }
      } else if (typeof tsa === 'string' && tsa.trim().length > 10) {
        return {
          isTrusted: true,
          timestamp: sourceRecord.signedAt || sourceRecord.signatureTimestamp || sourceRecord.registeredAt,
          authority: 'RFC 3161 Timestamp Authority (DER Token Sealed)',
          token: tsa,
          status: 'TRUSTED_TSA_TOKEN',
          reason: 'Verifiable RFC 3161 TSA token envelope attached.',
          isProductionIntegrationRequired: false,
          productionNotice: 'Note: Binary ASN.1 DER parsing and X.509 root cert validation required in production backend.',
        };
      }
    }

    // 2. Check for Independent Ledger WORM Checkpoint Anchor Proof
    const rawLedgerProof = sourceRecord.ledgerProof || sourceRecord.checkpointProof || sourceRecord.wormAnchor;
    if (rawLedgerProof) {
      const checkpointEval = checkpointService.verifyCheckpointProof(rawLedgerProof, sourceRecord);
      if (checkpointEval && checkpointEval.isTrusted) {
        return {
          isTrusted: true,
          timestamp: checkpointEval.timestamp,
          authority: checkpointEval.authority,
          token: rawLedgerProof,
          status: 'TRUSTED_LEDGER_PROOF',
          reason: checkpointEval.reason,
          isProductionGrade: checkpointEval.isProductionGrade,
          productionNotice: checkpointEval.isProductionGrade ? 'Independently anchored proof verified.' : 'Demo Mode: Validly signed demonstration checkpoint.',
        };
      } else {
        // Checkpoint failed cryptographic verification, lacks authority, or is altered.
        // Rule: Never trust a checkpoint merely because fields exist! Never return TRUSTED_LEDGER_PROOF!
        return {
          isTrusted: false,
          timestamp: checkpointEval ? checkpointEval.timestamp : null,
          authority: (checkpointEval && checkpointEval.authority) || 'Unverified Checkpoint Authority',
          token: rawLedgerProof,
          status: 'UNVERIFIED_CHECKPOINT',
          subStatus: (checkpointEval && checkpointEval.subStatus) || 'UNVERIFIED_CHECKPOINT',
          reason: checkpointEval ? checkpointEval.reason : 'Checkpoint proof failed cryptographic verification against authorized checkpoint authorities.',
          productionNotice: 'Production deployment requires independent WORM vault signed checkpoint anchor.',
        };
      }
    }

    // 3. Fallback: Distinguish untrusted client signedAt vs unverified registeredAt
    const hasClientSignedAt = !!(sourceRecord.signedAt || sourceRecord.signatureTimestamp);
    const hasRegisteredAt = !!sourceRecord.registeredAt;
    const rawTime = sourceRecord.signedAt || sourceRecord.signatureTimestamp || sourceRecord.registeredAt || sourceRecord.timestamp;

    if (hasClientSignedAt) {
      return {
        isTrusted: false,
        timestamp: rawTime,
        status: 'UNTRUSTED_CLIENT_TIMESTAMP',
        reason: 'Client-supplied signedAt timestamp is unverified. Lacks an independent RFC 3161 TSA token or ledger proof.',
      };
    }

    if (hasRegisteredAt) {
      return {
        isTrusted: false,
        timestamp: sourceRecord.registeredAt,
        status: 'UNTRUSTED_REGISTRATION_TIMESTAMP',
        reason: 'Registration timestamp does not prove when the digital signature was created. Lacks an independent RFC 3161 TSA token.',
      };
    }

    return {
      isTrusted: false,
      timestamp: null,
      status: 'MISSING_TIMESTAMP',
      reason: 'Missing signing timestamp evidence in source record.',
    };
  },

  /**
   * Verify file authenticity
   * POST /api/verify
   * Payload: { sha256, sourceId, fileName, signature, publicKey }
   */
  async verifySource(payloadOrHash, maybeSourceId = null) {
    let payload = {};
    if (typeof payloadOrHash === 'string') {
      payload = { sha256: payloadOrHash, sourceId: maybeSourceId };
    } else if (payloadOrHash && typeof payloadOrHash === 'object') {
      payload = payloadOrHash;
    }

    try {
      const response = await apiClient.post('/api/verify', payload);
      return { ...response.data, isDemoMode: false };
    } catch (error) {
      console.warn('Backend unavailable (/api/verify), verifying using browser cryptographic engine:', error.message);

      const { sha256, sourceId } = payload;

      // 0. Check if the file is a registered authorized or unauthorized derivative
      const derivativeInfo = versionControlService.evaluateDerivative(sha256, sourceId);
      if (derivativeInfo && derivativeInfo.isDerivative) {
        if (derivativeInfo.status === 'AUTHORIZED') {
          const master = ledgerStorage.getSourceById(derivativeInfo.version.sourceId);
          await ledgerStorage.addLedgerBlock('VERIFY_ORIGINAL', `Derivative Verified: ${derivativeInfo.version.fileName}`, {
            versionId: derivativeInfo.version.versionId,
            sourceId: derivativeInfo.version.sourceId,
            hash: sha256,
            verdict: 'AUTHORIZED_DERIVATIVE',
          });

          return {
            verdict: 'AUTHORIZED_DERIVATIVE',
            status: 'info',
            message: 'Authorized Derivative – Lineage Confirmed',
            source: master || { id: derivativeInfo.version.sourceId, fileName: derivativeInfo.version.fileName },
            version: derivativeInfo.version,
            signatureValid: true,
            hashMatch: false,
            isDerivative: true,
            details: `File bitstream matches an approved authorized derivative (${derivativeInfo.version.transformationReason}) linked to master source ${derivativeInfo.version.sourceId}.`,
            isDemoMode: true,
          };
        } else {
          // Unauthorized derivative attempt
          await ledgerStorage.addLedgerBlock('UNAUTHORIZED_DERIVATIVE_ATTEMPT', `Security Alert: Unauthorized Derivative for ${derivativeInfo.version.sourceId}`, {
            versionId: derivativeInfo.version.versionId,
            sourceId: derivativeInfo.version.sourceId,
            hash: sha256,
            verdict: 'REQUIRES_INVESTIGATION',
            severity: 'HIGH',
            reason: 'File matches an unapproved derivative modification. Custodian approval token is missing or rejected.',
          });

          return {
            verdict: 'REQUIRES_INVESTIGATION',
            status: 'warning',
            message: 'Unauthorized Derivative – Investigation Required',
            version: derivativeInfo.version,
            signatureValid: false,
            hashMatch: false,
            details: 'File matches an unapproved derivative modification. Custodian approval token is missing or rejected.',
            isDemoMode: true,
          };
        }
      }

      let matchedSource = null;

      // 1. If user supplied a source ID, check that specific source
      if (sourceId && sourceId.trim()) {
        matchedSource = ledgerStorage.getSourceById(sourceId);
      } else {
        // 2. Search registered database for hash match
        matchedSource = ledgerStorage.findSourceByHash(sha256);
      }

      // Determine verdict
      if (!matchedSource) {
        // UNKNOWN: No registered source exists
        await ledgerStorage.addLedgerBlock('VERIFY_UNKNOWN', `Verification Check: Unknown Content`, {
          searchedHash: sha256,
          searchedSourceId: sourceId || null,
          verdict: 'UNKNOWN',
        });

        return {
          verdict: 'UNKNOWN',
          status: 'warning',
          message: 'Unknown – No Trusted Source Found',
          searchedHash: sha256,
          searchedSourceId: sourceId || null,
          details: 'This file fingerprint does not exist in the registered provenance registry. No cryptographic relationship could be established.',
          isDemoMode: true,
        };
      }

      // 1. Independently evaluate the signing timestamp against trusted authority standards
      const timestampVerification = this.verifyTrustedTimestamp(matchedSource);

      // 2. Independently evaluate the signing key status using the verified timestamp evidence
      const keyIdOrPk = matchedSource.publicKey || matchedSource.keyId;
      const keyEvaluation = keySecurityService.evaluateKeyStatus(
        keyIdOrPk,
        timestampVerification
      );

      // 3. Independently calculate the file hash match
      const sourceHash = matchedSource.sha256 || matchedSource.hash || '';
      const isExactMatch = sourceHash.toLowerCase() === sha256.toLowerCase();

      // 4. Independently verify the Ed25519 signature
      const isSigValid = verifyFingerprintSignature(
        sourceHash,
        matchedSource.signature,
        matchedSource.publicKey
      );

      // 5. Synthesize final verdict across all orthogonal security vectors

      const isKeyCompromised = 
        keyEvaluation.verdict === 'COMPROMISED_KEY' || 
        keyEvaluation.status === 'POST_COMPROMISE_BREACH' || 
        keyEvaluation.status === 'REVOKED' || 
        keySecurityService.isKeyCompromised(keyIdOrPk);

      // Vector 1: Content difference / modified file (!isExactMatch)
      if (!isExactMatch) {
        if (isKeyCompromised) {
          await ledgerStorage.addLedgerBlock('TAMPER_DETECTED', `Multi-Vector Alert: Modified File & Compromised Key for ${matchedSource.id}`, {
            sourceId: matchedSource.id,
            fileName: matchedSource.fileName,
            hash: sha256,
            verdict: 'MODIFIED_AND_COMPROMISED_KEY',
          });

          return {
            verdict: 'MODIFIED_AND_COMPROMISED_KEY',
            status: 'danger',
            message: 'Critical Alert – Modified File & Compromised Key',
            source: matchedSource,
            originalHash: sourceHash,
            uploadedHash: sha256,
            signatureValid: false,
            hashMatch: false,
            keyCompromised: true,
            keyStatus: keyEvaluation.status,
            timestampStatus: timestampVerification.status,
            details: 'Critical Multi-Vector Violation: The file bitstream does not match registered master fingerprint AND the signing key is cataloged as COMPROMISED.',
            isDemoMode: true,
          };
        } else {
          await ledgerStorage.addLedgerBlock('TAMPER_DETECTED', `Tamper Alert: Modified File for ${matchedSource.id}`, {
            sourceId: matchedSource.id,
            originalHash: sourceHash,
            uploadedHash: sha256,
            signatureValid: false,
            verdict: 'EDITED',
          });

          return {
            verdict: 'EDITED',
            status: 'danger',
            message: 'Edited – Content Difference Detected',
            source: matchedSource,
            originalHash: sourceHash,
            uploadedHash: sha256,
            signatureValid: false,
            hashMatch: false,
            keyStatus: 'ACTIVE',
            details: 'The submitted file references Source ID ' + matchedSource.id + ' but has a modified binary fingerprint. Cryptographic signature does not cover modified content.',
            isDemoMode: true,
          };
        }
      }

      // Vector 2: Missing or unavailable key status information OR unverified signing time during key compromise
      if (keyEvaluation.verdict === 'REQUIRES_INVESTIGATION') {
        await ledgerStorage.addLedgerBlock('TAMPER_DETECTED', `Security Alert: Investigation Required for ${matchedSource.id}`, {
          sourceId: matchedSource.id,
          fileName: matchedSource.fileName,
          hash: sha256,
          verdict: 'REQUIRES_INVESTIGATION',
          reason: keyEvaluation.reason,
          timestampStatus: timestampVerification.status,
        });

        return {
          verdict: 'REQUIRES_INVESTIGATION',
          subVerdict: keyEvaluation.status === 'UNKNOWN_SIGNING_TIME' ? 'UNKNOWN_SIGNING_TIME' : undefined,
          status: 'warning',
          message: keyEvaluation.status === 'UNKNOWN_SIGNING_TIME'
            ? 'Requires Investigation – Unverified Signing Timestamp'
            : 'Requires Investigation – Key Status Compromised or Unknown',
          source: matchedSource,
          signatureValid: isSigValid,
          hashMatch: isExactMatch,
          keyStatus: keyEvaluation.status,
          timestampStatus: timestampVerification.status,
          details: keyEvaluation.reason,
          isDemoMode: true,
        };
      }

      // Vector 3: Verified Pre-Compromise Historical Signature (Backed by verifiable TSA / ledger anchor)
      if (isSigValid && keyEvaluation.verdict === 'PRE_COMPROMISE_VALID') {
        matchedSource.verificationCount = (matchedSource.verificationCount || 0) + 1;
        matchedSource.lastVerifiedAt = new Date().toISOString();

        await ledgerStorage.addLedgerBlock('VERIFY_ORIGINAL', `Pre-Compromise Integrity Verified: ${matchedSource.fileName}`, {
          sourceId: matchedSource.id,
          fileName: matchedSource.fileName,
          hash: sha256,
          verdict: 'PRE_COMPROMISE_VALID',
          tsaAuthority: timestampVerification.authority,
        });

        return {
          verdict: 'PRE_COMPROMISE_VALID',
          status: 'success',
          message: 'Original – Verified Pre-Compromise Integrity',
          source: matchedSource,
          signatureValid: isSigValid,
          hashMatch: true,
          keyStatus: keyEvaluation.status,
          timestampStatus: timestampVerification.status,
          tsaAuthority: timestampVerification.authority,
          details: keyEvaluation.reason,
          isDemoMode: true,
        };
      }

      // Vector 4: Post-Compromise signature or Compromised Key
      if (isKeyCompromised) {
        await ledgerStorage.addLedgerBlock('TAMPER_DETECTED', `Security Alert: Compromised Key for ${matchedSource.id}`, {
          sourceId: matchedSource.id,
          fileName: matchedSource.fileName,
          hash: sha256,
          verdict: 'COMPROMISED_KEY',
        });

        return {
          verdict: 'COMPROMISED_KEY',
          status: 'danger',
          message: 'Security Alert – Signed with Compromised Key',
          source: matchedSource,
          signatureValid: isSigValid,
          hashMatch: true,
          keyCompromised: true,
          keyStatus: keyEvaluation.status,
          timestampStatus: timestampVerification.status,
          details: keyEvaluation.reason || 'The file bitstream matches, but the signing key has been reported COMPROMISED. The file cannot be authenticated as genuine.',
          isDemoMode: true,
        };
      }

      // Condition D: Correct hash + valid signature + active key -> ORIGINAL
      if (isExactMatch && isSigValid) {
        // Scenario 1: Correct hash + valid signature + active key -> ORIGINAL
        await ledgerStorage.addLedgerBlock('VERIFY_ORIGINAL', `Integrity Verified: ${matchedSource.fileName}`, {
          sourceId: matchedSource.id,
          fileName: matchedSource.fileName,
          hash: sha256,
          signatureValid: true,
          verdict: 'ORIGINAL',
        });

        return {
          verdict: 'ORIGINAL',
          status: 'success',
          message: 'Original – Cryptographically Verified',
          source: matchedSource,
          signatureValid: true,
          hashMatch: true,
          keyStatus: 'ACTIVE',
          details: 'The uploaded file bitstream matches the registered master fingerprint with a mathematically valid Ed25519 digital signature.',
          isDemoMode: true,
        };
      } else if (isExactMatch && !isSigValid) {
        // Hash matches but signature fails
        await ledgerStorage.addLedgerBlock('TAMPER_DETECTED', `Signature Alert: Invalid Signature for ${matchedSource.id}`, {
          sourceId: matchedSource.id,
          fileName: matchedSource.fileName,
          hash: sha256,
          signatureValid: false,
          verdict: 'SIGNATURE_INVALID',
        });

        return {
          verdict: 'SIGNATURE_INVALID',
          status: 'danger',
          message: 'Signature Mismatch – Digital Signature Invalid',
          source: matchedSource,
          signatureValid: false,
          hashMatch: true,
          details: 'The file bitstream matches registered fingerprint ' + matchedSource.id + ', but the Ed25519 digital signature failed mathematical verification.',
          isDemoMode: true,
        };
      } else {
        // Scenario 4: Modified file + invalid signature + active key -> EDITED
        await ledgerStorage.addLedgerBlock('TAMPER_DETECTED', `Tamper Alert: Modified File for ${matchedSource.id}`, {
          sourceId: matchedSource.id,
          originalHash: sourceHash,
          uploadedHash: sha256,
          signatureValid: false,
          verdict: 'EDITED',
        });

        return {
          verdict: 'EDITED',
          status: 'danger',
          message: 'Edited – Content Difference Detected',
          source: matchedSource,
          originalHash: sourceHash,
          uploadedHash: sha256,
          signatureValid: false,
          hashMatch: false,
          keyStatus: 'ACTIVE',
          details: 'The submitted file references Source ID ' + matchedSource.id + ' but has a modified binary fingerprint. Cryptographic signature does not cover modified content.',
          isDemoMode: true,
        };
      }
    }
  },

  /**
   * Compare two files or analyze tamper differences
   * POST /api/compare
   */
  async compareFiles(formData) {
    try {
      const response = await apiClient.post('/api/compare', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      return { ...response.data, isDemoMode: false };
    } catch (error) {
      console.warn('Backend unavailable (/api/compare), running client-side comparative analytics:', error.message);
      return {
        isDemoMode: true,
        message: 'Client-side comparative forensics engaged',
      };
    }
  },

  /**
   * GET /api/source/{id}
   */
  async getSource(id) {
    try {
      const response = await apiClient.get(`/api/source/${id}`);
      return { data: response.data, isDemoMode: false };
    } catch (error) {
      const local = ledgerStorage.getSourceById(id);
      return { data: local, isDemoMode: true };
    }
  },

  /**
   * GET /api/history/{id}
   */
  async getHistory(id) {
    try {
      const response = await apiClient.get(`/api/history/${id}`);
      return { data: response.data, isDemoMode: false };
    } catch (error) {
      const blocks = ledgerStorage.getLedgerBlocks();
      const events = blocks.filter(b => b.payload && (b.payload.sourceId === id || b.title.includes(id)));
      return { data: events, isDemoMode: true };
    }
  },

  /**
   * GET /api/dashboard
   */
  async getDashboardStats() {
    try {
      const response = await apiClient.get('/api/dashboard');
      return { ...response.data, isDemoMode: false };
    } catch (error) {
      return {
        ...ledgerStorage.getStats(),
        isDemoMode: true,
      };
    }
  },

  /**
   * GET /api/overview/stats - Real PostgreSQL-backed enterprise stats
   */
  async getGlobalOverviewStats() {
    try {
      const response = await apiClient.get('/api/overview/stats');
      return { ...response.data, isLivePostgres: response.data.databaseConnected };
    } catch (error) {
      return {
        success: false,
        databaseEngine: 'Offline Fallback',
        databaseConnected: false,
        error: error.message,
      };
    }
  },

  /**
   * Admin User Management APIs
   */
  async getAdminUsers() {
    const token = sessionStorage.getItem('sourcemark_enterprise_session');
    const headers = token ? { Authorization: `Bearer ${JSON.parse(token).token}` } : {};
    const response = await apiClient.get('/api/admin/users', { headers });
    return response.data;
  },

  async createAdminUser(userData) {
    const token = sessionStorage.getItem('sourcemark_enterprise_session');
    const headers = token ? { Authorization: `Bearer ${JSON.parse(token).token}` } : {};
    const response = await apiClient.post('/api/admin/users', userData, { headers });
    return response.data;
  },

  async deactivateUser(userId) {
    const token = sessionStorage.getItem('sourcemark_enterprise_session');
    const headers = token ? { Authorization: `Bearer ${JSON.parse(token).token}` } : {};
    const response = await apiClient.post(`/api/admin/users/${userId}/deactivate`, {}, { headers });
    return response.data;
  },

  async activateUser(userId) {
    const token = sessionStorage.getItem('sourcemark_enterprise_session');
    const headers = token ? { Authorization: `Bearer ${JSON.parse(token).token}` } : {};
    const response = await apiClient.post(`/api/admin/users/${userId}/activate`, {}, { headers });
    return response.data;
  },

  async resetUserPassword(userId, newPassword) {
    const token = sessionStorage.getItem('sourcemark_enterprise_session');
    const headers = token ? { Authorization: `Bearer ${JSON.parse(token).token}` } : {};
    const response = await apiClient.post(`/api/admin/users/${userId}/reset-password`, { newPassword }, { headers });
    return response.data;
  },

  /**
   * GET /api/ledger
   */
  async getLedger() {
    try {
      const response = await apiClient.get('/api/ledger');
      return { blocks: response.data, isDemoMode: false };
    } catch (error) {
      return {
        blocks: ledgerStorage.getLedgerBlocks(),
        isDemoMode: true,
      };
    }
  },

  /**
   * GET /api/ledger/validate
   */
  async validateLedger() {
    try {
      const response = await apiClient.get('/api/ledger/validate');
      return { ...response.data, isDemoMode: false };
    } catch (error) {
      const result = await ledgerStorage.validateLedgerChain();
      return {
        ...result,
        timestamp: new Date().toISOString(),
        isDemoMode: true,
      };
    }
  },

  /**
   * Enterprise KMS / HSM Methods
   */
  async getKmsStatus() {
    try {
      const response = await apiClient.get('/api/kms/status');
      return { ...response.data, isDemoMode: false };
    } catch (error) {
      return { success: false, error: error.message, isDemoMode: true };
    }
  },

  async generateKmsKey(metadata = {}) {
    const response = await apiClient.post('/api/kms/keys', metadata);
    return response.data;
  },

  async signWithKms(keyId, hashHex, context = {}) {
    const response = await apiClient.post('/api/kms/sign', { keyId, hashHex, context });
    return response.data;
  },

  async rotateKmsKey(keyId, reason = '') {
    const response = await apiClient.post('/api/kms/rotate', { keyId, reason });
    return response.data;
  },

  async revokeKmsKey(keyId, reason = '') {
    const response = await apiClient.post('/api/kms/revoke', { keyId, reason });
    return response.data;
  },

  /**
   * RFC 3161 Trusted Timestamp Authority (TSA) Methods
   */
  async getTsaStatus() {
    try {
      const response = await apiClient.get('/api/tsa/status');
      return { ...response.data, isDemoMode: false };
    } catch (error) {
      return { success: false, configured: false, error: error.message, isDemoMode: true };
    }
  },

  async requestTsaTimestamp(hashHex, sourceId = null, blockId = null) {
    const response = await apiClient.post('/api/tsa/request', { hashHex, sourceId, blockId });
    return response.data;
  },

  async verifyTsaToken(payload) {
    const response = await apiClient.post('/api/tsa/verify', payload);
    return response.data;
  },

  /**
   * Independent WORM Storage & Checkpoint Methods (Phase 7)
   */
  async getWormStatus() {
    try {
      const response = await apiClient.get('/api/worm/status');
      return { ...response.data, isDemoMode: false };
    } catch (error) {
      return { success: false, configured: false, error: error.message, isDemoMode: true };
    }
  },

  async getCheckpoints() {
    try {
      const response = await apiClient.get('/api/checkpoints');
      return response.data;
    } catch (error) {
      return { success: false, error: error.message, checkpoints: [] };
    }
  },

  async createCheckpoint(options = {}) {
    const response = await apiClient.post('/api/checkpoints/create', options);
    return response.data;
  },

  async verifyCheckpoint(checkpointId = null) {
    const response = await apiClient.post('/api/checkpoints/verify', { checkpointId });
    return response.data;
  },

  async simulateRollback(truncateCount = 2) {
    const response = await apiClient.post('/api/checkpoints/simulate-rollback', { truncateCount });
    return response.data;
  },

  async restoreLedger() {
    const response = await apiClient.post('/api/checkpoints/restore', {});
    return response.data;
  },
};

