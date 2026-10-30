import axios from 'axios';
import { ledgerStorage } from './ledgerStorage';
import { verifyFingerprintSignature } from './crypto';

const BASE_URL = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

const apiClient = axios.create({
  baseURL: BASE_URL,
  timeout: 3500, // Quick timeout to detect offline backend
  headers: {
    'Content-Type': 'application/json',
  },
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
      // In demo mode: save to local verified ledger
      const sourceRecord = ledgerStorage.addSource({
        ...payload,
        id: payload.id || `SRC-${Math.floor(10000 + Math.random() * 90000)}`,
        registeredAt: new Date().toISOString(),
        status: 'ACTIVE_REGISTERED',
        verificationCount: 0,
        lastVerifiedAt: null,
      });

      return {
        success: true,
        data: sourceRecord,
        isDemoMode: true,
        message: 'Source registered in Local Cryptographic Ledger (Demo Mode - Backend Offline)',
      };
    }
  },

  /**
   * Verify file authenticity
   * POST /api/verify
   * Payload: { sha256, sourceId, fileName, signature, publicKey }
   */
  async verifySource(payload) {
    try {
      const response = await apiClient.post('/api/verify', payload);
      return { ...response.data, isDemoMode: false };
    } catch (error) {
      console.warn('Backend unavailable (/api/verify), verifying using browser cryptographic engine:', error.message);
      
      const { sha256, sourceId } = payload;
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

      // Check if hashes match
      const isExactMatch = matchedSource.sha256.toLowerCase() === sha256.toLowerCase();

      // Cryptographically verify the Ed25519 signature
      const isSigValid = verifyFingerprintSignature(
        matchedSource.sha256,
        matchedSource.signature,
        matchedSource.publicKey
      );

      if (isExactMatch && isSigValid) {
        // STRICT ORIGINAL: Both hash AND Ed25519 signature are valid
        matchedSource.verificationCount = (matchedSource.verificationCount || 0) + 1;
        matchedSource.lastVerifiedAt = new Date().toISOString();

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
          details: 'The uploaded file bitstream matches the registered master fingerprint with a mathematically valid Ed25519 digital signature.',
          isDemoMode: true,
        };
      } else if (isExactMatch && !isSigValid) {
        // HASH MATCHES BUT SIGNATURE FAILED MATHEMATICAL VERIFICATION
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
          details: 'The file bitstream matches registered fingerprint ' + matchedSource.id + ', but the Ed25519 digital signature failed mathematical verification. Content origin cannot be authenticated.',
          isDemoMode: true,
        };
      } else {
        // EDITED: Hash does not match the registered source that was specifically requested
        await ledgerStorage.addLedgerBlock('TAMPER_DETECTED', `Tamper Alert: Modified File for ${matchedSource.id}`, {
          sourceId: matchedSource.id,
          originalHash: matchedSource.sha256,
          uploadedHash: sha256,
          signatureValid: false,
          verdict: 'EDITED',
        });

        return {
          verdict: 'EDITED',
          status: 'danger',
          message: 'Edited – Content Difference Detected',
          source: matchedSource,
          originalHash: matchedSource.sha256,
          uploadedHash: sha256,
          signatureValid: false,
          hashMatch: false,
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
};

