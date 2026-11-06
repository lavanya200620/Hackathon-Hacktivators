/**
 * SourceMark Key Security Centre Service
 * Manages signing key registry, compromise state, key rotation, and 
 * retroactive signature validity determination.
 */

import nacl from 'tweetnacl';
import { bufferToHex, setEphemeralRotatedKey } from './crypto.js';
import { ledgerStorage } from './ledgerStorage.js';

const KEY_REGISTRY_KEY = 'sourcemark_key_registry';

const INITIAL_KEYS = [
  {
    id: 'ED25519-2A71A707',
    publicKeyHex: '2a71a70705363c8fd0e154e5ac0386725dba39fdc8d175f9cf688ffd63af4a9f',
    owner: 'Dr. Evelyn Vance (Chief Geoint Analyst)',
    ownerId: 'AGY-USR-0042',
    role: 'Primary Satellite Geoint Authority',
    status: 'ACTIVE', // 'ACTIVE' | 'COMPROMISED' | 'REVOKED' | 'REPLACED'
    createdAt: '2026-09-15T00:00:00.000Z',
    compromisedAt: null,
    revokedAt: null,
    replacementKeyId: null,
    algorithm: 'Ed25519 / Curve25519',
    usageCount: 42,
    incidents: [],
  },
  {
    id: 'ED25519-A19B169B',
    publicKeyHex: 'a19b169bb061b6f37bef103a0049f43f5451c958dfcbf4222deeeb2685f26b51',
    owner: 'SecOps Build Automation (Demo Authority)',
    ownerId: 'SYSTEM-CI-BUILD',
    role: 'Automated CI/CD Firmware Signing',
    status: 'ACTIVE',
    createdAt: '2026-08-01T00:00:00.000Z',
    compromisedAt: null,
    revokedAt: null,
    replacementKeyId: null,
    algorithm: 'Ed25519 / Curve25519',
    usageCount: 156,
    incidents: [],
  },
  {
    id: 'ED25519-1D4CBE1A',
    publicKeyHex: '1d4cbe1ad10ab20738f35f97fc446a9dcddd82a5297ab807647805c5f8f91420',
    owner: 'Sarah Jenkins, Esq. (Legal Counsel)',
    ownerId: 'AGY-USR-0119',
    role: 'Corporate Legal & Governance Vault',
    status: 'ACTIVE',
    createdAt: '2026-07-20T00:00:00.000Z',
    compromisedAt: null,
    revokedAt: null,
    replacementKeyId: null,
    algorithm: 'Ed25519 / Curve25519',
    usageCount: 29,
    incidents: [],
  },
  {
    id: 'ED25519-LEGACY-01',
    publicKeyHex: 'f0e1d2c3b4a5968778695a4b3c2d1e0f0e1d2c3b4a5968778695a4b3c2d1e0f0',
    owner: 'Field Telemetry Node Delta',
    ownerId: 'NODE-SENSOR-DELTA',
    role: 'Decommissioned Edge Node',
    status: 'REPLACED',
    createdAt: '2026-01-10T00:00:00.000Z',
    compromisedAt: null,
    revokedAt: '2026-06-01T12:00:00.000Z',
    replacementKeyId: 'ED25519-2A71A707',
    algorithm: 'Ed25519 / Curve25519',
    usageCount: 88,
    incidents: ['Scheduled cryptographic key retirement after 6-month lifecycle.'],
  }
];

export const keySecurityService = {
  getTrustedRegistry() {
    return this.getKeys();
  },

  getKeys() {
    try {
      const data = localStorage.getItem(KEY_REGISTRY_KEY);
      let keys = data ? JSON.parse(data) : [...INITIAL_KEYS];
      if (!data) {
        localStorage.setItem(KEY_REGISTRY_KEY, JSON.stringify(INITIAL_KEYS));
      }

      // Sync active session demo key if present and not yet registered
      try {
        const sessionKeyData = localStorage.getItem('sourcemark_ed25519_keypair');
        if (sessionKeyData) {
          const parsed = JSON.parse(sessionKeyData);
          if (parsed && (parsed.keyId || parsed.publicKeyHex)) {
            const exists = keys.find(k => 
              (parsed.keyId && k.id && k.id.toLowerCase() === parsed.keyId.toLowerCase()) ||
              (parsed.publicKeyHex && k.publicKeyHex && k.publicKeyHex.toLowerCase() === parsed.publicKeyHex.toLowerCase())
            );
            if (!exists) {
              const sessionKey = {
                id: parsed.keyId || `ED25519-${parsed.publicKeyHex.substring(0, 8).toUpperCase()}`,
                publicKeyHex: parsed.publicKeyHex,
                owner: 'Authorized Demo Custodian (Current Session)',
                ownerId: 'LOCAL-SESSION-CUSTODIAN',
                role: 'Active Provenance Authority (Demo)',
                status: 'ACTIVE',
                createdAt: parsed.createdAt || new Date().toISOString(),
                compromisedAt: null,
                revokedAt: null,
                replacementKeyId: null,
                algorithm: 'Ed25519 / Curve25519',
                usageCount: 1,
                incidents: [],
                isDemoKey: true,
                hardwareBacked: false,
              };
              keys.push(sessionKey);
              localStorage.setItem(KEY_REGISTRY_KEY, JSON.stringify(keys));
            }
          }
        }
      } catch (err) {}

      return keys;
    } catch (e) {
      return INITIAL_KEYS;
    }
  },

  /**
   * Register or catalog a key in the public key trust registry
   */
  registerKey(keyData) {
    if (!keyData || (!keyData.id && !keyData.publicKeyHex)) return null;
    const keys = this.getKeys();
    const id = keyData.id || (keyData.publicKeyHex ? `ED25519-${keyData.publicKeyHex.substring(0, 8).toUpperCase()}` : null);
    
    // Check if key already exists by ID or public key hex
    const existing = keys.find(k => 
      (id && k.id && k.id.toLowerCase() === id.toLowerCase()) ||
      (keyData.publicKeyHex && k.publicKeyHex && k.publicKeyHex.toLowerCase() === keyData.publicKeyHex.toLowerCase())
    );
    
    if (existing) {
      return existing; // Preserve existing status (e.g. if already COMPROMISED or REVOKED)
    }

    const newKey = {
      id: id || `KEY-${Date.now().toString(36).toUpperCase()}`,
      publicKeyHex: keyData.publicKeyHex || '',
      owner: keyData.owner || keyData.creator || 'Authorized Demo Custodian',
      ownerId: keyData.ownerId || keyData.creatorId || 'CUSTODIAN-DEMO',
      role: keyData.role || 'Active Registration Authority (Demo)',
      status: keyData.status || 'ACTIVE',
      createdAt: keyData.createdAt || new Date().toISOString(),
      compromisedAt: null,
      revokedAt: null,
      replacementKeyId: null,
      algorithm: keyData.algorithm || 'Ed25519 / Curve25519',
      usageCount: 1,
      incidents: [],
      isDemoKey: true,
      hardwareBacked: false,
    };

    keys.push(newKey);
    this.saveKeys(keys);
    return newKey;
  },

  getKeyById(id) {
    if (!id) return null;
    const keys = this.getKeys();
    const clean = id.trim().toLowerCase();
    return keys.find(k => k.id.toLowerCase() === clean || (k.publicKeyHex && k.publicKeyHex.toLowerCase() === clean));
  },

  getCompromisedKeys() {
    const keys = this.getKeys();
    return keys.filter(k => k.status === 'COMPROMISED');
  },

  isKeyCompromised(publicKeyOrId) {
    if (!publicKeyOrId) return false;
    const target = this.getKeyById(publicKeyOrId);
    return target ? target.status === 'COMPROMISED' : false;
  },

  isKeyRevoked(publicKeyOrId) {
    if (!publicKeyOrId) return false;
    const target = this.getKeyById(publicKeyOrId);
    return target ? (target.status === 'REVOKED' || target.status === 'COMPROMISED') : false;
  },

  /**
   * Comprehensive evaluation of signing key status and historical validity
   */
  evaluateKeyStatus(keyIdOrPublicKey, trustedRecordTimestamp = null) {
    if (!keyIdOrPublicKey) {
      return {
        status: 'MISSING_OR_UNAVAILABLE',
        isTrusted: false,
        verdict: 'REQUIRES_INVESTIGATION',
        reason: 'Signing key identifier is missing or unavailable.',
        key: null,
      };
    }

    const key = this.getKeyById(keyIdOrPublicKey);
    if (!key) {
      return {
        status: 'MISSING_OR_UNAVAILABLE',
        isTrusted: false,
        verdict: 'REQUIRES_INVESTIGATION',
        reason: `Signing key "${keyIdOrPublicKey}" is uncatalogued in public key trust registry.`,
        key: null,
      };
    }

    // 1. ACTIVE Key
    if (key.status === 'ACTIVE') {
      return {
        status: 'ACTIVE',
        isTrusted: true,
        verdict: 'ACTIVE',
        reason: 'Signing key is active and uncompromised.',
        key,
      };
    }

    // 2. COMPROMISED Key
    if (key.status === 'COMPROMISED') {
      // If compromise timestamp is missing / unknown
      if (!key.compromisedAt) {
        return {
          status: 'COMPROMISED_UNKNOWN_TIME',
          isTrusted: false,
          verdict: 'REQUIRES_INVESTIGATION',
          reason: 'Signing key was compromised at an undetermined timestamp; signature flagged for mandatory forensic review.',
          key,
        };
      }

      // Check trusted timestamp evidence against compromise time
      let isTimestampTrusted = false;
      let recordTime = null;

      if (trustedRecordTimestamp) {
        if (typeof trustedRecordTimestamp === 'object' && trustedRecordTimestamp !== null) {
          isTimestampTrusted = trustedRecordTimestamp.isTrusted === true;
          recordTime = trustedRecordTimestamp.timestamp ? new Date(trustedRecordTimestamp.timestamp).getTime() : null;
        } else if (typeof trustedRecordTimestamp === 'string') {
          isTimestampTrusted = typeof arguments[2] === 'boolean' ? arguments[2] : true;
          recordTime = new Date(trustedRecordTimestamp).getTime();
        }
      }

      const compTime = new Date(key.compromisedAt).getTime();

      // Rule: If record timestamp is at or after compromise time, it is definitively compromised
      if (recordTime && recordTime >= compTime) {
        return {
          status: 'POST_COMPROMISE_BREACH',
          isTrusted: false,
          verdict: 'COMPROMISED_KEY',
          reason: `CRITICAL: Asset was signed or timestamped at or after the established key compromise time (${key.compromisedAt}).`,
          key,
        };
      }

      // Rule: If candidate timestamp claims to be before compromise time, but lacks verifiable trusted evidence (TSA/ledger proof):
      // Do NOT assume pre-compromise validity!
      if (!recordTime || !isTimestampTrusted) {
        return {
          status: 'UNKNOWN_SIGNING_TIME',
          isTrusted: false,
          verdict: 'REQUIRES_INVESTIGATION',
          reason: 'Signing key is reported COMPROMISED. Signing timestamp is unverified (lacks an independent RFC 3161 TSA token or ledger proof); cannot assume signature was created before key compromise.',
          key,
        };
      }

      // Rule: Verified trusted timestamp is strictly before compromise time:
      return {
        status: 'PRE_COMPROMISE_VALID',
        isTrusted: true,
        verdict: 'PRE_COMPROMISE_VALID',
        reason: `Cryptographically verified by trusted timestamp authority (${new Date(recordTime).toLocaleDateString()}) prior to recorded key breach time (${new Date(compTime).toLocaleDateString()}).`,
        key,
      };
    }

    // 3. REVOKED Key
    if (key.status === 'REVOKED') {
      return {
        status: 'REVOKED',
        isTrusted: false,
        verdict: 'COMPROMISED_KEY',
        reason: `Signing key authority was revoked at ${key.revokedAt || 'unknown time'}.`,
        key,
      };
    }

    // 4. REPLACED / ROTATED Key
    if (key.status === 'REPLACED') {
      if (trustedRecordTimestamp && key.revokedAt) {
        const recordTime = new Date(trustedRecordTimestamp).getTime();
        const revTime = new Date(key.revokedAt).getTime();
        if (recordTime <= revTime) {
          return {
            status: 'REPLACED_HISTORICALLY_VALID',
            isTrusted: true,
            verdict: 'PRE_COMPROMISE_VALID',
            reason: 'Asset was signed prior to scheduled key rotation and decommissioning.',
            key,
          };
        }
      }

      return {
        status: 'POST_REPLACEMENT_SIGNATURE',
        isTrusted: false,
        verdict: 'REQUIRES_INVESTIGATION',
        reason: `Asset references retired key superseded by ${key.replacementKeyId || 'new authority'}.`,
        key,
      };
    }

    return {
      status: key.status || 'UNKNOWN',
      isTrusted: false,
      verdict: 'REQUIRES_INVESTIGATION',
      reason: 'Key status requires manual administrative forensic triage.',
      key,
    };
  },

  saveKeys(keys) {
    localStorage.setItem(KEY_REGISTRY_KEY, JSON.stringify(keys));
  },

  /**
   * Simulate a Stolen Signing Key Attack
   */
  async simulateStolenKey(keyId, note = 'Simulated unauthorized exfiltration of private key material') {
    const keys = this.getKeys();
    const now = new Date().toISOString();
    let affectedKey = null;

    const updated = keys.map(k => {
      if (k.id === keyId) {
        affectedKey = {
          ...k,
          status: 'COMPROMISED',
          compromisedAt: now,
          revokedAt: now,
          incidents: [
            ...(k.incidents || []),
            `SECURITY INCIDENT [${now}]: Stolen signing key alert triggered. ${note}`
          ]
        };
        return affectedKey;
      }
      return k;
    });

    this.saveKeys(updated);

    // Append incident to append-only audit ledger
    try {
      await ledgerStorage.addLedgerBlock('KEY_SECURITY_INCIDENT', `Security Alert: Key Compromised (${keyId})`, {
        action: 'KEY_COMPROMISE_FLAGGED',
        keyId,
        compromisedAt: now,
        severity: 'CRITICAL',
        note,
      });
    } catch (e) {
      console.warn('Ledger logging error for stolen key:', e);
    }

    return affectedKey;
  },

  /**
   * Formally revoke an authority signing key
   */
  async revokeKey(keyId, reason = 'Administrative Authority Revocation') {
    const keys = this.getKeys();
    const now = new Date().toISOString();
    let revoked = null;

    const updated = keys.map(k => {
      if (k.id === keyId) {
        revoked = {
          ...k,
          status: 'REVOKED',
          revokedAt: now,
          incidents: [
            ...(k.incidents || []),
            `REVOCATION EVENT [${now}]: Authority permanently revoked. Reason: ${reason}`
          ]
        };
        return revoked;
      }
      return k;
    });

    this.saveKeys(updated);

    try {
      await ledgerStorage.addLedgerBlock('KEY_REVOCATION', `Key Authority Revoked: ${keyId}`, {
        action: 'KEY_REVOKED',
        keyId,
        revokedAt: now,
        reason,
      });
    } catch (e) {
      console.warn('Ledger logging error for key revocation:', e);
    }

    return revoked;
  },

  /**
   * Register a new or rotated replacement key
   */
  async rotateKey(oldKeyId, reasonOrData = 'Cryptographic Key Lifecycle Rotation') {
    const keys = this.getKeys();
    const now = new Date().toISOString();

    let newKeyData;
    let newSecretHex = null;
    if (typeof reasonOrData === 'object' && reasonOrData !== null && reasonOrData.id) {
      newKeyData = reasonOrData;
    } else {
      // Generate a fresh authentic Ed25519 keypair
      const kp = nacl.sign.keyPair();
      const pubHex = bufferToHex(kp.publicKey);
      newSecretHex = bufferToHex(kp.secretKey);
      const newId = `ED25519-${pubHex.substring(0, 8).toUpperCase()}`;
      newKeyData = {
        id: newId,
        publicKeyHex: pubHex,
        owner: 'Dr. Evelyn Vance (Rotated Authority)',
        ownerId: 'AGY-USR-0042',
        role: 'Primary Satellite Geoint Authority (Rotated)',
        algorithm: 'Ed25519 / Curve25519',
      };

      // Update in-memory session active keypair without saving private keys to localStorage
      try {
        setEphemeralRotatedKey(pubHex, kp.secretKey, newId);
        if (typeof localStorage !== 'undefined') {
          localStorage.removeItem('sourcemark_ed25519_keypair');
        }
      } catch (e) {
        console.warn('Session key update error:', e);
      }
    }

    const updated = keys.map(k => {
      if (k.id === oldKeyId) {
        return {
          ...k,
          status: k.status === 'COMPROMISED' ? 'REVOKED' : 'REPLACED',
          revokedAt: now,
          replacementKeyId: newKeyData.id,
          incidents: [
            ...(k.incidents || []),
            `ROTATION EVENT [${now}]: Key retired and superseded by ${newKeyData.id}`
          ]
        };
      }
      return k;
    });

    const newKey = {
      ...newKeyData,
      status: 'ACTIVE',
      createdAt: now,
      compromisedAt: null,
      revokedAt: null,
      replacementKeyId: null,
      usageCount: 0,
      incidents: [`COMMISSIONED [${now}]: Created as authoritative replacement for ${oldKeyId}`],
      rotationHistory: [
        {
          predecessorKeyId: oldKeyId,
          rotatedAt: now,
          reason: typeof reasonOrData === 'string' ? reasonOrData : 'Key lifecycle rotation',
        }
      ]
    };

    updated.unshift(newKey);
    this.saveKeys(updated);

    try {
      await ledgerStorage.addLedgerBlock('KEY_ROTATION', `Cryptographic Key Rotated: ${oldKeyId} -> ${newKey.id}`, {
        action: 'KEY_ROTATION',
        retiredKeyId: oldKeyId,
        commissionedKeyId: newKey.id,
        timestamp: now,
      });
    } catch (e) {
      console.warn('Ledger logging error for key rotation:', e);
    }

    return { success: true, newKey };
  },

  /**
   * Run retroactive validation across a collection of ledger records
   */
  validateRetroactiveSignatures(keyId, ledger = []) {
    let validCount = 0;
    let suspiciousCount = 0;
    const evaluatedRecords = [];

    const key = this.getKeyById(keyId);
    if (!key) {
      return {
        keyId,
        validCount: 0,
        suspiciousCount: 0,
        status: 'KEY_NOT_FOUND',
        records: []
      };
    }

    for (const record of ledger) {
      const ts = record.signedAt || record.signatureTimestamp || record.timestamp || record.registeredAt || new Date().toISOString();
      const evalResult = this.revalidateSignature(keyId, ts);

      if (evalResult.valid) {
        validCount++;
      } else {
        suspiciousCount++;
      }

      evaluatedRecords.push({
        recordId: record.id || record.sourceId || 'SRC-UNKNOWN',
        fileName: record.fileName || 'Asset',
        timestamp: ts,
        evalResult
      });
    }

    return {
      keyId,
      keyStatus: key.status,
      validCount,
      suspiciousCount,
      status: key.status === 'COMPROMISED' ? 'COMPROMISED_AUDIT_COMPLETE' : 'AUDIT_COMPLETE',
      records: evaluatedRecords
    };
  },

  resetToDefaults() {
    return this.resetRegistry();
  },

  /**
   * Revalidate signature against key compromise history:
   * Rule A: Signature created BEFORE compromise timestamp remains VALID.
   * Rule B: Signature created AFTER compromise timestamp is FLAGGED / INVESTIGATION REQUIRED.
   * Rule C: If compromise timestamp is unknown, mark as FLAGGED.
   */
  revalidateSignature(keyId, registrationTimestamp) {
    const key = this.getKeyById(keyId);
    if (!key) {
      return {
        status: 'UNKNOWN_KEY',
        valid: false,
        flagged: true,
        reason: 'Signing key identifier is not catalogued in trust registry.'
      };
    }

    if (key.status === 'ACTIVE') {
      return {
        status: 'ACTIVE',
        valid: true,
        flagged: false,
        reason: 'Signing key is active and uncompromised.'
      };
    }

    if (key.status === 'REPLACED') {
      const regTime = new Date(registrationTimestamp).getTime();
      const revTime = new Date(key.revokedAt).getTime();
      if (regTime <= revTime) {
        return {
          status: 'REPLACED_HISTORICALLY_VALID',
          valid: true,
          flagged: false,
          reason: 'Signed prior to scheduled key rotation.'
        };
      } else {
        return {
          status: 'POST_REPLACEMENT_SIGNATURE',
          valid: false,
          flagged: true,
          reason: 'Signed after key was decommissioned and rotated.'
        };
      }
    }

    if (key.status === 'COMPROMISED' || key.status === 'REVOKED') {
      if (!key.compromisedAt) {
        return {
          status: 'COMPROMISED_UNKNOWN_TIME',
          valid: false,
          flagged: true,
          reason: 'Key compromised at undetermined timestamp; signature flagged for mandatory forensic review.'
        };
      }

      const regTime = new Date(registrationTimestamp).getTime();
      const compTime = new Date(key.compromisedAt).getTime();

      if (regTime < compTime) {
        return {
          status: 'PRE_COMPROMISE_VALID',
          valid: true,
          flagged: false,
          reason: 'Cryptographically registered and sealed prior to recorded key breach time.'
        };
      } else {
        return {
          status: 'POST_COMPROMISE_BREACH',
          valid: false,
          flagged: true,
          reason: 'CRITICAL: File was signed AFTER key was exfiltrated/compromised. Possible unauthorized forgery.'
        };
      }
    }

    return { status: key.status, valid: false, flagged: true, reason: 'Key state requires investigation.' };
  },

  resetRegistry() {
    localStorage.setItem(KEY_REGISTRY_KEY, JSON.stringify(INITIAL_KEYS));
    return INITIAL_KEYS;
  }
};

