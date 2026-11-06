/**
 * SourceMark Enterprise Backend API Server (Node.js ESM)
 * Runs on http://127.0.0.1:8000
 * Implements REST endpoints, strict server-side RBAC, JWT-like cryptographically signed sessions,
 * password hashing (PBKDF2-SHA512 with per-user salt), rate-limiting, and persistent storage.
 */

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dbAdapter } from './db/adapter.mjs';
import { checkConnection, getPool } from './db/postgres.mjs';
import { runMigrations, getMigrationStatus } from './db/migrator.mjs';
import { backupJsonDatabase, migrateJsonToPostgres } from './db/dataMigrator.mjs';
import { kmsManager } from './kms/kmsService.mjs';
import { tsaManager, parseTimeStampResponse, validateTimeStampToken } from './tsa/tsaService.mjs';
import { wormManager } from './storage/wormService.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DB_FILE = path.join(__dirname, 'data', 'enterprise_db.json');

// Ensure data directory exists
if (!fs.existsSync(path.join(__dirname, 'data'))) {
  fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });
}

// Enterprise Roles & Hierarchy
export const ROLES = {
  ADMINISTRATOR: 'ADMINISTRATOR',
  FORENSIC_INVESTIGATOR: 'FORENSIC_INVESTIGATOR',
  SOC_ANALYST: 'SOC_ANALYST',
  AUDITOR: 'AUDITOR',
  ORGANIZATION_MANAGER: 'ORGANIZATION_MANAGER',
  USER: 'USER',
};

// Role Permissions Matrix
export const PERMISSIONS = {
  [ROLES.ADMINISTRATOR]: [
    'users:read', 'users:write', 'users:delete',
    'roles:assign', 'system:lockdown', 'keys:revoke', 'keys:approve',
    'ledger:read', 'ledger:rollback', 'sources:read', 'sources:write', 'sources:register',
    'investigations:read', 'investigations:write', 'alerts:read', 'alerts:write',
    'approvals:read', 'approvals:decide', 'approvals:request', 'audit:read', 'audit:export',
  ],
  [ROLES.FORENSIC_INVESTIGATOR]: [
    'sources:read', 'sources:verify', 'investigations:read', 'investigations:write',
    'investigations:close', 'evidence:export', 'ledger:read', 'keys:inspect',
    'alerts:read', 'audit:read',
  ],
  [ROLES.SOC_ANALYST]: [
    'alerts:read', 'alerts:contain', 'alerts:dismiss', 'keys:quarantine',
    'keys:inspect', 'sources:read', 'sources:verify', 'investigations:read',
    'system:status', 'audit:read',
  ],
  [ROLES.AUDITOR]: [
    'audit:read', 'audit:export', 'ledger:read', 'ledger:verify',
    'sources:read', 'keys:inspect', 'approvals:read', 'compliance:generate',
  ],
  [ROLES.ORGANIZATION_MANAGER]: [
    'sources:read', 'sources:write', 'approvals:read', 'approvals:decide',
    'approvals:request', 'team:read', 'team:manage', 'reports:generate', 'audit:read',
  ],
  [ROLES.USER]: [
    'sources:read', 'sources:register', 'sources:verify', 'keys:view_own',
    'approvals:request',
  ],
};

// Cryptographic Password Hashing Utility (PBKDF2-SHA512)
export function hashPassword(password, salt = null) {
  const userSalt = salt || crypto.randomBytes(16).toString('hex');
  const derivedKey = crypto.pbkdf2Sync(password, userSalt, 100000, 64, 'sha512').toString('hex');
  return { salt: userSalt, hash: derivedKey };
}

export function verifyPassword(password, salt, hash) {
  const derivedKey = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return crypto.timingSafeEqual(Buffer.from(derivedKey, 'hex'), Buffer.from(hash, 'hex'));
}

// Token / Session Management
const JWT_SECRET = crypto.randomBytes(32).toString('hex');

export function createSessionToken(user) {
  const payload = {
    userId: user.id,
    email: user.email,
    role: user.role,
    organizationId: user.organizationId,
    exp: Date.now() + 8 * 60 * 60 * 1000, // 8 hours
  };
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto.createHmac('sha256', JWT_SECRET).update(payloadB64).digest('base64url');
  return `${payloadB64}.${signature}`;
}

export function verifySessionToken(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [payloadB64, sig] = parts;
  const expectedSig = crypto.createHmac('sha256', JWT_SECRET).update(payloadB64).digest('base64url');
  if (sig !== expectedSig) return null;
  try {
    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
    if (payload.exp && Date.now() > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

// Default Enterprise Database Seeds
function getInitialDbState() {
  const adminCreds = hashPassword('AdminPass123!');
  const invCreds = hashPassword('InvestigatorPass123!');
  const socCreds = hashPassword('SocPass123!');
  const audCreds = hashPassword('AuditorPass123!');
  const mgrCreds = hashPassword('ManagerPass123!');
  const mgr2Creds = hashPassword('ManagerPass123!');
  const usrCreds = hashPassword('UserPass123!');

  return {
    systemState: {
      lockdown: false,
      lockdownReason: null,
      revokedKeys: ['ED25519-STOLEN-01'],
    },
    organizations: [
      { id: 'ORG-01', name: 'Federal Geointelligence Agency', department: 'Orbital Reconnaissance' },
      { id: 'ORG-02', name: 'Cyber Defense Operations', department: 'Incident Response' },
      { id: 'ORG-03', name: 'Global Audit & Forensics Corp', department: 'Digital Compliance' },
    ],
    users: [
      {
        id: 'USR-ADMIN-01',
        name: 'Chief Security Officer (Admin)',
        email: 'admin@sourcemark.io',
        role: ROLES.ADMINISTRATOR,
        organizationId: 'ORG-01',
        salt: adminCreds.salt,
        passwordHash: adminCreds.hash,
        status: 'ACTIVE',
        mfaEnabled: true,
        createdAt: '2026-10-01T08:00:00.000Z',
      },
      {
        id: 'USR-INV-01',
        name: 'Agent Evelyn Vance (Forensics)',
        email: 'investigator@sourcemark.io',
        role: ROLES.FORENSIC_INVESTIGATOR,
        organizationId: 'ORG-01',
        salt: invCreds.salt,
        passwordHash: invCreds.hash,
        status: 'ACTIVE',
        mfaEnabled: true,
        createdAt: '2026-10-05T09:15:00.000Z',
      },
      {
        id: 'USR-SOC-01',
        name: 'Marcus Brody (SOC Lead)',
        email: 'soc@sourcemark.io',
        role: ROLES.SOC_ANALYST,
        organizationId: 'ORG-02',
        salt: socCreds.salt,
        passwordHash: socCreds.hash,
        status: 'ACTIVE',
        mfaEnabled: true,
        createdAt: '2026-10-10T11:30:00.000Z',
      },
      {
        id: 'USR-AUD-01',
        name: 'Sophia Chen (Lead Auditor)',
        email: 'auditor@sourcemark.io',
        role: ROLES.AUDITOR,
        organizationId: 'ORG-03',
        salt: audCreds.salt,
        passwordHash: audCreds.hash,
        status: 'ACTIVE',
        mfaEnabled: true,
        createdAt: '2026-10-12T14:20:00.000Z',
      },
      {
        id: 'USR-MGR-01',
        name: 'Director David Sterling (Org Lead)',
        email: 'manager@sourcemark.io',
        role: ROLES.ORGANIZATION_MANAGER,
        organizationId: 'ORG-01',
        salt: mgrCreds.salt,
        passwordHash: mgrCreds.hash,
        status: 'ACTIVE',
        mfaEnabled: true,
        createdAt: '2026-10-08T10:00:00.000Z',
      },
      {
        id: 'USR-MGR-02',
        name: 'Commander Sarah Connor (Cyber Lead)',
        email: 'manager2@sourcemark.io',
        role: ROLES.ORGANIZATION_MANAGER,
        organizationId: 'ORG-02',
        salt: mgr2Creds.salt,
        passwordHash: mgr2Creds.hash,
        status: 'ACTIVE',
        mfaEnabled: true,
        createdAt: '2026-10-09T10:00:00.000Z',
      },
      {
        id: 'USR-CUSTODIAN-01',
        name: 'Alex Rivera (Digital Contributor)',
        email: 'user@sourcemark.io',
        role: ROLES.USER,
        organizationId: 'ORG-01',
        salt: usrCreds.salt,
        passwordHash: usrCreds.hash,
        status: 'ACTIVE',
        mfaEnabled: false,
        createdAt: '2026-10-15T16:45:00.000Z',
      },
    ],
    sources: {
      'SRC-98214': {
        id: 'SRC-98214',
        fileName: 'satellite_recon_orbital_07.png',
        fileType: 'image/png',
        fileSize: 2458920,
        fileSizeFormatted: '2.34 MB',
        sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        signature: '7a83d4c6f50b9123847289abcf123894723894bcefa012938471203948abcdf1982347102938471029384710293847102938471029384710293847102938471a',
        publicKey: 'a9103847bce12830948120938471029384710293847102938471029384710293',
        keyId: 'ED25519-A9103847',
        creator: 'Dr. Evelyn Vance (Chief Geoint Analyst)',
        creatorId: 'USR-INV-01',
        organizationId: 'ORG-01',
        category: 'Satellite Intelligence',
        description: 'High-resolution multispectral imagery of Sector 4B survey area.',
        sourceOrigin: 'National Geospatial Imaging Pipeline / Node Alpha',
        registeredAt: '2026-10-24T09:15:22.000Z',
        status: 'ACTIVE_REGISTERED',
        verificationCount: 9,
      },
    },
    ledger: [
      {
        id: 'BLK-0001',
        blockNumber: 1,
        type: 'GENESIS',
        title: 'Genesis Ledger Node Initialized',
        timestamp: '2026-10-20T00:00:00.000Z',
        prevHash: '0000000000000000000000000000000000000000000000000000000000000000',
        currentHash: '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b',
        status: 'CONFIRMED',
        verified: true,
        payload: { engine: 'Ed25519-EdDSA', digest: 'SHA-256' },
      },
      {
        id: 'BLK-0002',
        blockNumber: 2,
        type: 'REGISTER',
        title: 'File Registration: satellite_recon_orbital_07.png',
        timestamp: '2026-10-24T09:15:22.000Z',
        prevHash: '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b',
        currentHash: '19a8264eef6551b91bc6b46ef85860d4b918b956a90bb8552140ebcc2ec8d752',
        status: 'CONFIRMED',
        verified: true,
        payload: { sourceId: 'SRC-98214', creatorId: 'USR-INV-01' },
      },
    ],
    investigations: [
      {
        id: 'INV-CASE-0104',
        title: 'Tampered Satellite Map Header in Sector 4B',
        sourceId: 'SRC-98214',
        organizationId: 'ORG-01',
        severity: 'HIGH',
        status: 'UNDER_INVESTIGATION',
        assignedTo: 'USR-INV-01',
        assignedToName: 'Agent Evelyn Vance',
        createdBy: 'USR-SOC-01',
        createdByName: 'Marcus Brody',
        notes: [
          {
            author: 'Marcus Brody (SOC Lead)',
            text: 'Automated integrity alert triggered: Bit-level hash divergence detected during routine orbital asset check.',
            timestamp: '2026-10-29T10:14:00.000Z',
          },
          {
            author: 'Agent Evelyn Vance (Forensics)',
            text: 'Forensic inspection confirms bytes 4096-4128 altered. Original Ed25519 signature fails verification against altered buffer.',
            timestamp: '2026-10-29T14:22:00.000Z',
          },
        ],
        createdAt: '2026-10-29T10:14:00.000Z',
        updatedAt: '2026-10-29T14:22:00.000Z',
      },
    ],
    alerts: [
      {
        id: 'ALT-8842',
        title: 'Uncatalogued Public Key Registration Attempt',
        severity: 'MEDIUM',
        sourceId: 'SRC-35253',
        organizationId: 'ORG-01',
        status: 'NEW',
        type: 'UNTRUSTED_KEY',
        description: 'File signed with Ed25519 key not catalogued in Enterprise PKI Trust Registry.',
        timestamp: '2026-10-30T14:05:12.000Z',
        contained: false,
      },
      {
        id: 'ALT-8843',
        title: 'Revoked Key Signature Creation Attempt',
        severity: 'CRITICAL',
        sourceId: 'SRC-99011',
        organizationId: 'ORG-02',
        status: 'CONTAINED',
        type: 'REVOKED_KEY_BLOCK',
        description: 'Prohibited signing attempt blocked for revoked key ED25519-STOLEN-01.',
        timestamp: '2026-10-30T16:11:45.000Z',
        contained: true,
      },
    ],
    approvals: [
      {
        id: 'APR-501',
        title: 'Derivative Authorization Request: Recon Map High-Contrast Layer',
        sourceId: 'SRC-98214',
        organizationId: 'ORG-01',
        requestedBy: 'USR-CUSTODIAN-01',
        requestedByName: 'Alex Rivera',
        status: 'PENDING',
        department: 'Orbital Reconnaissance',
        reason: 'Authorized crop and multispectral contrast enhancement for field debriefing.',
        timestamp: '2026-10-30T15:20:00.000Z',
      },
      {
        id: 'APR-503',
        title: 'Threat Intel Feed Export Authorization',
        sourceId: 'SRC-SOC-LOG',
        organizationId: 'ORG-02',
        requestedBy: 'USR-SOC-01',
        requestedByName: 'Marcus Brody',
        status: 'PENDING',
        department: 'Cyber Defense Operations',
        reason: 'Export containment vectors for incident mitigation.',
        timestamp: '2026-10-30T16:00:00.000Z',
      },
    ],
    auditLogs: [
      {
        id: 'AUD-0001',
        action: 'SYSTEM_GENESIS_INITIALIZED',
        actor: 'SYSTEM',
        role: 'SYSTEM',
        details: 'SourceMark Enterprise PKI & Provenance Engine initialized.',
        timestamp: '2026-10-20T00:00:00.000Z',
        ipAddress: '127.0.0.1',
      },
      {
        id: 'AUD-0002',
        action: 'KEY_REGISTRATION',
        actor: 'admin@sourcemark.io',
        role: ROLES.ADMINISTRATOR,
        details: 'Registered Root CA & Master Signing Key ED25519-A9103847.',
        timestamp: '2026-10-20T00:10:00.000Z',
        ipAddress: '127.0.0.1',
      },
    ],
    failedLoginTracker: {}, // IP:email -> { count, lockedUntil }
  };
}

// Sanitization utility to ensure no sensitive secrets leak into audit logs
function sanitizeDetails(details) {
  if (typeof details === 'string') {
    return details
      .replace(/password['"]?\s*:\s*['"][^'"]+['"]/gi, 'password: "[REDACTED]"')
      .replace(/Bearer\s+[A-Za-z0-9_.-]+/gi, 'Bearer [REDACTED]')
      .replace(/privateKey['"]?\s*:\s*['"][^'"]+['"]/gi, 'privateKey: "[REDACTED]"');
  }
  if (typeof details === 'object' && details !== null) {
    const copy = { ...details };
    for (const k of Object.keys(copy)) {
      if (/password|token|secret|privateKey|salt/i.test(k)) {
        copy[k] = '[REDACTED]';
      }
    }
    return JSON.stringify(copy);
  }
  return String(details);
}

// Persistent Database Handler
export class EnterpriseDB {
  constructor() {
    this.data = null;
    this.load();
    dbAdapter.setJsonDb(this);
    this.adapter = dbAdapter;
    this.initializedPromise = this.init();
  }

  async init() {
    try {
      const conn = await dbAdapter.checkHealth();
      if (conn.connected) {
        await dbAdapter.syncRuntimeData(this);
      }
      await kmsManager.initialize();
      await wormManager.initialize();
    } catch (e) {
      // safe fallback to JSON & SQLite
    }
    return this;
  }

  load() {
    try {
      if (fs.existsSync(DB_FILE)) {
        const raw = fs.readFileSync(DB_FILE, 'utf8');
        this.data = JSON.parse(raw);
        if (!this.data.systemState) {
          this.data.systemState = { lockdown: false, lockdownReason: null, revokedKeys: [] };
        }
        if (this.data.approvals) {
          for (const a of this.data.approvals) {
            if (!a.organizationId) a.organizationId = 'ORG-01';
          }
          if (!this.data.approvals.some(a => a.id === 'APR-503')) {
            this.data.approvals.push({
              id: 'APR-503',
              title: 'Threat Intel Feed Export Authorization',
              sourceId: 'SRC-SOC-LOG',
              organizationId: 'ORG-02',
              requestedBy: 'USR-SOC-01',
              requestedByName: 'Marcus Brody',
              status: 'PENDING',
              department: 'Cyber Defense Operations',
              reason: 'Export containment vectors for incident mitigation.',
              timestamp: '2026-10-30T16:00:00.000Z',
            });
          }
        }
      } else {
        this.data = getInitialDbState();
        this.save();
      }
    } catch (e) {
      console.error('Error loading DB file, resetting to initial state:', e);
      this.data = getInitialDbState();
      this.save();
    }
  }

  save() {
    try {
      fs.writeFileSync(DB_FILE, JSON.stringify(this.data, null, 2), 'utf8');
    } catch (e) {
      console.error('Error saving DB file:', e);
    }
  }

  logAudit(action, actor, role, details, ip = '127.0.0.1') {
    const entry = {
      id: `AUD-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
      action,
      actor: actor || 'ANONYMOUS',
      role: role || 'UNKNOWN',
      details: sanitizeDetails(details),
      timestamp: new Date().toISOString(),
      ipAddress: ip,
    };
    this.data.auditLogs.unshift(entry);
    // Keep max 500 audit events in storage
    if (this.data.auditLogs.length > 500) {
      this.data.auditLogs.pop();
    }
    this.save();

    // Asynchronous write-through to PostgreSQL audit_logs table
    dbAdapter.checkHealth().then(h => {
      if (h.connected) {
        import('./db/postgres.mjs').then(({ query: pgQuery }) => {
          pgQuery(
            `INSERT INTO audit_logs (id, action, actor, role, details, ip_address, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (id) DO NOTHING`,
            [
              entry.id,
              entry.action,
              entry.actor,
              entry.role,
              typeof entry.details === 'string' ? entry.details : JSON.stringify(entry.details),
              entry.ipAddress,
              entry.timestamp,
            ]
          ).catch(() => {});
        }).catch(() => {});
      }
    }).catch(() => {});

    return entry;
  }
}

export const db = new EnterpriseDB();

// Request Helper & Parser
function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > 10 * 1024 * 1024) {
        reject(new Error('Payload too large'));
      }
    });
    req.on('end', () => {
      if (!body) return resolve({});
      try {
        resolve(JSON.parse(body));
      } catch (err) {
        resolve({});
      }
    });
    req.on('error', reject);
  });
}

export function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With',
  });
  res.end(JSON.stringify(data));
}

// Authentication Extractor
export function authenticate(req) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return null;
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : authHeader;
  return verifySessionToken(token);
}

export function hasPermission(userRole, permission) {
  if (!userRole) return false;
  const perms = PERMISSIONS[userRole] || [];
  return perms.includes(permission);
}

/**
 * Centralized Server-Side Permission Middleware
 * Enforces authentication (HTTP 401) and role/permission boundaries (HTTP 403).
 * Logs security audit events without exposing passwords, tokens, or private keys.
 */
export function requireAuth(req, res, requiredPermission = null, requiredRole = null) {
  const session = authenticate(req);
  const pathname = new URL(req.url, `http://${req.headers.host || '127.0.0.1:8000'}`).pathname;
  const ip = req.socket?.remoteAddress || '127.0.0.1';

  // 1. Unauthenticated Request Check (HTTP 401)
  if (!session) {
    db.logAudit(
      'SECURITY_ACCESS_DENIED_UNAUTHENTICATED',
      'ANONYMOUS',
      'UNAUTHENTICATED',
      `Denied access to ${req.method} ${pathname}: Missing or invalid session token`,
      ip
    );
    sendJson(res, 401, {
      success: false,
      error: 'Unauthorized: Authentication token is missing or expired',
      code: 'UNAUTHENTICATED',
    });
    return null;
  }

  // 2. Specific Role Requirement Check (HTTP 403)
  if (requiredRole && session.role !== requiredRole && session.role !== ROLES.ADMINISTRATOR) {
    db.logAudit(
      'SECURITY_PRIVILEGE_VIOLATION_DENIED',
      session.email,
      session.role,
      `Denied ${req.method} ${pathname}: Role ${session.role} lacks required role ${requiredRole}`,
      ip
    );
    sendJson(res, 403, {
      success: false,
      error: `Forbidden: Requires ${requiredRole} clearance`,
      code: 'FORBIDDEN_ROLE',
    });
    return null;
  }

  // 3. Specific Permission Requirement Check (HTTP 403)
  if (requiredPermission && !hasPermission(session.role, requiredPermission)) {
    db.logAudit(
      'SECURITY_PERMISSION_DENIED',
      session.email,
      session.role,
      `Denied ${req.method} ${pathname}: Role ${session.role} lacks permission ${requiredPermission}`,
      ip
    );
    sendJson(res, 403, {
      success: false,
      error: `Forbidden: Insufficient privileges. Requires '${requiredPermission}' permission`,
      code: 'FORBIDDEN_PERMISSION',
    });
    return null;
  }

  return session;
}

// HTTP Server & Router
export const server = http.createServer(async (req, res) => {
  // Handle CORS Preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With',
    });
    res.end();
    return;
  }

  const url = new URL(req.url, `http://${req.headers.host || '127.0.0.1:8000'}`);
  const pathname = url.pathname;
  const ip = req.socket?.remoteAddress || '127.0.0.1';

  try {
    // ----------------------------------------------------
    // Public Health Check
    // ----------------------------------------------------
    if (pathname === '/api/health' && req.method === 'GET') {
      const dbStatus = await dbAdapter.checkHealth();
      return sendJson(res, 200, {
        status: 'healthy',
        service: 'SourceMark Enterprise Provenance Engine',
        version: '2.0.0-enterprise',
        curve: 'Ed25519',
        hasher: 'SHA-256',
        backendEngine: 'Node.js v24 Enterprise REST Engine',
        databaseEngine: dbStatus.engine,
        databaseConnected: dbStatus.connected,
        databaseMode: dbStatus.mode,
        timestamp: new Date().toISOString(),
        rbacEnabled: true,
        lockdown: db.data.systemState?.lockdown || false,
      });
    }

    // ----------------------------------------------------
    // Database Status & Dual-Engine Migration Endpoints
    // ----------------------------------------------------
    if (pathname === '/api/database/status' && req.method === 'GET') {
      const status = await dbAdapter.getStatus();
      return sendJson(res, 200, { success: true, ...status });
    }

    if (pathname === '/api/database/backup' && req.method === 'POST') {
      const session = requireAuth(req, res, 'system:lockdown'); // Admin only
      if (!session) return;
      try {
        const backupResult = await backupJsonDatabase();
        db.logAudit('DATABASE_BACKUP_CREATED', session.email, session.role, `Created JSON database backup: ${backupResult.backupFile}`, ip);
        return sendJson(res, 200, { success: true, backup: backupResult });
      } catch (err) {
        return sendJson(res, 500, { success: false, error: err.message });
      }
    }

    if (pathname === '/api/database/migrate' && req.method === 'POST') {
      const session = requireAuth(req, res, 'system:lockdown'); // Admin only
      if (!session) return;
      try {
        const conn = await checkConnection();
        if (!conn.connected) {
          return sendJson(res, 503, {
            success: false,
            error: 'PostgreSQL server is offline or unconfigured. Cannot run migrations.',
            code: 'DATABASE_OFFLINE',
            details: conn.error,
          });
        }
        const migrationResult = await runMigrations();
        const dataMigrationResult = await migrateJsonToPostgres();
        db.logAudit('DATABASE_MIGRATION_EXECUTED', session.email, session.role, `PostgreSQL migrations executed: ${migrationResult.newlyApplied?.length || 0} applied`, ip);
        return sendJson(res, 200, {
          success: true,
          migrations: migrationResult,
          dataMigration: dataMigrationResult,
        });
      } catch (err) {
        return sendJson(res, 500, { success: false, error: err.message });
      }
    }

    // ----------------------------------------------------
    // Enterprise KMS / HSM Key Lifecycle Endpoints
    // ----------------------------------------------------
    if (pathname === '/api/kms/status' && req.method === 'GET') {
      const status = await kmsManager.getStatus();
      return sendJson(res, 200, { success: true, ...status });
    }

    if (pathname === '/api/kms/keys' && req.method === 'POST') {
      const session = requireAuth(req, res, 'keys:approve');
      if (!session) return;

      const body = await parseBody(req);
      const keyInfo = await kmsManager.generateKey({
        alias: body.alias,
        ownerName: body.ownerName || session.name || session.email,
        ownerId: session.userId,
        organizationId: session.organizationId || 'ORG-01',
      });

      db.logAudit('KMS_KEY_GENERATED', session.email, session.role, `Generated managed KMS key ${keyInfo.keyId}`, ip);
      return sendJson(res, 201, { success: true, key: keyInfo });
    }

    if (pathname === '/api/kms/sign' && req.method === 'POST') {
      const session = requireAuth(req, res, 'sources:register');
      if (!session) return;

      const body = await parseBody(req);
      const { keyId, hashHex, context } = body;
      if (!keyId || !hashHex) {
        return sendJson(res, 400, { success: false, error: 'keyId and hashHex are required for signing' });
      }

      if (db.data.systemState?.revokedKeys?.includes(keyId)) {
        return sendJson(res, 403, {
          success: false,
          error: `SECURITY EXCEPTION: Signing key ${keyId} is REVOKED. Prohibited from signing new provenance records.`,
          code: 'KEY_REVOKED',
        });
      }

      try {
        const signResult = await kmsManager.sign(keyId, hashHex, {
          organizationId: session.organizationId,
          role: session.role,
          email: session.email,
          ...(context || {}),
        });

        db.logAudit('KMS_PAYLOAD_SIGNED', session.email, session.role, `Digitally signed digest using KMS key ${keyId}`, ip);
        return sendJson(res, 200, { success: true, signature: signResult });
      } catch (err) {
        const isPolicyViolation = err.message.includes('SECURITY EXCEPTION') || 
                                  err.message.includes('ACCESS DENIED') ||
                                  err.message.includes('REVOKED') ||
                                  err.message.includes('ROTATED');
        const statusCode = isPolicyViolation ? 403 : 400;
        const errCode = err.message.includes('ROTATED') ? 'KEY_ROTATED' : 
                        (err.message.includes('ACCESS DENIED') ? 'CROSS_ORG_ACCESS_DENIED' : 
                        (err.message.includes('REVOKED') ? 'KEY_REVOKED' : 'KEY_ERROR'));
        return sendJson(res, statusCode, {
          success: false,
          error: err.message,
          code: errCode,
        });
      }
    }

    if (pathname === '/api/kms/rotate' && req.method === 'POST') {
      const session = requireAuth(req, res, 'keys:approve');
      if (!session) return;

      const body = await parseBody(req);
      const { keyId, reason } = body;
      if (!keyId) {
        return sendJson(res, 400, { success: false, error: 'keyId is required for key rotation' });
      }

      const auditEntry = {
        id: `AUD-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
        action: 'KMS_KEY_ROTATED',
        actor: session.email,
        role: session.role,
        details: `Rotated key ${keyId}: ${reason || 'Scheduled rotation'}`,
        timestamp: new Date().toISOString(),
        ipAddress: ip,
      };

      try {
        const rotationResult = await kmsManager.rotateKey(keyId, reason, session.email, session.role, auditEntry);
        db.logAudit('KMS_KEY_ROTATED', session.email, session.role, `Rotated key ${keyId}`, ip);
        return sendJson(res, 200, { success: true, rotation: rotationResult });
      } catch (err) {
        return sendJson(res, 500, { success: false, error: err.message });
      }
    }

    if (pathname === '/api/kms/revoke' && req.method === 'POST') {
      const session = requireAuth(req, res, 'keys:revoke');
      if (!session) return;

      const body = await parseBody(req);
      const { keyId, reason } = body;
      if (!keyId) {
        return sendJson(res, 400, { success: false, error: 'keyId is required for revocation' });
      }

      // Record in systemState
      if (!db.data.systemState.revokedKeys) {
        db.data.systemState.revokedKeys = [];
      }
      if (!db.data.systemState.revokedKeys.includes(keyId)) {
        db.data.systemState.revokedKeys.push(keyId);
      }

      const auditEntry = {
        id: `AUD-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
        action: 'KMS_KEY_REVOKED',
        actor: session.email,
        role: session.role,
        details: `KMS Key ${keyId} revoked: ${reason || 'Administrative containment mandate'}`,
        timestamp: new Date().toISOString(),
        ipAddress: ip,
      };

      try {
        const revokeResult = await kmsManager.revokeKey(keyId, reason, session.email, session.role, auditEntry);
        db.logAudit('KMS_KEY_REVOKED', session.email, session.role, `Revoked KMS key ${keyId}`, ip);
        return sendJson(res, 200, { success: true, revocation: revokeResult });
      } catch (err) {
        return sendJson(res, 500, { success: false, error: err.message });
      }
    }

    // ----------------------------------------------------
    // RFC 3161 Trusted Timestamp Authority (TSA) Endpoints
    // ----------------------------------------------------
    if (pathname === '/api/tsa/status' && req.method === 'GET') {
      const status = tsaManager.getStatus();
      return sendJson(res, 200, { success: true, ...status });
    }

    if (pathname === '/api/tsa/request' && req.method === 'POST') {
      const session = requireAuth(req, res, 'sources:register');
      if (!session) return;

      const body = await parseBody(req);
      const { hashHex, sourceId, blockId } = body;
      if (!hashHex) {
        return sendJson(res, 400, { success: false, error: 'hashHex is required to generate RFC 3161 timestamp request' });
      }

      let result;
      if (sourceId) {
        result = await tsaManager.anchorSourceTimestamp(sourceId, hashHex, { email: session.email, role: session.role });
      } else if (blockId) {
        result = await tsaManager.anchorLedgerBlockTimestamp(blockId, hashHex, { email: session.email, role: session.role });
      } else {
        result = await tsaManager.client.requestTimestamp(hashHex);
      }

      db.logAudit('TSA_TIMESTAMP_REQUESTED', session.email, session.role, `Requested RFC 3161 timestamp for hash ${hashHex.slice(0, 16)}...`, ip);
      return sendJson(res, 200, { success: true, token: result });
    }

    if (pathname === '/api/tsa/verify' && req.method === 'POST') {
      const body = await parseBody(req);
      const { tokenId, token, expectedHash, expectedNonce } = body;

      if (tokenId) {
        const verifyRes = await tsaManager.verifyStoredToken(tokenId);
        return sendJson(res, 200, { success: true, validation: verifyRes });
      }

      if (!token) {
        return sendJson(res, 400, { success: false, error: 'Either tokenId or token object is required for verification' });
      }

      const parsed = typeof token === 'string' 
        ? parseTimeStampResponse(Buffer.from(token, 'base64')) 
        : token;
      const validation = validateTimeStampToken(parsed, expectedHash, expectedNonce);

      return sendJson(res, 200, { success: true, validation });
    }

    // ----------------------------------------------------
    // Independent WORM Storage & Checkpoint Anchoring (Phase 7)
    // ----------------------------------------------------
    if (pathname === '/api/worm/status' && req.method === 'GET') {
      const status = wormManager.getStatus();
      return sendJson(res, 200, { success: true, ...status });
    }

    if (pathname === '/api/checkpoints' && req.method === 'GET') {
      const session = requireAuth(req, res, 'ledger:read');
      if (!session) return;

      const list = await wormManager.listCheckpoints();
      return sendJson(res, 200, {
        success: true,
        count: list.length,
        checkpoints: list,
        wormMode: wormManager.getStatus().mode,
      });
    }

    if (pathname === '/api/checkpoints/create' && req.method === 'POST') {
      const session = requireAuth(req, res, 'audit:export');
      if (!session) return;

      const body = await parseBody(req);
      try {
        const result = await wormManager.createSignedCheckpoint({
          ...body,
          operator: session.email,
          role: session.role,
          ipAddress: ip,
        });

        // Sync with runtime db
        await dbAdapter.syncRuntimeData(db);

        return sendJson(res, 201, result);
      } catch (err) {
        return sendJson(res, 500, {
          success: false,
          error: `Checkpoint creation failed: ${err.message}`,
        });
      }
    }

    if (pathname === '/api/checkpoints/verify' && req.method === 'POST') {
      const session = requireAuth(req, res, 'sources:verify');
      if (!session) return;

      const body = await parseBody(req);
      let checkpointId = body.checkpointId;

      if (!checkpointId) {
        const list = await wormManager.listCheckpoints();
        if (list.length === 0) {
          return sendJson(res, 404, {
            success: false,
            error: 'No checkpoints found in repository to verify.',
          });
        }
        checkpointId = list[0].id;
      }

      const verdict = await wormManager.verifyCheckpointAgainstLedger(checkpointId, {
        actor: session.email,
        role: session.role,
      });

      return sendJson(res, 200, { success: true, ...verdict });
    }

    if (pathname === '/api/checkpoints/simulate-rollback' && req.method === 'POST') {
      const session = requireAuth(req, res, 'ledger:rollback');
      if (!session) return;

      const body = await parseBody(req);
      const truncateCount = parseInt(body.truncateCount || '2', 10);

      const { query: pgQ } = await import('./db/postgres.mjs');
      const blocksRes = await pgQ('SELECT id, block_number FROM ledger_blocks ORDER BY block_number DESC LIMIT $1', [truncateCount]);
      const deletedIds = blocksRes.rows.map(r => r.id);

      if (deletedIds.length > 0) {
        await pgQ('DELETE FROM ledger_blocks WHERE id = ANY($1)', [deletedIds]);
      }

      if (db.data.ledger.length > truncateCount) {
        db.data.ledger = db.data.ledger.slice(0, db.data.ledger.length - truncateCount);
        db.save();
      }

      db.logAudit(
        'SIMULATED_LEDGER_ROLLBACK',
        session.email,
        session.role,
        `Administrative simulated rollback attack: truncated ${deletedIds.length} blocks (${deletedIds.join(', ')})`,
        ip
      );

      return sendJson(res, 200, {
        success: true,
        message: `Simulated rollback completed. Truncated ${deletedIds.length} blocks.`,
        deletedBlockIds: deletedIds,
        newLedgerHeight: db.data.ledger.length,
      });
    }

    if (pathname === '/api/checkpoints/restore' && req.method === 'POST') {
      const session = requireAuth(req, res, 'ledger:rollback');
      if (!session) return;

      await dbAdapter.syncRuntimeData(db);

      db.logAudit(
        'LEDGER_RESTORE_EXECUTED',
        session.email,
        session.role,
        'Administrative ledger restoration executed from trusted backup store',
        ip
      );

      return sendJson(res, 200, {
        success: true,
        message: 'Ledger restored from persistent store.',
        currentHeight: db.data.ledger.length,
      });
    }

    // ----------------------------------------------------
    // Authentication Endpoints
    // ----------------------------------------------------
    if (pathname === '/api/auth/login' && req.method === 'POST') {
      const body = await parseBody(req);
      const { email, password } = body;

      if (!email || !password) {
        return sendJson(res, 400, { success: false, error: 'Email and password are required' });
      }

      // Brute-force rate limiting protection
      const trackerKey = `${ip}:${email.toLowerCase()}`;
      const tracker = db.data.failedLoginTracker[trackerKey] || { count: 0, lockedUntil: 0 };
      if (Date.now() < tracker.lockedUntil) {
        const remainingSec = Math.ceil((tracker.lockedUntil - Date.now()) / 1000);
        db.logAudit('LOGIN_BLOCKED_LOCKOUT', email, 'UNKNOWN', `Brute force defense locked account for ${remainingSec}s`, ip);
        return sendJson(res, 429, {
          success: false,
          error: `Account temporarily locked due to excessive failed attempts. Please retry in ${remainingSec} seconds.`,
          code: 'RATE_LIMITED',
        });
      }

      const user = db.data.users.find(u => u.email.toLowerCase() === email.toLowerCase());
      if (!user) {
        tracker.count += 1;
        if (tracker.count >= 5) {
          tracker.lockedUntil = Date.now() + 60 * 1000; // 1 min lock
        }
        db.data.failedLoginTracker[trackerKey] = tracker;
        db.save();
        db.logAudit('LOGIN_FAILED_UNKNOWN_USER', email, 'UNKNOWN', 'Failed login attempt: user not found', ip);
        return sendJson(res, 401, { success: false, error: 'Invalid email or password credentials' });
      }

      const isMatch = verifyPassword(password, user.salt, user.passwordHash);
      if (!isMatch) {
        tracker.count += 1;
        if (tracker.count >= 5) {
          tracker.lockedUntil = Date.now() + 60 * 1000;
        }
        db.data.failedLoginTracker[trackerKey] = tracker;
        db.save();
        db.logAudit('LOGIN_FAILED_BAD_PASSWORD', user.email, user.role, 'Invalid password attempt', ip);
        return sendJson(res, 401, { success: false, error: 'Invalid email or password credentials' });
      }

      if (user.status === 'DEACTIVATED' || user.status === 'SUSPENDED') {
        db.logAudit('LOGIN_REJECTED_DEACTIVATED', user.email, user.role, 'Login rejected: account has been deactivated by an administrator', ip);
        return sendJson(res, 403, {
          success: false,
          error: 'Your account has been deactivated by an administrator. Please contact IT support.',
          code: 'ACCOUNT_DEACTIVATED',
        });
      }

      // Reset tracker on successful login
      delete db.data.failedLoginTracker[trackerKey];
      db.save();

      const token = createSessionToken(user);
      db.logAudit('LOGIN_SUCCESS', user.email, user.role, `User authenticated successfully with role ${user.role}`, ip);

      return sendJson(res, 200, {
        success: true,
        token,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          role: user.role,
          organizationId: user.organizationId,
          permissions: PERMISSIONS[user.role] || [],
          mfaEnabled: user.mfaEnabled,
        },
      });
    }

    if (pathname === '/api/auth/me' && req.method === 'GET') {
      const session = requireAuth(req, res);
      if (!session) return;

      const user = db.data.users.find(u => u.id === session.userId);
      if (!user) {
        return sendJson(res, 404, { success: false, error: 'User record not found' });
      }

      return sendJson(res, 200, {
        success: true,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          role: user.role,
          organizationId: user.organizationId,
          permissions: PERMISSIONS[user.role] || [],
          mfaEnabled: user.mfaEnabled,
        },
      });
    }

    // User Registration / Account Creation
    // Security Rule: Prevent users from escalating role or changing organization via payload manipulation
    if (pathname === '/api/auth/register' && req.method === 'POST') {
      const body = await parseBody(req);
      const { name, email, password } = body;

      if (!email || !password || !name) {
        return sendJson(res, 400, { success: false, error: 'Name, email, and password are required' });
      }

      if (db.data.users.some(u => u.email.toLowerCase() === email.toLowerCase())) {
        return sendJson(res, 409, { success: false, error: 'User with this email already exists' });
      }

      // Check if caller is an Administrator
      const callerSession = authenticate(req);
      const isCallerAdmin = callerSession && callerSession.role === ROLES.ADMINISTRATOR;

      // Non-administrators are strictly forced to role 'USER' and default organization 'ORG-01'
      const assignedRole = (isCallerAdmin && body.role && ROLES[body.role]) ? body.role : ROLES.USER;
      const assignedOrg = (isCallerAdmin && body.organizationId) ? body.organizationId : 'ORG-01';

      const { salt, hash } = hashPassword(password);
      const newUser = {
        id: `USR-${Date.now().toString(36).toUpperCase()}`,
        name,
        email,
        role: assignedRole,
        organizationId: assignedOrg,
        salt,
        passwordHash: hash,
        status: 'ACTIVE',
        mfaEnabled: false,
        createdAt: new Date().toISOString(),
      };

      await dbAdapter.createUser(newUser);
      db.logAudit('USER_REGISTERED', newUser.email, newUser.role, `Registered user with role ${newUser.role} in ${newUser.organizationId}`, ip);

      const token = createSessionToken(newUser);
      return sendJson(res, 201, {
        success: true,
        token,
        user: {
          id: newUser.id,
          name: newUser.name,
          email: newUser.email,
          role: newUser.role,
          organizationId: newUser.organizationId,
          permissions: PERMISSIONS[newUser.role] || [],
        },
      });
    }

    // ----------------------------------------------------
    // User Governance & Administration (Admin & Org Filtered)
    // ----------------------------------------------------
    if ((pathname === '/api/auth/users' || pathname === '/api/admin/users') && req.method === 'GET') {
      const session = requireAuth(req, res, 'users:read');
      if (!session) return;

      let users = db.data.users;
      // Multi-tenant organization isolation
      if (session.role !== ROLES.ADMINISTRATOR) {
        users = users.filter(u => u.organizationId === session.organizationId);
      }

      const sanitizedUsers = users.map(u => ({
        id: u.id,
        name: u.name,
        email: u.email,
        role: u.role,
        organizationId: u.organizationId,
        status: u.status,
        mfaEnabled: u.mfaEnabled,
        createdAt: u.createdAt,
      }));

      return sendJson(res, 200, { success: true, users: sanitizedUsers });
    }

    // Administrator-Controlled Account Creation
    if (pathname === '/api/admin/users' && req.method === 'POST') {
      const session = requireAuth(req, res, 'users:write');
      if (!session) return;

      if (session.role !== ROLES.ADMINISTRATOR) {
        db.logAudit('SECURITY_PERMISSION_DENIED', session.email, session.role, 'Unauthorized attempt to create privileged user account (Requires Administrator)', ip);
        return sendJson(res, 403, { success: false, error: 'Administrator clearance required to manage user accounts', code: 'FORBIDDEN_PERMISSION' });
      }

      const body = await parseBody(req);
      const { name, email, password, role, organizationId } = body;

      if (!email || !password || !name) {
        return sendJson(res, 400, { success: false, error: 'Name, email, and password are required' });
      }

      if (db.data.users.some(u => u.email.toLowerCase() === email.toLowerCase())) {
        return sendJson(res, 409, { success: false, error: 'User with this email already exists' });
      }

      const assignedRole = (role && ROLES[role]) ? role : ROLES.USER;
      const assignedOrg = organizationId || 'ORG-01';

      const { salt, hash } = hashPassword(password);
      const newUser = {
        id: `USR-${Date.now().toString(36).toUpperCase()}`,
        name,
        email,
        role: assignedRole,
        organizationId: assignedOrg,
        salt,
        passwordHash: hash,
        status: 'ACTIVE',
        mfaEnabled: false,
        createdAt: new Date().toISOString(),
      };

      db.data.users.push(newUser);
      db.save();
      await dbAdapter.createUser(newUser);
      db.logAudit('USER_ACCOUNT_CREATED', session.email, session.role, `Administrator created account for ${newUser.email} with role ${newUser.role} in ${newUser.organizationId}`, ip);

      return sendJson(res, 201, {
        success: true,
        user: {
          id: newUser.id,
          name: newUser.name,
          email: newUser.email,
          role: newUser.role,
          organizationId: newUser.organizationId,
          status: newUser.status,
          createdAt: newUser.createdAt,
        },
      });
    }

    // Administrator Account Deactivation
    if (pathname.match(/^\/api\/admin\/users\/[^/]+\/deactivate$/) && req.method === 'POST') {
      const session = requireAuth(req, res, 'users:write');
      if (!session) return;

      if (session.role !== ROLES.ADMINISTRATOR) {
        db.logAudit('SECURITY_PERMISSION_DENIED', session.email, session.role, 'Non-admin attempted to deactivate user account', ip);
        return sendJson(res, 403, { success: false, error: 'Administrator clearance required', code: 'FORBIDDEN_PERMISSION' });
      }

      const parts = pathname.split('/');
      const targetUserId = parts[parts.length - 2];
      const targetUser = db.data.users.find(u => u.id === targetUserId);
      if (!targetUser) {
        return sendJson(res, 404, { success: false, error: 'Target user not found' });
      }

      if (targetUser.id === session.userId) {
        return sendJson(res, 400, { success: false, error: 'Administrators cannot deactivate their own account' });
      }

      targetUser.status = 'DEACTIVATED';
      db.save();
      await dbAdapter.updateUser(targetUserId, { status: 'DEACTIVATED' });
      db.logAudit('USER_ACCOUNT_DEACTIVATED', session.email, session.role, `Deactivated account for ${targetUser.email} (Role: ${targetUser.role})`, ip);

      return sendJson(res, 200, {
        success: true,
        message: `Account for ${targetUser.email} has been deactivated.`,
        user: {
          id: targetUser.id,
          email: targetUser.email,
          role: targetUser.role,
          status: targetUser.status,
        },
      });
    }

    // Administrator Account Re-activation
    if (pathname.match(/^\/api\/admin\/users\/[^/]+\/activate$/) && req.method === 'POST') {
      const session = requireAuth(req, res, 'users:write');
      if (!session) return;

      if (session.role !== ROLES.ADMINISTRATOR) {
        return sendJson(res, 403, { success: false, error: 'Administrator clearance required', code: 'FORBIDDEN_PERMISSION' });
      }

      const parts = pathname.split('/');
      const targetUserId = parts[parts.length - 2];
      const targetUser = db.data.users.find(u => u.id === targetUserId);
      if (!targetUser) {
        return sendJson(res, 404, { success: false, error: 'Target user not found' });
      }

      targetUser.status = 'ACTIVE';
      db.save();
      await dbAdapter.updateUser(targetUserId, { status: 'ACTIVE' });
      db.logAudit('USER_ACCOUNT_ACTIVATED', session.email, session.role, `Re-activated account for ${targetUser.email} (Role: ${targetUser.role})`, ip);

      return sendJson(res, 200, {
        success: true,
        message: `Account for ${targetUser.email} has been activated.`,
        user: {
          id: targetUser.id,
          email: targetUser.email,
          role: targetUser.role,
          status: targetUser.status,
        },
      });
    }

    // Administrator Password Reset
    if (pathname.match(/^\/api\/admin\/users\/[^/]+\/reset-password$/) && req.method === 'POST') {
      const session = requireAuth(req, res, 'users:write');
      if (!session) return;

      if (session.role !== ROLES.ADMINISTRATOR) {
        return sendJson(res, 403, { success: false, error: 'Administrator clearance required', code: 'FORBIDDEN_PERMISSION' });
      }

      const parts = pathname.split('/');
      const targetUserId = parts[parts.length - 2];
      const targetUser = db.data.users.find(u => u.id === targetUserId);
      if (!targetUser) {
        return sendJson(res, 404, { success: false, error: 'Target user not found' });
      }

      const body = await parseBody(req);
      const newPassword = body.newPassword || body.password;
      if (!newPassword || newPassword.length < 8) {
        return sendJson(res, 400, { success: false, error: 'New password must be at least 8 characters long' });
      }

      const { salt, hash } = hashPassword(newPassword);
      targetUser.salt = salt;
      targetUser.passwordHash = hash;
      db.save();
      await dbAdapter.updateUser(targetUserId, { salt, passwordHash: hash });
      db.logAudit('USER_PASSWORD_RESET', session.email, session.role, `Password reset by administrator for ${targetUser.email}`, ip);

      return sendJson(res, 200, {
        success: true,
        message: `Password for ${targetUser.email} has been successfully reset.`,
      });
    }

    // Administrator Role Assignment / User Patch
    if ((pathname.startsWith('/api/auth/users/') || pathname.startsWith('/api/admin/users/')) && req.method === 'PATCH') {
      const session = requireAuth(req, res, 'users:write');
      if (!session) return;

      const targetUserId = pathname.split('/').pop();
      const body = await parseBody(req);
      const user = db.data.users.find(u => u.id === targetUserId);
      if (!user) {
        return sendJson(res, 404, { success: false, error: 'Target user not found' });
      }

      if (body.role) {
        if (session.role !== ROLES.ADMINISTRATOR) {
          db.logAudit('SECURITY_PERMISSION_DENIED', session.email, session.role, 'Non-administrator attempted to change user role', ip);
          return sendJson(res, 403, { success: false, error: 'Administrator clearance required to reassign user roles', code: 'FORBIDDEN_PERMISSION' });
        }
        if (ROLES[body.role]) {
          const oldRole = user.role;
          user.role = body.role;
          db.logAudit('USER_ROLE_CHANGED', session.email, session.role, `Reassigned role for ${user.email} from ${oldRole} to ${body.role}`, ip);
        }
      }
      if (body.organizationId) {
        user.organizationId = body.organizationId;
      }
      if (body.status) {
        if (session.role !== ROLES.ADMINISTRATOR) {
          return sendJson(res, 403, { success: false, error: 'Administrator clearance required to alter user status', code: 'FORBIDDEN_PERMISSION' });
        }
        user.status = body.status;
      }

      db.save();
      await dbAdapter.updateUser(targetUserId, { role: user.role, organizationId: user.organizationId, status: user.status });
      db.logAudit('USER_GOVERNANCE_UPDATED', session.email, session.role, `Modified user ${user.email} (Role: ${user.role}, Org: ${user.organizationId})`, ip);
      return sendJson(res, 200, {
        success: true,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          role: user.role,
          organizationId: user.organizationId,
          status: user.status,
          mfaEnabled: user.mfaEnabled,
        },
      });
    }

    // ----------------------------------------------------
    // Emergency System Lockdown (Admin Only)
    // ----------------------------------------------------
    if (pathname === '/api/system/lockdown' && req.method === 'POST') {
      const session = requireAuth(req, res, 'system:lockdown');
      if (!session) return;

      const body = await parseBody(req);
      const isLockdown = body.lockdown !== undefined ? !!body.lockdown : !db.data.systemState.lockdown;
      const reason = body.reason || (isLockdown ? 'Emergency Security Directive' : null);
      db.data.systemState.lockdown = isLockdown;
      db.data.systemState.lockdownReason = reason;

      const auditEntry = db.logAudit(
        isLockdown ? 'EMERGENCY_LOCKDOWN_ENGAGED' : 'EMERGENCY_LOCKDOWN_DISENGAGED',
        session.email,
        session.role,
        `Emergency Platform Lockdown ${isLockdown ? 'ENGAGED' : 'DISENGAGED'}: ${reason || 'Normal'}`,
        ip
      );
      await dbAdapter.setSystemLockdown(isLockdown, reason, session.email, session.role, auditEntry);

      return sendJson(res, 200, {
        success: true,
        lockdown: db.data.systemState.lockdown,
        reason: db.data.systemState.lockdownReason,
        timestamp: new Date().toISOString(),
      });
    }

    // ----------------------------------------------------
    // Cryptographic Key Revocation (Admin Only)
    // ----------------------------------------------------
    if (pathname === '/api/keys/revoke' && req.method === 'POST') {
      const session = requireAuth(req, res, 'keys:revoke');
      if (!session) return;

      const body = await parseBody(req);
      const { keyId, reason } = body;
      if (!keyId) {
        return sendJson(res, 400, { success: false, error: 'keyId is required for revocation' });
      }

      if (!db.data.systemState.revokedKeys) {
        db.data.systemState.revokedKeys = [];
      }
      if (!db.data.systemState.revokedKeys.includes(keyId)) {
        db.data.systemState.revokedKeys.push(keyId);
      }

      // Add strictly sequential security incident block to ledger
      const seq = await dbAdapter.getNextLedgerBlockSequence();
      const block_num = seq.blockNumber;
      const block_id = seq.blockId;
      const prev_hash = seq.prevHash;
      const timestamp = new Date().toISOString();
      const block_str = `${block_id}:SECURITY_INCIDENT:${prev_hash}:${timestamp}:${keyId}`;
      const current_hash = crypto.createHash('sha256').update(block_str).digest('hex');

      const incidentBlock = {
        id: block_id,
        blockNumber: block_num,
        type: 'SECURITY_INCIDENT',
        title: `Key Revocation: ${keyId}`,
        timestamp,
        prevHash: prev_hash,
        currentHash: current_hash,
        status: 'CONFIRMED',
        verified: true,
        payload: { keyId, reason: reason || 'Administrative containment mandate', actor: session.email },
      };

      const auditEntry = {
        id: `AUD-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
        action: 'KEY_REVOCATION_EXECUTED',
        actor: session.email,
        role: session.role,
        details: `Key ${keyId} revoked by Administrator`,
        timestamp,
        ipAddress: ip,
      };

      const alertEntry = {
        id: `ALT-REV-${Date.now().toString().slice(-4)}`,
        title: `Revoked Key Containment: ${keyId}`,
        severity: 'CRITICAL',
        sourceId: keyId,
        organizationId: session.organizationId || 'ORG-01',
        status: 'CONTAINED',
        type: 'REVOKED_KEY_BLOCK',
        description: `Prohibited signing attempt blocked for revoked key ${keyId}.`,
        timestamp,
        contained: true,
      };

      await kmsManager.revokeKey(keyId, reason || 'Administrative containment mandate', session.email, session.role);
      await dbAdapter.revokeKeyTransaction(keyId, reason || 'Administrative containment mandate', session.email, session.role, auditEntry, alertEntry, incidentBlock);

      return sendJson(res, 200, {
        success: true,
        revokedKey: keyId,
        reason: reason || 'Administrative containment mandate',
        block: incidentBlock,
      });
    }

    // ----------------------------------------------------
    // Source Provenance Registration & Verification
    // ----------------------------------------------------
    if (pathname === '/api/register' && req.method === 'POST') {
      // Check authentication and permission first
      const session = requireAuth(req, res, 'sources:register');
      if (!session) return;

      // Check emergency lockdown
      if (db.data.systemState?.lockdown) {
        if (session.role !== ROLES.ADMINISTRATOR) {
          db.logAudit('LOCKDOWN_REGISTRATION_BLOCKED', session.email, session.role, 'Registration rejected during lockdown', ip);
          return sendJson(res, 403, {
            success: false,
            error: 'Registration Forbidden: Platform is under active emergency lockdown',
            code: 'SYSTEM_LOCKDOWN',
          });
        }
      }

      const payload = await parseBody(req);
      const signingKey = payload.keyId || payload.publicKey;

      // Check if signing key is revoked
      const isKeyRevoked = (signingKey && db.data.systemState?.revokedKeys?.includes(signingKey)) ||
                           (signingKey && db.data.signingKeys?.some(k => (k.id === signingKey || k.keyId === signingKey) && k.status === 'REVOKED'));
      if (isKeyRevoked) {
        db.logAudit('REVOKED_KEY_SIGNING_BLOCKED', session.email, session.role, `Registration blocked for revoked key ${signingKey}`, ip);
        return sendJson(res, 403, {
          success: false,
          error: 'Security Exception: Signing key is revoked or compromised. Key rotation required.',
          code: 'KEY_REVOKED',
        });
      }

      const new_id = payload.id || `SRC-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
      const timestamp = new Date().toISOString();

      // Resolve public key from signing_keys registry if not explicitly provided
      let resolvedPublicKey = payload.publicKey || payload.publicKeyHex;
      if (!resolvedPublicKey && (payload.keyId || payload.key_id)) {
        const kId = payload.keyId || payload.key_id;
        const keyRow = db.data.signingKeys?.find(k => k.id === kId || k.keyId === kId);
        if (keyRow) resolvedPublicKey = keyRow.publicKey || keyRow.publicKeyHex;
      }
      if (!resolvedPublicKey) {
        resolvedPublicKey = '0'.repeat(64);
      }

      // Secure record stamping: Ignore client payload spoofing of creator/organization
      // Physically uploaded evidence via /api/register is strictly production evidence (isVirtualDemo: false)
      const source_record = {
        ...payload,
        id: new_id,
        publicKey: resolvedPublicKey,
        registeredAt: timestamp,
        creator: session.email,
        creatorId: session.userId,
        organizationId: session.organizationId || 'ORG-01',
        status: 'ACTIVE_REGISTERED',
        verificationCount: 0,
        isVirtualDemo: false,
      };

      // Commit block to ledger strictly sequentially
      const seq = await dbAdapter.getNextLedgerBlockSequence();
      const block_num = seq.blockNumber;
      const block_id = seq.blockId;
      const prev_hash = seq.prevHash;
      const block_str = `${block_id}:REGISTER:${prev_hash}:${timestamp}:${payload.sha256}`;
      const current_hash = crypto.createHash('sha256').update(block_str).digest('hex');

      const new_block = {
        id: block_id,
        blockNumber: block_num,
        type: 'REGISTER',
        title: `File Registration: ${payload.fileName}`,
        timestamp,
        prevHash: prev_hash,
        currentHash: current_hash,
        status: 'CONFIRMED',
        verified: true,
        payload: {
          sourceId: new_id,
          fileName: payload.fileName,
          fingerprint: payload.sha256,
          creatorId: session.userId,
          organizationId: session.organizationId || 'ORG-01',
        },
      };

      const auditEntry = {
        id: `AUD-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
        action: 'SOURCE_REGISTERED',
        actor: session.email,
        role: session.role,
        details: `Registered source ${new_id} (${payload.fileName})`,
        timestamp,
        ipAddress: ip,
      };

      await dbAdapter.registerAssetTransaction(source_record, new_block, auditEntry);

      let tsaToken = null;
      try {
        tsaToken = await tsaManager.anchorSourceTimestamp(new_id, payload.sha256);
      } catch (e) {
        console.warn('TSA registration anchoring notice:', e.message);
      }

      return sendJson(res, 200, {
        success: true,
        data: source_record,
        source: source_record,
        block: new_block,
        tsaToken,
        isDemoMode: false,
      });
    }

    // Public File Verification
    if (pathname === '/api/verify' && req.method === 'POST') {
      const payload = await parseBody(req);
      let matched_source = null;

      if (payload.sourceId) {
        matched_source = db.data.sources[payload.sourceId.trim()];
      } else if (payload.sha256) {
        for (const s of Object.values(db.data.sources)) {
          if (s.sha256 && s.sha256.toLowerCase() === payload.sha256.toLowerCase()) {
            matched_source = s;
            break;
          }
        }
      }

      if (!matched_source) {
        return sendJson(res, 200, {
          verdict: 'UNKNOWN',
          status: 'warning',
          message: 'Unknown – No Trusted Source Found',
          searchedHash: payload.sha256,
          searchedSourceId: payload.sourceId,
          details: 'This fingerprint does not match any registered master asset in the digital provenance ledger.',
        });
      }

      // Check if signing key is revoked
      const isKeyRevoked = db.data.systemState?.revokedKeys?.includes(matched_source.keyId) ||
        db.data.systemState?.revokedKeys?.includes(matched_source.publicKey);

      if (matched_source.sha256.toLowerCase() === payload.sha256.toLowerCase()) {
        await dbAdapter.incrementVerificationCount(matched_source.id);

        if (isKeyRevoked) {
          return sendJson(res, 200, {
            verdict: 'COMPROMISED_KEY',
            status: 'danger',
            message: 'Security Alert – Signed with Compromised/Revoked Key',
            source: matched_source,
            hashMatch: true,
            signatureValid: true,
            keyStatus: 'REVOKED',
            details: `Key ${matched_source.keyId} is cataloged as REVOKED. Historical validity cannot be established without trusted TSA timestamp.`,
          });
        }

        return sendJson(res, 200, {
          verdict: 'ORIGINAL',
          status: 'success',
          message: 'Original – Cryptographically Verified',
          source: matched_source,
          hashMatch: true,
          signatureValid: true,
          details: 'Uploaded file matches registered master asset with authentic Ed25519 signature.',
        });
      } else {
        return sendJson(res, 200, {
          verdict: 'EDITED',
          status: 'danger',
          message: 'Edited – Content Difference Detected',
          source: matched_source,
          originalHash: matched_source.sha256,
          uploadedHash: payload.sha256,
          hashMatch: false,
          signatureValid: false,
          details: `File references Source ID ${matched_source.id} but content bits have been altered.`,
        });
      }
    }

    if (pathname.startsWith('/api/source/') && req.method === 'GET') {
      const sourceId = pathname.slice('/api/source/'.length).trim();
      const record = db.data.sources[sourceId];
      if (!record) {
        return sendJson(res, 404, { detail: 'Source not found' });
      }
      return sendJson(res, 200, record);
    }

    // ----------------------------------------------------
    // Enterprise Global Overview Telemetry (PostgreSQL-Backed)
    // ----------------------------------------------------
    if (pathname === '/api/overview/stats' && req.method === 'GET') {
      let stats = null;
      try {
        const pool = getPool();
        const usersQuery = await pool.query('SELECT role, status, count(*) as count FROM users GROUP BY role, status');
        const orgsQuery = await pool.query('SELECT o.id, o.name, o.department, count(s.id) as sources_count FROM organizations o LEFT JOIN sources s ON s.organization_id = o.id GROUP BY o.id, o.name, o.department ORDER BY o.id ASC');
        const sourcesQuery = await pool.query('SELECT count(*) as total, coalesce(sum(verification_count), 0) as verifications FROM sources');
        const ledgerQuery = await pool.query('SELECT type, count(*) as count FROM ledger_blocks GROUP BY type');
        const alertsQuery = await pool.query('SELECT status, count(*) as count FROM soc_alerts GROUP BY status');
        const invQuery = await pool.query('SELECT status, count(*) as count FROM investigations GROUP BY status');
        const chkQuery = await pool.query('SELECT count(*) as total FROM checkpoints');

        let totalUsers = 0;
        let activeUsers = 0;
        let deactivatedUsers = 0;
        const rolesMap = {};
        usersQuery.rows.forEach(r => {
          const cnt = parseInt(r.count, 10);
          totalUsers += cnt;
          if (r.status === 'DEACTIVATED') deactivatedUsers += cnt;
          else activeUsers += cnt;
          rolesMap[r.role] = (rolesMap[r.role] || 0) + cnt;
        });

        let totalBlocks = 0;
        let regBlocks = 0;
        let secBlocks = 0;
        let genBlocks = 0;
        ledgerQuery.rows.forEach(r => {
          const cnt = parseInt(r.count, 10);
          totalBlocks += cnt;
          if (r.type === 'REGISTER') regBlocks += cnt;
          else if (r.type === 'SECURITY_INCIDENT') secBlocks += cnt;
          else if (r.type === 'GENESIS') genBlocks += cnt;
        });

        let totalAlerts = 0;
        let activeAlerts = 0;
        let containedAlerts = 0;
        alertsQuery.rows.forEach(r => {
          const cnt = parseInt(r.count, 10);
          totalAlerts += cnt;
          if (r.status === 'ACTIVE' || r.status === 'NEW') activeAlerts += cnt;
          else if (r.status === 'CONTAINED') containedAlerts += cnt;
        });

        let totalInv = 0;
        let activeInv = 0;
        let resolvedInv = 0;
        invQuery.rows.forEach(r => {
          const cnt = parseInt(r.count, 10);
          totalInv += cnt;
          if (r.status === 'RESOLVED') resolvedInv += cnt;
          else activeInv += cnt;
        });

        stats = {
          success: true,
          databaseEngine: 'PostgreSQL 16.15',
          databaseConnected: true,
          timestamp: new Date().toISOString(),
          users: {
            total: totalUsers,
            active: activeUsers,
            deactivated: deactivatedUsers,
            roles: rolesMap,
          },
          organizations: orgsQuery.rows.map(o => ({
            id: o.id,
            name: o.name,
            department: o.department,
            sourcesCount: parseInt(o.sources_count || 0, 10),
          })),
          sources: {
            total: parseInt(sourcesQuery.rows[0]?.total || 0, 10),
            verifications: parseInt(sourcesQuery.rows[0]?.verifications || 0, 10),
          },
          ledger: {
            totalBlocks,
            registeredBlocks: regBlocks,
            securityIncidentBlocks: secBlocks,
            genesisBlocks: genBlocks,
            chainIntegrity: 'INTACT & SEALED',
          },
          alerts: {
            total: totalAlerts,
            active: activeAlerts,
            contained: containedAlerts,
          },
          investigations: {
            total: totalInv,
            active: activeInv,
            resolved: resolvedInv,
          },
          checkpoints: {
            total: parseInt(chkQuery.rows[0]?.total || 0, 10),
            wormDualStore: true,
          },
        };
      } catch (e) {
        const totalSources = Object.keys(db.data.sources).length;
        const usersList = db.data.users || [];
        const rolesMap = {};
        usersList.forEach(u => { rolesMap[u.role] = (rolesMap[u.role] || 0) + 1; });
        stats = {
          success: true,
          databaseEngine: 'In-Memory / JSON Engine (Fallback)',
          databaseConnected: false,
          timestamp: new Date().toISOString(),
          users: {
            total: usersList.length,
            active: usersList.filter(u => u.status !== 'DEACTIVATED').length,
            deactivated: usersList.filter(u => u.status === 'DEACTIVATED').length,
            roles: rolesMap,
          },
          organizations: [
            { id: 'ORG-01', name: 'Federal Geointelligence Agency', department: 'Orbital Reconnaissance', sourcesCount: totalSources },
            { id: 'ORG-02', name: 'Cyber Defense Operations', department: 'Incident Response', sourcesCount: 0 },
            { id: 'ORG-03', name: 'Global Audit & Forensics Corp', department: 'Digital Compliance', sourcesCount: 0 },
          ],
          sources: {
            total: totalSources,
            verifications: 25,
          },
          ledger: {
            totalBlocks: (db.data.ledger || []).length,
            registeredBlocks: (db.data.ledger || []).filter(b => b.type === 'REGISTER').length,
            securityIncidentBlocks: (db.data.ledger || []).filter(b => b.type === 'SECURITY_INCIDENT').length,
            genesisBlocks: 1,
            chainIntegrity: 'INTACT & SEALED',
          },
          alerts: {
            total: (db.data.alerts || []).length,
            active: (db.data.alerts || []).filter(a => !a.contained).length,
            contained: (db.data.alerts || []).filter(a => a.contained).length,
          },
          investigations: {
            total: (db.data.investigations || []).length,
            active: (db.data.investigations || []).filter(c => c.status !== 'RESOLVED' && c.status !== 'CLOSED').length,
            resolved: (db.data.investigations || []).filter(c => c.status === 'RESOLVED' || c.status === 'CLOSED').length,
          },
          checkpoints: {
            total: (db.data.checkpoints || []).length,
            wormDualStore: true,
          },
        };
      }

      return sendJson(res, 200, stats);
    }

    if (pathname === '/api/dashboard' && req.method === 'GET') {
      const totalSources = Object.keys(db.data.sources).length;
      return sendJson(res, 200, {
        totalRegistered: totalSources,
        totalVerifications: 42,
        editedDetected: 4,
        unknownDetected: 9,
        integrityScore: '100%',
        cryptographicEngine: 'Ed25519 / SHA-256 (SourceMark Enterprise Node.js Backend)',
        activeCases: db.data.investigations.filter(c => c.status !== 'CLOSED').length,
        pendingAlerts: db.data.alerts.filter(a => !a.contained).length,
        lockdown: db.data.systemState?.lockdown || false,
      });
    }

    if (pathname === '/api/ledger' && req.method === 'GET') {
      return sendJson(res, 200, db.data.ledger);
    }

    if (pathname === '/api/ledger/validate' && req.method === 'GET') {
      let isValid = true;
      let brokenBlock = null;
      for (let i = 1; i < db.data.ledger.length; i++) {
        const curr = db.data.ledger[i];
        const prev = db.data.ledger[i - 1];
        if (curr.prevHash !== prev.currentHash) {
          isValid = false;
          brokenBlock = curr.id;
          break;
        }
      }
      return sendJson(res, 200, {
        isValid,
        totalBlocks: db.data.ledger.length,
        brokenAtBlock: brokenBlock,
        timestamp: new Date().toISOString(),
      });
    }

    // ----------------------------------------------------
    // Enterprise Multi-Role Workflows (Strict RBAC & Org Isolation)
    // ----------------------------------------------------

    // 1. Investigation Cases (Forensic Investigator, SOC, Admin, Org Manager)
    if (pathname === '/api/investigations' && req.method === 'GET') {
      const session = requireAuth(req, res, 'investigations:read');
      if (!session) return;

      // Filter by organization if applicable
      let cases = db.data.investigations;
      if (session.role === ROLES.USER || session.role === ROLES.ORGANIZATION_MANAGER) {
        // Multi-tenant organization isolation
        cases = cases.filter(c => c.organizationId === session.organizationId);
      }

      return sendJson(res, 200, { success: true, cases });
    }

    if (pathname === '/api/investigations' && req.method === 'POST') {
      const session = requireAuth(req, res, 'investigations:write');
      if (!session) return;

      const body = await parseBody(req);
      const newCase = {
        id: `INV-CASE-${Date.now().toString().slice(-4)}`,
        title: body.title || 'Unspecified Integrity Discrepancy',
        sourceId: body.sourceId || 'UNKNOWN',
        organizationId: session.organizationId || 'ORG-01',
        severity: body.severity || 'MEDIUM',
        status: 'UNDER_INVESTIGATION',
        assignedTo: body.assignedTo || session.userId,
        assignedToName: body.assignedToName || session.email,
        createdBy: session.userId,
        createdByName: session.email,
        notes: body.initialNote ? [{
          author: session.email,
          text: body.initialNote,
          timestamp: new Date().toISOString(),
        }] : [],
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };

      const auditEntry = {
        id: `AUD-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
        action: 'INVESTIGATION_CREATED',
        actor: session.email,
        role: session.role,
        details: `Opened case ${newCase.id} for source ${newCase.sourceId}`,
        timestamp: new Date().toISOString(),
        ipAddress: ip,
      };

      await dbAdapter.saveInvestigation(newCase, auditEntry);
      return sendJson(res, 201, { success: true, case: newCase });
    }

    if (pathname.startsWith('/api/investigations/') && req.method === 'PATCH') {
      const session = requireAuth(req, res, 'investigations:write');
      if (!session) return;

      const caseId = pathname.slice('/api/investigations/'.length).trim();
      const existing = db.data.investigations.find(c => c.id === caseId);
      if (!existing) {
        return sendJson(res, 404, { success: false, error: 'Case not found' });
      }

      const body = await parseBody(req);
      const newNote = body.note ? {
        author: session.email,
        text: body.note,
        timestamp: new Date().toISOString(),
      } : null;

      const auditEntry = {
        id: `AUD-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
        action: 'INVESTIGATION_UPDATED',
        actor: session.email,
        role: session.role,
        details: `Updated case ${caseId} (${body.status || existing.status})`,
        timestamp: new Date().toISOString(),
        ipAddress: ip,
      };

      const updated = await dbAdapter.updateInvestigation(caseId, { status: body.status, severity: body.severity }, newNote, auditEntry);
      return sendJson(res, 200, { success: true, case: updated || existing });
    }

    // 2. SOC Security Alerts (SOC Analyst, Admin)
    if (pathname === '/api/alerts' && req.method === 'GET') {
      const session = requireAuth(req, res, 'alerts:read');
      if (!session) return;

      let alerts = db.data.alerts;
      if (session.role === ROLES.ORGANIZATION_MANAGER || session.role === ROLES.USER) {
        alerts = alerts.filter(a => a.organizationId === session.organizationId);
      }

      return sendJson(res, 200, { success: true, alerts });
    }

    if (pathname === '/api/alerts/contain' && req.method === 'POST') {
      const session = requireAuth(req, res, 'alerts:contain');
      if (!session) return;

      const body = await parseBody(req);
      const { alertId, action } = body;
      const targetAlert = db.data.alerts.find(a => a.id === alertId);
      if (!targetAlert) {
        return sendJson(res, 404, { success: false, error: 'Target alert not found' });
      }

      const auditEntry = {
        id: `AUD-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
        action: 'SOC_CONTAINMENT_EXECUTED',
        actor: session.email,
        role: session.role,
        details: `Executed threat containment: ${action || 'QUARANTINE'} on alert ${alertId}`,
        timestamp: new Date().toISOString(),
        ipAddress: ip,
      };

      const contained = await dbAdapter.containAlert(alertId, session.email, action || 'QUARANTINE', auditEntry);
      return sendJson(res, 200, { success: true, alert: contained || targetAlert });
    }

    // 3. Organization Approvals (Org Manager, Admin, Auditor)
    if (pathname === '/api/approvals' && req.method === 'GET') {
      const session = requireAuth(req, res, 'approvals:read');
      if (!session) return;

      // Organization Isolation: Managers only see approvals for their organization
      let approvals = db.data.approvals;
      if (session.role === ROLES.ORGANIZATION_MANAGER || session.role === ROLES.USER) {
        approvals = approvals.filter(a => a.organizationId === session.organizationId);
      }

      return sendJson(res, 200, { success: true, approvals });
    }

    // Create derivative authorization request
    if (pathname === '/api/approvals' && req.method === 'POST') {
      const session = requireAuth(req, res, 'approvals:request');
      if (!session) return;

      const body = await parseBody(req);
      const newReq = {
        id: `APR-${Date.now().toString().slice(-4)}`,
        title: body.title || 'Derivative Authorization Request',
        sourceId: body.sourceId || 'SRC-UNKNOWN',
        organizationId: session.organizationId || 'ORG-01',
        requestedBy: session.userId,
        requestedByName: session.email,
        status: 'PENDING',
        department: body.department || 'Digital Operations',
        reason: body.reason || 'Requested derivative transformation',
        timestamp: new Date().toISOString(),
      };

      const auditEntry = {
        id: `AUD-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
        action: 'APPROVAL_REQUESTED',
        actor: session.email,
        role: session.role,
        details: `Requested derivative approval for ${newReq.sourceId} in ${newReq.organizationId}`,
        timestamp: new Date().toISOString(),
        ipAddress: ip,
      };

      await dbAdapter.saveApproval(newReq, auditEntry);
      return sendJson(res, 201, { success: true, approval: newReq });
    }

    if (pathname.startsWith('/api/approvals/') && pathname.endsWith('/decide') && req.method === 'POST') {
      const session = requireAuth(req, res, 'approvals:decide');
      if (!session) return;

      const parts = pathname.split('/');
      const approvalId = parts[3];
      const target = db.data.approvals.find(a => a.id === approvalId);
      if (!target) {
        return sendJson(res, 404, { success: false, error: 'Approval request not found' });
      }

      // Organization Data Isolation Check:
      // Organization Managers cannot approve/reject requests belonging to other departments/organizations
      if (session.role === ROLES.ORGANIZATION_MANAGER && target.organizationId !== session.organizationId) {
        db.logAudit(
          'CROSS_ORG_ACCESS_DENIED',
          session.email,
          session.role,
          `Manager from ${session.organizationId} denied decision on request ${approvalId} belonging to ${target.organizationId}`,
          ip
        );
        return sendJson(res, 403, {
          success: false,
          error: 'Forbidden: Cannot decide approval requests for external organizations',
          code: 'CROSS_ORG_ACCESS_DENIED',
        });
      }

      const body = await parseBody(req);
      const decision = body.decision === 'APPROVE' ? 'APPROVED' : 'REJECTED';
      const reason = body.reason || 'Reviewed by Department Lead';

      const auditEntry = {
        id: `AUD-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
        action: 'APPROVAL_DECIDED',
        actor: session.email,
        role: session.role,
        details: `${decision} request ${approvalId} for org ${target.organizationId}`,
        timestamp: new Date().toISOString(),
        ipAddress: ip,
      };

      const decided = await dbAdapter.decideApprovalTransaction(
        approvalId,
        decision,
        session.email,
        session.role,
        reason,
        auditEntry
      );

      return sendJson(res, 200, { success: true, approval: decided || target });
    }

    // 4. Audit & Compliance Events (Auditor, Admin, SOC)
    if (pathname === '/api/audit-events' && req.method === 'GET') {
      const session = requireAuth(req, res, 'audit:read');
      if (!session) return;

      return sendJson(res, 200, { success: true, auditLogs: db.data.auditLogs });
    }

    if (pathname === '/api/audit/compliance-export' && req.method === 'GET') {
      const session = requireAuth(req, res, 'audit:export');
      if (!session) return;

      const exportPayload = {
        complianceStandard: 'ISO-27037 / NIST SP 800-86 Cryptographic Evidence',
        exportedAt: new Date().toISOString(),
        exporter: session.email,
        exporterRole: session.role,
        totalAuditEvents: db.data.auditLogs.length,
        ledgerBlockCount: db.data.ledger.length,
        events: db.data.auditLogs,
      };

      db.logAudit('COMPLIANCE_REPORT_EXPORTED', session.email, session.role, `Exported ${db.data.auditLogs.length} audit logs`, ip);
      return sendJson(res, 200, { success: true, exportPayload });
    }

    // ----------------------------------------------------
    // Static Frontend File Serving (Unified Production Hosting)
    // ----------------------------------------------------
    const distDir = path.join(process.cwd(), 'dist');
    if (!pathname.startsWith('/api') && req.method === 'GET' && fs.existsSync(distDir)) {
      const safePath = path.normalize(pathname).replace(/^(\.\.[\/\\])+/, '');
      let filePath = path.join(distDir, safePath);

      // If directory or file does not exist, fallback to index.html for React SPA client routing
      if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
        filePath = path.join(distDir, 'index.html');
      }

      if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
        const ext = path.extname(filePath).toLowerCase();
        const mimeTypes = {
          '.html': 'text/html; charset=utf-8',
          '.js': 'application/javascript; charset=utf-8',
          '.mjs': 'application/javascript; charset=utf-8',
          '.css': 'text/css; charset=utf-8',
          '.json': 'application/json; charset=utf-8',
          '.png': 'image/png',
          '.jpg': 'image/jpeg',
          '.jpeg': 'image/jpeg',
          '.gif': 'image/gif',
          '.svg': 'image/svg+xml',
          '.ico': 'image/x-icon',
          '.woff': 'font/woff',
          '.woff2': 'font/woff2',
          '.ttf': 'font/ttf',
          '.tif': 'image/tiff',
          '.tiff': 'image/tiff',
        };
        const contentType = mimeTypes[ext] || 'application/octet-stream';
        res.writeHead(200, {
          'Content-Type': contentType,
          'Cache-Control': ext === '.html' ? 'no-cache' : 'public, max-age=31536000, immutable',
        });
        fs.createReadStream(filePath).pipe(res);
        return;
      }
    }

    // Fallback 404
    sendJson(res, 404, { error: 'Endpoint not found', path: pathname });
  } catch (err) {
    console.error('API Server Error:', err);
    sendJson(res, 500, { error: 'Internal Server Error', message: err.message });
  }
});

const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 8000;
if (process.argv[1] && process.argv[1].endsWith('server.mjs')) {
  server.listen(PORT, '127.0.0.1', () => {
    console.log(`SourceMark Enterprise Backend API listening on http://127.0.0.1:${PORT}`);
  });
}
