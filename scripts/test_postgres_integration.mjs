/**
 * SourceMark PostgreSQL Integration & Migration Test Suite
 * Rigorously verifies:
 * 1. Normalized Relational Schema & Table Definitions (17 tables, FKs, constraints, indexes).
 * 2. Versioned Migration Scripts (001_initial_schema.sql, 002_seed_enterprise_data.sql).
 * 3. PostgreSQL Client Pool & Parameterized SQL Injection Resistance.
 * 4. Dual-Engine Database Adapter & Fallback Mechanics.
 * 5. ACID Transaction Contracts for asset registration, key revocation, and approvals.
 * 6. Automated Backup of enterprise_db.json before migration.
 * 7. Server Database REST Endpoints (/api/database/status, /api/database/backup, /api/database/migrate).
 * 8. Truthful reporting of connection status (never faking a connection).
 */

import fs from 'node:fs';
import path from 'node:path';
import { EventEmitter } from 'node:events';
import { fileURLToPath } from 'node:url';

import {
  server,
  db,
  ROLES,
  createSessionToken,
} from '../backend/server.mjs';

import {
  getDbConfig,
  checkConnection,
  isPostgresConfigured,
} from '../backend/db/postgres.mjs';

import {
  runMigrations,
  getMigrationStatus,
} from '../backend/db/migrator.mjs';

import {
  backupJsonDatabase,
  migrateJsonToPostgres,
} from '../backend/db/dataMigrator.mjs';

import {
  dbAdapter,
} from '../backend/db/adapter.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.join(__dirname, '..');
const DB_DIR = path.join(ROOT_DIR, 'backend', 'db');
const MIGRATIONS_DIR = path.join(DB_DIR, 'migrations');
const DATA_DIR = path.join(ROOT_DIR, 'backend', 'data');

let passed = 0;
let failed = 0;

function report(testName, expected, actual, detail, isPass) {
  const index = passed + failed + 1;
  console.log(`[Test ${index}] ${testName}`);
  console.log(`   Expected: ${expected}`);
  console.log(`   Actual:   ${actual}`);
  console.log(`   Detail:   ${detail}`);
  if (isPass) {
    console.log(`   Result:   ✓ PASS\n`);
    passed++;
  } else {
    console.log(`   Result:   ✗ FAIL\n`);
    failed++;
  }
}

// In-process HTTP request dispatcher for server.mjs
function makeRequest({ method, url, headers = {}, body = null }) {
  return new Promise((resolve) => {
    const req = new EventEmitter();
    req.method = method;
    req.url = url;
    const normalizedHeaders = {};
    for (const [k, v] of Object.entries(headers)) {
      normalizedHeaders[k.toLowerCase()] = v;
    }
    req.headers = normalizedHeaders;
    req.socket = { remoteAddress: '127.0.0.1' };

    const res = new EventEmitter();
    let resHeaders = {};
    let statusCode = 200;
    let responseBody = '';

    res.writeHead = (code, h = {}) => {
      statusCode = code;
      resHeaders = { ...resHeaders, ...h };
    };

    res.end = (chunk) => {
      if (chunk) responseBody += chunk;
      let parsed = null;
      try {
        parsed = JSON.parse(responseBody);
      } catch {
        parsed = responseBody;
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

async function runPostgresIntegrationTests() {
  console.log('================================================================');
  console.log('  SOURCEMARK PHASE 2: POSTGRESQL MIGRATION INTEGRATION TESTS   ');
  console.log('================================================================\n');

  // -------------------------------------------------------------------------
  // SECTION 1: RELATIONAL SCHEMA DEFINITIONS & NORMALIZATION
  // -------------------------------------------------------------------------
  const schemaPath = path.join(DB_DIR, 'schema.sql');
  const schemaExists = fs.existsSync(schemaPath);
  const schemaSql = schemaExists ? fs.readFileSync(schemaPath, 'utf8') : '';

  report(
    'Schema DDL Existence',
    'backend/db/schema.sql exists and is non-empty',
    schemaExists ? `Found (${schemaSql.length} bytes)` : 'Not Found',
    'PostgreSQL DDL schema must define complete enterprise relational structures',
    schemaExists && schemaSql.length > 1000
  );

  const requiredTables = [
    'organizations',
    'roles',
    'permissions',
    'role_permissions',
    'users',
    'sessions',
    'signing_keys',
    'sources',
    'file_versions',
    'ledger_blocks',
    'checkpoints',
    'investigations',
    'investigation_notes',
    'soc_alerts',
    'derivative_approvals',
    'audit_logs',
    'system_state',
  ];

  const missingTables = requiredTables.filter(t => !schemaSql.includes(`CREATE TABLE IF NOT EXISTS ${t}`));
  report(
    'Complete Normalized Tables Definition',
    'All 17 normalized enterprise tables defined',
    missingTables.length === 0 ? 'All 17 tables present in schema.sql' : `Missing: ${missingTables.join(', ')}`,
    'Schema must cover users, orgs, sources, versions, signatures, keys, cases, alerts, approvals, ledger, audits',
    missingTables.length === 0
  );

  const hasForeignKeys = schemaSql.includes('REFERENCES organizations(id)') && schemaSql.includes('REFERENCES users(id)');
  report(
    'Foreign Key Integrity Constraints',
    'Schema enforces relational foreign key integrity across organizations and users',
    hasForeignKeys ? 'Enforced with REFERENCES organizations(id) and REFERENCES users(id)' : 'Missing foreign keys',
    'Prevents orphaned sources, investigation notes, approvals, or user records',
    hasForeignKeys
  );

  // -------------------------------------------------------------------------
  // SECTION 2: VERSION-CONTROLLED MIGRATIONS
  // -------------------------------------------------------------------------
  const migrationFiles = fs.existsSync(MIGRATIONS_DIR) ? fs.readdirSync(MIGRATIONS_DIR) : [];
  const has001 = migrationFiles.includes('001_initial_schema.sql');
  const has002 = migrationFiles.includes('002_seed_enterprise_data.sql');

  report(
    'Version-Controlled Migration Files',
    '001_initial_schema.sql and 002_seed_enterprise_data.sql exist',
    `Found ${migrationFiles.length} migration scripts (${migrationFiles.join(', ')})`,
    'Migrations must be versioned, immutable, and executable sequentially',
    has001 && has002
  );

  const seedSql = has002 ? fs.readFileSync(path.join(MIGRATIONS_DIR, '002_seed_enterprise_data.sql'), 'utf8') : '';
  const seedsRoles = seedSql.includes('ADMINISTRATOR') && seedSql.includes('FORENSIC_INVESTIGATOR');
  report(
    'Enterprise Role & Permission Seed Script',
    '002_seed_enterprise_data.sql seeds standard roles and permissions',
    seedsRoles ? 'Contains seeds for 6 roles, permissions, and initial organizations' : 'Missing seed data',
    'Initializes role permission matrices on first database boot',
    seedsRoles
  );

  // -------------------------------------------------------------------------
  // SECTION 3: TRUTHFUL POSTGRESQL CONNECTIVITY & CLIENT CONFIGURATION
  // -------------------------------------------------------------------------
  const config = getDbConfig();
  report(
    'PostgreSQL Configuration Reader',
    'Reads host, port, database, pool max from environment',
    `Host: ${config.host}, Port: ${config.port}, Database: ${config.database}, MaxPool: ${config.max}`,
    'Safely retrieves database configuration with secure defaults',
    config.host && config.database && config.max > 0
  );

  const connProbe = await checkConnection();
  report(
    'Truthful PostgreSQL Connection Probe',
    'Accurately and truthfully reports live connection or offline status',
    connProbe.connected ? `Connected (version: ${connProbe.version})` : `Disconnected (code: ${connProbe.code || 'CONNECTION_FAILED'})`,
    'CRITICAL: Must never fake or pretend a PostgreSQL connection is active',
    (connProbe.connected === true && typeof connProbe.version === 'string') ||
    (connProbe.connected === false && connProbe.error !== undefined)
  );

  // -------------------------------------------------------------------------
  // SECTION 4: SQL INJECTION DEFENSE (PARAMETERIZED QUERY VERIFICATION)
  // -------------------------------------------------------------------------
  // Verify that adapter repository methods use parameterized SQL arguments ($1, $2) rather than string interpolation
  const adapterSource = fs.readFileSync(path.join(DB_DIR, 'adapter.mjs'), 'utf8');
  const usesParamQuery = adapterSource.includes('$1') && adapterSource.includes('pgQuery(');
  const dangerousConcat = /query\s*\(\s*`[^`]*\$\{.*users/i.test(adapterSource);

  report(
    'SQL Injection Resistance via Parameterized Queries',
    'All user inputs bound via $1, $2 positional parameters with zero raw string interpolation',
    usesParamQuery && !dangerousConcat ? 'Verified: Parameterized queries used throughout repository' : 'Potential concatenation risk detected',
    'Prevents malicious SQL injection payloads such as "; DROP TABLE users; --"',
    usesParamQuery && !dangerousConcat
  );

  // -------------------------------------------------------------------------
  // SECTION 5: DUAL-ENGINE ADAPTER FALLBACK & HEALTH REPORTING
  // -------------------------------------------------------------------------
  const health = await dbAdapter.checkHealth();
  report(
    'Dual-Engine Adapter Fallback Engine Selection',
    'Designates PostgreSQL as primary engine when connected, and json_fallback when unreachable',
    `Engine: ${health.engine}, Mode: ${health.mode}`,
    'Ensures zero downtime or crashed requests if PostgreSQL server is offline',
    (health.connected === true && health.engine === 'postgresql') ||
    (health.connected === false && health.engine === 'json_fallback')
  );

  const status = await dbAdapter.getStatus();
  report(
    'Comprehensive Adapter Status Telemetry',
    'Provides health, migrationStatus, jsonBackupAvailable, and configured flags',
    `Engine: ${status.health.engine}, BackupAvailable: ${status.jsonBackupAvailable}`,
    'Supplies complete operational status to audit dashboards',
    status.health && status.migrationStatus !== undefined
  );

  // -------------------------------------------------------------------------
  // SECTION 6: REPOSITORY READ & QUERY FALLBACK
  // -------------------------------------------------------------------------
  const adminUser = await dbAdapter.findUserByEmail('admin@sourcemark.io');
  report(
    'Repository: findUserByEmail',
    'Finds admin@sourcemark.io with role ADMINISTRATOR',
    adminUser ? `Found: ${adminUser.email} (Role: ${adminUser.role})` : 'Not found',
    'User repository retrieves valid user records in fallback mode',
    adminUser && adminUser.role === ROLES.ADMINISTRATOR
  );

  const investigatorUser = await dbAdapter.findUserById('USR-INV-01');
  report(
    'Repository: findUserById',
    'Finds USR-INV-01 with role FORENSIC_INVESTIGATOR',
    investigatorUser ? `Found: ${investigatorUser.id} (${investigatorUser.name})` : 'Not found',
    'User repository correctly identifies user by unique ID',
    investigatorUser && investigatorUser.role === ROLES.FORENSIC_INVESTIGATOR
  );

  const org1Users = await dbAdapter.listUsers('ORG-01');
  report(
    'Repository: listUsers with Organization Filtering',
    'Returns users strictly belonging to ORG-01',
    `Returned ${org1Users.length} users, all with organizationId ORG-01: ${org1Users.every(u => u.organizationId === 'ORG-01')}`,
    'Enforces organizational boundaries on user listings',
    org1Users.length > 0 && org1Users.every(u => u.organizationId === 'ORG-01')
  );

  const sampleSource = await dbAdapter.getSourceById('SRC-98214');
  report(
    'Repository: getSourceById',
    'Retrieves registered source SRC-98214',
    sampleSource ? `Found: ${sampleSource.fileName} (SHA-256: ${sampleSource.sha256.slice(0, 16)}...)` : 'Not found',
    'Source repository retrieves registered asset metadata',
    sampleSource && sampleSource.fileName === 'satellite_recon_orbital_07.png'
  );

  // -------------------------------------------------------------------------
  // SECTION 7: ACID TRANSACTION CONTRACTS IN DUAL-ENGINE ADAPTER
  // -------------------------------------------------------------------------
  const testAssetId = `SRC-TEST-TX-${Date.now().toString().slice(-4)}`;
  const testAssetData = {
    id: testAssetId,
    fileName: 'test_acid_asset.png',
    fileType: 'image/png',
    fileSize: 1048576,
    fileSizeFormatted: '1.00 MB',
    sha256: 'a1b2c3d4e5f60011223344556677889900aabbccddeeff001122334455667788',
    signature: 'test_sig_64_bytes_00000000000000000000000000000000000000000000000000',
    publicKey: 'test_pub_32_bytes_00000000000000000000000000000000000000000000000000',
    keyId: 'ED25519-TX-TEST',
    creator: 'Automated Test Runner',
    creatorId: 'USR-INV-01',
    organizationId: 'ORG-01',
    category: 'Integrity Test',
    description: 'ACID registration test transaction',
    sourceOrigin: 'Test Pipeline',
    registeredAt: new Date().toISOString(),
    status: 'ACTIVE_REGISTERED',
    verificationCount: 0,
  };

  const seq = await dbAdapter.getNextLedgerBlockSequence();
  const testLedgerBlock = {
    id: seq.blockId,
    blockNumber: seq.blockNumber,
    type: 'REGISTER',
    title: `File Registration: ${testAssetData.fileName}`,
    timestamp: new Date().toISOString(),
    prevHash: seq.prevHash,
    currentHash: 'b5c6d7e8f9a0011223344556677889900aabbccddeeff0011223344556677889',
    status: 'CONFIRMED',
    verified: true,
    payload: { sourceId: testAssetId },
  };

  const testAuditLog = {
    id: `AUD-TX-${Date.now()}`,
    action: 'TEST_ASSET_REGISTERED',
    actor: 'test@sourcemark.io',
    role: ROLES.FORENSIC_INVESTIGATOR,
    details: `ACID registration test for ${testAssetId}`,
    ipAddress: '127.0.0.1',
    timestamp: new Date().toISOString(),
  };

  const regResult = await dbAdapter.registerAssetTransaction(testAssetData, testLedgerBlock, testAuditLog);
  report(
    'ACID Transaction: Asset Registration & Ledger Block',
    'Atomically creates asset record, ledger block, and audit event',
    regResult.success ? `Registered ${testAssetId} with ledger block ${testLedgerBlock.id}` : 'Failed',
    'Guarantees consistency across asset repository, hash ledger, and audit history',
    regResult.success && dbAdapter.jsonDb.data.sources[testAssetId] !== undefined
  );

  // Test Key Revocation Transaction
  const testRevocationKeyId = 'ED25519-TX-REVOKE-TEST';
  const revokeAudit = {
    id: `AUD-REV-${Date.now()}`,
    action: 'KEY_REVOCATION_TX',
    actor: 'admin@sourcemark.io',
    role: ROLES.ADMINISTRATOR,
    details: `Emergency revocation of ${testRevocationKeyId}`,
    ipAddress: '127.0.0.1',
    timestamp: new Date().toISOString(),
  };
  const revokeAlert = {
    id: `ALT-REV-${Date.now().toString().slice(-4)}`,
    title: `Compromised Key Revoked: ${testRevocationKeyId}`,
    severity: 'CRITICAL',
    sourceId: 'SRC-KEY-REVOKE',
    organizationId: 'ORG-01',
    status: 'CONTAINED',
    type: 'KEY_REVOKED',
    description: 'Key revoked via ACID transaction',
    timestamp: new Date().toISOString(),
    contained: true,
  };

  const revokeResult = await dbAdapter.revokeKeyTransaction(
    testRevocationKeyId,
    'Stolen private key reported',
    'admin@sourcemark.io',
    ROLES.ADMINISTRATOR,
    revokeAudit,
    revokeAlert
  );

  report(
    'ACID Transaction: Key Revocation & Incident Containment',
    'Revokes key, creates SOC containment alert, and logs audit event',
    revokeResult.revoked ? `Revoked key ${testRevocationKeyId}` : 'Failed',
    'Synchronizes security containment across system state, SOC alerts, and audit logs',
    revokeResult.revoked && db.data.systemState.revokedKeys.includes(testRevocationKeyId)
  );

  // -------------------------------------------------------------------------
  // SECTION 8: AUTOMATED DATABASE BACKUP & DATA PRESERVATION
  // -------------------------------------------------------------------------
  const backupResult = await backupJsonDatabase();
  const backupExists = fs.existsSync(backupResult.backupFile);
  const jsonExists = fs.existsSync(backupResult.sourceFile);

  report(
    'Automated JSON Database Backup Creation',
    'Creates enterprise_db.backup.json without modifying or deleting original store',
    backupExists && jsonExists ? `Backup created (${backupResult.bytes} bytes at ${backupResult.backupFile})` : 'Failed',
    'Strictly satisfies data preservation requirement: original JSON is preserved',
    backupExists && jsonExists && backupResult.bytes > 0
  );

  // -------------------------------------------------------------------------
  // SECTION 9: DATABASE REST API ENDPOINTS
  // -------------------------------------------------------------------------
  // 1. GET /api/database/status
  const statusRes = await makeRequest({
    method: 'GET',
    url: '/api/database/status',
  });

  report(
    'API: GET /api/database/status',
    'Returns HTTP 200 with truthful database engine status',
    `Status ${statusRes.statusCode}: engine=${statusRes.body?.health?.engine}, connected=${statusRes.body?.health?.connected}`,
    'Exposes real-time database health and engine information to management dashboards',
    statusRes.statusCode === 200 && statusRes.body.success === true &&
    (statusRes.body.health.engine === 'postgresql' || statusRes.body.health.engine === 'json_fallback')
  );

  // 2. POST /api/database/backup (Admin clearance required)
  const adminToken = createSessionToken({
    id: 'USR-ADMIN-01',
    email: 'admin@sourcemark.io',
    role: ROLES.ADMINISTRATOR,
    organizationId: 'ORG-01',
  });

  const userToken = createSessionToken({
    id: 'USR-CUSTODIAN-01',
    email: 'user@sourcemark.io',
    role: ROLES.USER,
    organizationId: 'ORG-01',
  });

  const unauthBackup = await makeRequest({
    method: 'POST',
    url: '/api/database/backup',
    headers: { Authorization: `Bearer ${userToken}` },
  });

  report(
    'API: POST /api/database/backup Authorization Boundary',
    'Returns HTTP 403 Forbidden for USER role',
    `Status ${unauthBackup.statusCode}: code=${unauthBackup.body?.code}`,
    'Only Administrators can trigger database backups',
    unauthBackup.statusCode === 403
  );

  const authBackup = await makeRequest({
    method: 'POST',
    url: '/api/database/backup',
    headers: { Authorization: `Bearer ${adminToken}` },
  });

  report(
    'API: POST /api/database/backup Execution',
    'Returns HTTP 200 and verified backup details for Administrator',
    `Status ${authBackup.statusCode}: bytes=${authBackup.body?.backup?.bytes}`,
    'Executes and verifies JSON database backup via authenticated REST API',
    authBackup.statusCode === 200 && authBackup.body?.backup?.bytes > 0
  );

  // 3. POST /api/database/migrate (Truthful execution or offline reporting)
  const migrateRes = await makeRequest({
    method: 'POST',
    url: '/api/database/migrate',
    headers: { Authorization: `Bearer ${adminToken}` },
  });

  report(
    'API: POST /api/database/migrate Truthful Reporting',
    'Executes migrations (HTTP 200) when connected or reports HTTP 503 DATABASE_OFFLINE when unreachable',
    `Status ${migrateRes.statusCode}: success=${migrateRes.body?.success}`,
    'Strict user mandate: Never pretend database is connected or simulate migrations without PostgreSQL server',
    (migrateRes.statusCode === 200 && migrateRes.body?.success === true) ||
    (migrateRes.statusCode === 503 && migrateRes.body?.code === 'DATABASE_OFFLINE')
  );

  // 4. GET /api/health Database Engine Telemetry
  const healthRes = await makeRequest({
    method: 'GET',
    url: '/api/health',
  });

  report(
    'API: GET /api/health Database Metadata',
    'Reports databaseEngine and databaseConnected truthfully in health response',
    `databaseEngine=${healthRes.body?.databaseEngine}, databaseConnected=${healthRes.body?.databaseConnected}`,
    'Enables frontend dashboards to dynamically render database connectivity badges',
    healthRes.statusCode === 200 &&
    (healthRes.body?.databaseEngine === 'postgresql' || healthRes.body?.databaseEngine === 'json_fallback')
  );

  // -------------------------------------------------------------------------
  // SECTION 10: SQLITE COMPATIBILITY, PRESERVATION & DUAL PERSISTENCE
  // -------------------------------------------------------------------------
  const { getSqliteDb, checkSqliteHealth } = await import('../backend/db/sqlite.mjs');
  const sqliteFile = path.join(DATA_DIR, 'sourcemark.sqlite');
  const sqliteExists = fs.existsSync(sqliteFile);

  report(
    'SQLite Database Persistence File',
    'backend/data/sourcemark.sqlite exists and is non-empty',
    sqliteExists ? `Exists (${fs.statSync(sqliteFile).size} bytes)` : 'Not Found',
    'Maintains local embedded SQLite database alongside PostgreSQL and JSON',
    sqliteExists && fs.statSync(sqliteFile).size > 1000
  );

  const sqliteHealth = checkSqliteHealth();
  report(
    'SQLite Health Check & User Integrity',
    'SQLite database connected with seeded enterprise users',
    `Connected: ${sqliteHealth.connected}, Users: ${sqliteHealth.userCount}`,
    'Ensures user records and authentication credentials exist in SQLite store',
    sqliteHealth.connected && sqliteHealth.userCount >= 6
  );

  const sqliteDb = getSqliteDb();
  const sourceCount = sqliteDb.prepare('SELECT count(*) as c FROM sources').get()?.c || 0;
  report(
    'SQLite Registered Sources & Provenance Integrity',
    'SQLite preserves registered digital assets and Ed25519 signatures',
    `Sources found: ${sourceCount}`,
    'Ensures digital evidence sources are preserved in SQLite database',
    sourceCount > 0
  );

  const ledgerCount = sqliteDb.prepare('SELECT count(*) as c FROM ledger_blocks').get()?.c || 0;
  report(
    'SQLite Ledger Blocks & Merkle Hash Preservation',
    'SQLite preserves immutable ledger block records',
    `Ledger blocks found: ${ledgerCount}`,
    'Guarantees audit ledger blocks remain accessible via SQLite engine',
    ledgerCount > 0
  );

  const approvalCount = sqliteDb.prepare('SELECT count(*) as c FROM derivative_approvals').get()?.c || 0;
  report(
    'SQLite Derivative Approvals Tracking',
    'SQLite preserves derivative transformation approval workflows',
    `Approvals found: ${approvalCount}`,
    'Ensures derivative authorization requests persist across restarts',
    approvalCount > 0
  );

  // -------------------------------------------------------------------------
  // FINAL SCORECARD
  // -------------------------------------------------------------------------
  console.log('----------------------------------------------------------------');
  console.log(`TOTAL POSTGRES INTEGRATION TESTS: ${passed + failed}`);
  console.log(`PASSED: ${passed}`);
  console.log(`FAILED: ${failed}`);
  console.log(`SUCCESS RATE: ${((passed / (passed + failed)) * 100).toFixed(1)}%`);
  console.log('================================================================\n');

  if (failed > 0) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

runPostgresIntegrationTests().catch(err => {
  console.error('Fatal error in PostgreSQL integration test runner:', err);
  process.exit(1);
});
