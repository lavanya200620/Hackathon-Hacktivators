/**
 * SourceMark Server-Side RBAC & Security Boundary Test Suite
 * Rigorously tests:
 * 1. HTTP 401 for unauthenticated requests on every sensitive endpoint.
 * 2. HTTP 403 for unauthorized roles on every restricted endpoint (negative testing for all 6 roles).
 * 3. Organization-level data isolation (cross-organization denial for managers).
 * 4. Request payload manipulation & privilege escalation defense (forcing role USER on public registration).
 * 5. Emergency system lockdown enforcement.
 * 6. Audit logging with sensitive credential redaction.
 */

import { EventEmitter } from 'node:events';
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
      req.emit('data', JSON.stringify(body));
    }
    req.emit('end');
  });
}

// Generate valid session tokens for each role
const adminToken = createSessionToken({
  id: 'USR-ADMIN-01',
  email: 'admin@sourcemark.io',
  role: ROLES.ADMINISTRATOR,
  organizationId: 'ORG-01',
});

const invToken = createSessionToken({
  id: 'USR-INV-01',
  email: 'investigator@sourcemark.io',
  role: ROLES.FORENSIC_INVESTIGATOR,
  organizationId: 'ORG-01',
});

const socToken = createSessionToken({
  id: 'USR-SOC-01',
  email: 'soc@sourcemark.io',
  role: ROLES.SOC_ANALYST,
  organizationId: 'ORG-02',
});

const audToken = createSessionToken({
  id: 'USR-AUD-01',
  email: 'auditor@sourcemark.io',
  role: ROLES.AUDITOR,
  organizationId: 'ORG-03',
});

const mgr1Token = createSessionToken({
  id: 'USR-MGR-01',
  email: 'manager@sourcemark.io',
  role: ROLES.ORGANIZATION_MANAGER,
  organizationId: 'ORG-01',
});

const mgr2Token = createSessionToken({
  id: 'USR-MGR-02',
  email: 'manager2@sourcemark.io',
  role: ROLES.ORGANIZATION_MANAGER,
  organizationId: 'ORG-02',
});

const usrToken = createSessionToken({
  id: 'USR-CUSTODIAN-01',
  email: 'user@sourcemark.io',
  role: ROLES.USER,
  organizationId: 'ORG-01',
});

console.log('================================================================');
console.log('    SOURCEMARK COMPLETE SERVER-SIDE RBAC & BOUNDARY SUITE       ');
console.log('================================================================\n');

async function runTests() {
  // ----------------------------------------------------
  // Section 1: Unauthenticated Access Rejection (HTTP 401)
  // ----------------------------------------------------
  console.log('--- SECTION 1: Unauthenticated Rejections (HTTP 401) ---');

  const unauthEndpoints = [
    { method: 'GET', url: '/api/auth/me', name: 'Identity inspection' },
    { method: 'GET', url: '/api/auth/users', name: 'User governance directory' },
    { method: 'POST', url: '/api/keys/revoke', name: 'Emergency key revocation' },
    { method: 'POST', url: '/api/system/lockdown', name: 'System lockdown toggle' },
    { method: 'GET', url: '/api/investigations', name: 'Investigation case queue' },
    { method: 'POST', url: '/api/investigations', name: 'Investigation case creation' },
    { method: 'GET', url: '/api/alerts', name: 'SOC security alert feed' },
    { method: 'POST', url: '/api/alerts/contain', name: 'Threat containment execution' },
    { method: 'GET', url: '/api/approvals', name: 'Approval queue inspection' },
    { method: 'POST', url: '/api/approvals', name: 'Approval request creation' },
    { method: 'POST', url: '/api/approvals/APR-501/decide', name: 'Approval decision' },
    { method: 'GET', url: '/api/audit-events', name: 'Audit event ledger' },
    { method: 'GET', url: '/api/audit/compliance-export', name: 'Compliance report export' },
    { method: 'POST', url: '/api/register', name: 'Source file registration' },
  ];

  for (const ep of unauthEndpoints) {
    const res = await makeRequest({ method: ep.method, url: ep.url, headers: {} });
    const is401 = res.statusCode === 401 && res.body?.code === 'UNAUTHENTICATED';
    report(
      `Unauthenticated ${ep.method} ${ep.url} (${ep.name})`,
      'HTTP 401 UNAUTHENTICATED',
      `HTTP ${res.statusCode} ${res.body?.code || ''}`,
      'Protected endpoint strictly rejects anonymous calls.',
      is401
    );
  }

  // ----------------------------------------------------
  // Section 2: Negative Role Boundary Tests (HTTP 403)
  // ----------------------------------------------------
  console.log('--- SECTION 2: Role Boundary Negative Tests (HTTP 403) ---');

  // USER role negative tests
  const userViolations = [
    { method: 'POST', url: '/api/keys/revoke', body: { keyId: 'ED-TEST' }, name: 'Key revocation' },
    { method: 'POST', url: '/api/system/lockdown', body: { lockdown: true }, name: 'System lockdown' },
    { method: 'GET', url: '/api/auth/users', body: null, name: 'User governance read' },
    { method: 'PATCH', url: '/api/auth/users/USR-ADMIN-01', body: { role: 'ADMINISTRATOR' }, name: 'User role edit' },
    { method: 'POST', url: '/api/investigations', body: { title: 'Unauthorized case' }, name: 'Investigation case creation' },
    { method: 'POST', url: '/api/alerts/contain', body: { alertId: 'ALT-8842' }, name: 'SOC containment' },
    { method: 'POST', url: '/api/approvals/APR-501/decide', body: { decision: 'APPROVE' }, name: 'Approval decision' },
    { method: 'GET', url: '/api/audit/compliance-export', body: null, name: 'Compliance export' },
  ];

  for (const v of userViolations) {
    const res = await makeRequest({
      method: v.method,
      url: v.url,
      headers: { authorization: `Bearer ${usrToken}` },
      body: v.body,
    });
    const is403 = res.statusCode === 403;
    report(
      `USER Role Denied: ${v.method} ${v.url} (${v.name})`,
      'HTTP 403 FORBIDDEN',
      `HTTP ${res.statusCode} (${res.body?.code || res.body?.error || ''})`,
      'Standard USER is strictly blocked from executing administrative or governance actions.',
      is403
    );
  }

  // FORENSIC_INVESTIGATOR negative tests
  const invViolations = [
    { method: 'POST', url: '/api/keys/revoke', body: { keyId: 'ED-TEST' }, name: 'Key revocation' },
    { method: 'POST', url: '/api/system/lockdown', body: { lockdown: true }, name: 'System lockdown' },
    { method: 'GET', url: '/api/auth/users', body: null, name: 'User governance read' },
    { method: 'POST', url: '/api/alerts/contain', body: { alertId: 'ALT-8842' }, name: 'SOC containment' },
    { method: 'POST', url: '/api/approvals/APR-501/decide', body: { decision: 'APPROVE' }, name: 'Approval decision' },
  ];

  for (const v of invViolations) {
    const res = await makeRequest({
      method: v.method,
      url: v.url,
      headers: { authorization: `Bearer ${invToken}` },
      body: v.body,
    });
    const is403 = res.statusCode === 403;
    report(
      `FORENSIC_INVESTIGATOR Denied: ${v.method} ${v.url} (${v.name})`,
      'HTTP 403 FORBIDDEN',
      `HTTP ${res.statusCode} (${res.body?.code || ''})`,
      'Examiner is restricted from administrative controls and managerial approvals.',
      is403
    );
  }

  // SOC_ANALYST negative tests
  const socViolations = [
    { method: 'POST', url: '/api/keys/revoke', body: { keyId: 'ED-TEST' }, name: 'Key revocation' },
    { method: 'POST', url: '/api/system/lockdown', body: { lockdown: true }, name: 'System lockdown' },
    { method: 'GET', url: '/api/auth/users', body: null, name: 'User governance read' },
    { method: 'POST', url: '/api/investigations', body: { title: 'Case by SOC' }, name: 'Investigation case creation' },
    { method: 'POST', url: '/api/approvals/APR-501/decide', body: { decision: 'APPROVE' }, name: 'Approval decision' },
  ];

  for (const v of socViolations) {
    const res = await makeRequest({
      method: v.method,
      url: v.url,
      headers: { authorization: `Bearer ${socToken}` },
      body: v.body,
    });
    const is403 = res.statusCode === 403;
    report(
      `SOC_ANALYST Denied: ${v.method} ${v.url} (${v.name})`,
      'HTTP 403 FORBIDDEN',
      `HTTP ${res.statusCode} (${res.body?.code || ''})`,
      'SOC analyst can contain alerts, but cannot revoke root keys or approve derivative workflows.',
      is403
    );
  }

  // AUDITOR negative tests
  const audViolations = [
    { method: 'POST', url: '/api/keys/revoke', body: { keyId: 'ED-TEST' }, name: 'Key revocation' },
    { method: 'POST', url: '/api/system/lockdown', body: { lockdown: true }, name: 'System lockdown' },
    { method: 'POST', url: '/api/register', body: { fileName: 'test.dat', fileSize: 100, sha256: 'abc' }, name: 'Source registration' },
    { method: 'POST', url: '/api/investigations', body: { title: 'Case by Auditor' }, name: 'Investigation case creation' },
    { method: 'POST', url: '/api/alerts/contain', body: { alertId: 'ALT-8842' }, name: 'SOC containment' },
    { method: 'POST', url: '/api/approvals/APR-501/decide', body: { decision: 'APPROVE' }, name: 'Approval decision' },
  ];

  for (const v of audViolations) {
    const res = await makeRequest({
      method: v.method,
      url: v.url,
      headers: { authorization: `Bearer ${audToken}` },
      body: v.body,
    });
    const is403 = res.statusCode === 403;
    report(
      `AUDITOR Denied: ${v.method} ${v.url} (${v.name})`,
      'HTTP 403 FORBIDDEN',
      `HTTP ${res.statusCode} (${res.body?.code || ''})`,
      'Auditor is an observer and compliance exporter; cannot modify source records or decide approvals.',
      is403
    );
  }

  // ORGANIZATION_MANAGER negative tests
  const mgrViolations = [
    { method: 'POST', url: '/api/keys/revoke', body: { keyId: 'ED-TEST' }, name: 'Key revocation' },
    { method: 'POST', url: '/api/system/lockdown', body: { lockdown: true }, name: 'System lockdown' },
    { method: 'GET', url: '/api/auth/users', body: null, name: 'User governance read' },
    { method: 'POST', url: '/api/investigations', body: { title: 'Case by Manager' }, name: 'Investigation case creation' },
    { method: 'POST', url: '/api/alerts/contain', body: { alertId: 'ALT-8842' }, name: 'SOC containment' },
  ];

  for (const v of mgrViolations) {
    const res = await makeRequest({
      method: v.method,
      url: v.url,
      headers: { authorization: `Bearer ${mgr1Token}` },
      body: v.body,
    });
    const is403 = res.statusCode === 403;
    report(
      `ORGANIZATION_MANAGER Denied: ${v.method} ${v.url} (${v.name})`,
      'HTTP 403 FORBIDDEN',
      `HTTP ${res.statusCode} (${res.body?.code || ''})`,
      'Organization Manager is restricted to team governance and derivative approvals.',
      is403
    );
  }

  // ----------------------------------------------------
  // Section 3: Organization-Level Data Isolation
  // ----------------------------------------------------
  console.log('--- SECTION 3: Organization-Level Data Isolation ---');

  // Ensure test approvals exist in db
  const apr501 = db.data.approvals.find(a => a.id === 'APR-501');
  if (apr501) apr501.organizationId = 'ORG-01';
  if (!db.data.approvals.some(a => a.id === 'APR-503')) {
    db.data.approvals.push({
      id: 'APR-503',
      title: 'Threat Intel Feed Export Authorization',
      sourceId: 'SRC-SOC-LOG',
      organizationId: 'ORG-02',
      status: 'PENDING',
    });
  }

  // Manager 1 (ORG-01) attempting to decide approval belonging to ORG-02 (APR-503)
  const crossOrgRes = await makeRequest({
    method: 'POST',
    url: '/api/approvals/APR-503/decide',
    headers: { authorization: `Bearer ${mgr1Token}` },
    body: { decision: 'APPROVE', reason: 'Cross-org attempt' },
  });
  const crossOrgDenied = crossOrgRes.statusCode === 403 && crossOrgRes.body?.code === 'CROSS_ORG_ACCESS_DENIED';
  report(
    'Cross-Organization Approval Decision Boundary',
    'HTTP 403 CROSS_ORG_ACCESS_DENIED',
    `HTTP ${crossOrgRes.statusCode} (${crossOrgRes.body?.code || ''})`,
    'Manager of ORG-01 cannot decide approval requests originating from ORG-02.',
    crossOrgDenied
  );

  // Manager 1 (ORG-01) deciding approval belonging to their own organization (APR-501)
  const ownOrgRes = await makeRequest({
    method: 'POST',
    url: '/api/approvals/APR-501/decide',
    headers: { authorization: `Bearer ${mgr1Token}` },
    body: { decision: 'APPROVE', reason: 'Approved by authorized department lead' },
  });
  const ownOrgAllowed = ownOrgRes.statusCode === 200 && ownOrgRes.body?.approval?.status === 'APPROVED';
  report(
    'Same-Organization Approval Decision Authorized',
    'HTTP 200 APPROVED',
    `HTTP ${ownOrgRes.statusCode} (${ownOrgRes.body?.approval?.status || ''})`,
    'Manager can successfully decide requests within their assigned department.',
    ownOrgAllowed
  );

  // ----------------------------------------------------
  // Section 4: Payload Manipulation & Privilege Escalation Defense
  // ----------------------------------------------------
  console.log('--- SECTION 4: Payload Manipulation & Privilege Escalation Defense ---');

  // Attempt to self-register with role 'ADMINISTRATOR' without being an admin
  const spoofedReg = await makeRequest({
    method: 'POST',
    url: '/api/auth/register',
    headers: {},
    body: {
      name: 'Malicious Actor',
      email: `attacker-${Date.now()}@example.com`,
      password: 'HackerPassword123!',
      role: 'ADMINISTRATOR',
      organizationId: 'ORG-ROOT',
    },
  });
  const isRoleForcedToUser = spoofedReg.statusCode === 201 && spoofedReg.body?.user?.role === 'USER';
  report(
    'Public Registration Role Spoofing Defense',
    'Role forced to USER (HTTP 201)',
    `Created role: ${spoofedReg.body?.user?.role}`,
    'Public register payload role: ADMINISTRATOR is sanitized and forced to standard USER.',
    isRoleForcedToUser
  );

  // ----------------------------------------------------
  // Section 5: Emergency Lockdown Enforcement
  // ----------------------------------------------------
  console.log('--- SECTION 5: Emergency System Lockdown Enforcement ---');

  // Admin engages emergency lockdown
  const engageLockdown = await makeRequest({
    method: 'POST',
    url: '/api/system/lockdown',
    headers: { authorization: `Bearer ${adminToken}` },
    body: { lockdown: true, reason: 'Active cryptographic threat detection' },
  });
  const lockdownEngaged = engageLockdown.statusCode === 200 && engageLockdown.body?.lockdown === true;

  // Standard user attempts registration during lockdown -> rejected with 403 SYSTEM_LOCKDOWN
  const regDuringLockdown = await makeRequest({
    method: 'POST',
    url: '/api/register',
    headers: { authorization: `Bearer ${usrToken}` },
    body: {
      fileName: 'lockdown_test.png',
      fileSize: 1024,
      sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    },
  });
  const lockdownBlocked = regDuringLockdown.statusCode === 403 && regDuringLockdown.body?.code === 'SYSTEM_LOCKDOWN';
  report(
    'Registration Blocked During Emergency Lockdown',
    'HTTP 403 SYSTEM_LOCKDOWN',
    `HTTP ${regDuringLockdown.statusCode} (${regDuringLockdown.body?.code || ''})`,
    'Write operations are gated when administrative emergency lockdown is engaged.',
    lockdownEngaged && lockdownBlocked
  );

  // Admin disengages lockdown
  await makeRequest({
    method: 'POST',
    url: '/api/system/lockdown',
    headers: { authorization: `Bearer ${adminToken}` },
    body: { lockdown: false },
  });

  // ----------------------------------------------------
  // Section 6: Audit Logging Sanitization (No Leaked Secrets)
  // ----------------------------------------------------
  console.log('--- SECTION 6: Audit Logging Credential Redaction ---');

  const auditEvents = db.data.auditLogs;
  let hasPasswordLeak = false;
  let hasTokenLeak = false;

  for (const log of auditEvents) {
    const str = JSON.stringify(log);
    if (/password\s*:\s*"(?!\[REDACTED\])[^"]+"/i.test(str)) hasPasswordLeak = true;
    if (/Bearer\s+[A-Za-z0-9_-]{20,}/.test(str)) hasTokenLeak = true;
  }

  report(
    'Security Audit Log Credential Redaction Check',
    'hasPasswordLeak: false, hasTokenLeak: false',
    `hasPasswordLeak: ${hasPasswordLeak}, hasTokenLeak: ${hasTokenLeak}`,
    'Audit logs record actions and denied attempts without leaking plaintext passwords or session tokens.',
    !hasPasswordLeak && !hasTokenLeak
  );

  // ----------------------------------------------------
  // Summary
  // ----------------------------------------------------
  console.log('----------------------------------------------------------------');
  console.log(`TOTAL SERVER-SIDE RBAC TESTS: ${passed + failed}`);
  console.log(`PASSED: ${passed}`);
  console.log(`FAILED: ${failed}`);
  console.log(`STATUS: ${failed === 0 ? 'ALL SERVER-SIDE RBAC BOUNDARIES ENFORCED (100%)' : 'VIOLATIONS DETECTED'}`);
  console.log('================================================================\n');

  if (failed > 0) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

runTests();
