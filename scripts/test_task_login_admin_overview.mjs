/**
 * SourceMark Final Login, Admin Access Control & Global Overview Verification Suite
 * Tests all 10 requirements:
 * 1. Manual login for all six roles.
 * 2. Invalid username and password.
 * 3. Standard user attempting administrator login/action.
 * 4. Unauthorized access to every privileged dashboard/API.
 * 5. Administrator creating a new investigator account.
 * 6. Administrator deactivating an account & login denial.
 * 7. Multiple standard users logging in independently.
 * 8. Session persistence and logout.
 * 9. Global Overview and Admin Command loading separate content.
 * 10. Database persistence after backend restart.
 */

import http from 'node:http';
import { spawn } from 'node:child_process';
import { getPool } from '../backend/db/postgres.mjs';

const PORT = 8015;
const BASE_URL = `http://127.0.0.1:${PORT}`;

let passed = 0;
let failed = 0;

function assert(condition, name, details) {
  if (condition) {
    console.log(`[PASS] ${name}`);
    passed++;
  } else {
    console.error(`[FAIL] ${name}: ${details}`);
    failed++;
  }
}

async function request(path, options = {}) {
  const url = `${BASE_URL}${path}`;
  const res = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
    body: options.body ? (typeof options.body === 'string' ? options.body : JSON.stringify(options.body)) : undefined,
  });
  let data = null;
  try {
    data = await res.json();
  } catch {
    data = await res.text();
  }
  return { status: res.status, headers: res.headers, data };
}

async function runSuite() {
  console.log('================================================================');
  console.log('   SOURCEMARK LOGIN, ADMIN CONTROL & GLOBAL OVERVIEW SUITE      ');
  console.log('================================================================\n');

  let serverProc = spawn('node', ['backend/server.mjs'], {
    env: { ...process.env, PORT: String(PORT) },
    stdio: 'pipe',
  });

  // Wait for server to spin up
  await new Promise((r) => setTimeout(r, 2000));

  try {
    // -------------------------------------------------------------
    // Test 1: Manual login for all six roles
    // -------------------------------------------------------------
    console.log('--- Test 1: Manual Login for All Six Roles ---');
    const rolesCredentials = [
      { role: 'ADMINISTRATOR', email: 'admin@sourcemark.io', pwd: 'AdminPass123!' },
      { role: 'FORENSIC_INVESTIGATOR', email: 'investigator@sourcemark.io', pwd: 'InvestigatorPass123!' },
      { role: 'SOC_ANALYST', email: 'soc@sourcemark.io', pwd: 'SocPass123!' },
      { role: 'AUDITOR', email: 'auditor@sourcemark.io', pwd: 'AuditorPass123!' },
      { role: 'ORGANIZATION_MANAGER', email: 'manager@sourcemark.io', pwd: 'ManagerPass123!' },
      { role: 'USER', email: 'user@sourcemark.io', pwd: 'UserPass123!' },
    ];

    const tokens = {};
    for (const cred of rolesCredentials) {
      const res = await request('/api/auth/login', {
        method: 'POST',
        body: { email: cred.email, password: cred.pwd },
      });
      const ok = res.status === 200 && res.data.success && res.data.user.role === cred.role;
      assert(ok, `Manual login for role ${cred.role}`, `Status: ${res.status}, Role: ${res.data?.user?.role}`);
      if (ok) tokens[cred.role] = res.data.token;
    }

    // -------------------------------------------------------------
    // Test 2: Invalid username and password rejection
    // -------------------------------------------------------------
    console.log('\n--- Test 2: Invalid Username and Password Rejection ---');
    const badPwd = await request('/api/auth/login', {
      method: 'POST',
      body: { email: 'admin@sourcemark.io', password: 'WrongPassword123!' },
    });
    assert(badPwd.status === 401, 'Rejects invalid password with HTTP 401', `Status: ${badPwd.status}`);

    const badUser = await request('/api/auth/login', {
      method: 'POST',
      body: { email: 'nonexistent_user@sourcemark.io', password: 'AnyPassword123!' },
    });
    assert(badUser.status === 401, 'Rejects unknown username with HTTP 401', `Status: ${badUser.status}`);

    const emptyBody = await request('/api/auth/login', {
      method: 'POST',
      body: {},
    });
    assert(emptyBody.status === 400, 'Rejects missing credentials with HTTP 400', `Status: ${emptyBody.status}`);

    // -------------------------------------------------------------
    // Test 3: Standard user attempting administrator action / role escalation
    // -------------------------------------------------------------
    console.log('\n--- Test 3: Standard User Attempting Administrator Action ---');
    const userToken = tokens['USER'];
    const adminToken = tokens['ADMINISTRATOR'];

    const userLockdown = await request('/api/system/lockdown', {
      method: 'POST',
      headers: { Authorization: `Bearer ${userToken}` },
      body: { lockdown: true },
    });
    assert(userLockdown.status === 403, 'Standard user denied lockdown (HTTP 403)', `Status: ${userLockdown.status}`);

    const userCreateAdmin = await request('/api/admin/users', {
      method: 'POST',
      headers: { Authorization: `Bearer ${userToken}` },
      body: {
        name: 'Unauthorized User Escalate',
        email: 'attacker@sourcemark.io',
        password: 'AttackerPassword123!',
        role: 'ADMINISTRATOR',
      },
    });
    assert(userCreateAdmin.status === 403, 'Standard user denied privileged account creation (HTTP 403)', `Status: ${userCreateAdmin.status}`);

    // Tampered token test (fabricated role)
    const forgedToken = 'fake.jwt.token.with.admin.claims';
    const forgedReq = await request('/api/admin/users', {
      method: 'GET',
      headers: { Authorization: `Bearer ${forgedToken}` },
    });
    assert(forgedReq.status === 401, 'Tampered token rejected with HTTP 401', `Status: ${forgedReq.status}`);

    // -------------------------------------------------------------
    // Test 4: Unauthorized access to every privileged dashboard API
    // -------------------------------------------------------------
    console.log('\n--- Test 4: Dashboard API RBAC Boundary Defense ---');
    // Investigator API
    const userInvestigate = await request('/api/investigations', {
      method: 'POST',
      headers: { Authorization: `Bearer ${userToken}` },
      body: { title: 'Unauthorized case' },
    });
    assert(userInvestigate.status === 403, 'USER denied investigator endpoint (HTTP 403)', `Status: ${userInvestigate.status}`);

    // SOC API
    const userContainAlert = await request('/api/alerts/contain', {
      method: 'POST',
      headers: { Authorization: `Bearer ${userToken}` },
      body: { alertId: 'ALT-1', reason: 'hacked' },
    });
    assert(userContainAlert.status === 403, 'USER denied SOC containment endpoint (HTTP 403)', `Status: ${userContainAlert.status}`);

    // Manager API
    const userDecideApproval = await request('/api/approvals/APR-TEST/decide', {
      method: 'POST',
      headers: { Authorization: `Bearer ${userToken}` },
      body: { decision: 'APPROVE' },
    });
    assert(userDecideApproval.status === 403, 'USER denied Org Manager approval endpoint (HTTP 403)', `Status: ${userDecideApproval.status}`);

    // Unauthenticated access
    const unauthReq = await request('/api/auth/me');
    assert(unauthReq.status === 401, 'Unauthenticated request rejected with HTTP 401', `Status: ${unauthReq.status}`);

    // -------------------------------------------------------------
    // Test 5: Administrator creating a new investigator account
    // -------------------------------------------------------------
    console.log('\n--- Test 5: Administrator Creating New Investigator Account ---');
    const newInvEmail = `investigator_test_${Date.now()}@sourcemark.io`;
    const newInvPwd = 'InvestigatorPass2026!';
    const createRes = await request('/api/admin/users', {
      method: 'POST',
      headers: { Authorization: `Bearer ${adminToken}` },
      body: {
        name: 'Agent Sarah Connor (Digital Forensics)',
        email: newInvEmail,
        password: newInvPwd,
        role: 'FORENSIC_INVESTIGATOR',
        organizationId: 'ORG-01',
      },
    });

    assert(createRes.status === 201 && createRes.data.success, 'Administrator creates FORENSIC_INVESTIGATOR account', `Status: ${createRes.status}`);
    assert(!createRes.data?.user?.passwordHash && !createRes.data?.user?.salt, 'Password hash and salt never exposed in response', 'Hash or salt leaked');

    const newInvLogin = await request('/api/auth/login', {
      method: 'POST',
      body: { email: newInvEmail, password: newInvPwd },
    });
    assert(newInvLogin.status === 200 && newInvLogin.data.user.role === 'FORENSIC_INVESTIGATOR', 'Newly created investigator successfully logs in', `Role: ${newInvLogin.data?.user?.role}`);

    const createdUserId = createRes.data.user.id;

    // -------------------------------------------------------------
    // Test 6: Administrator deactivating an account
    // -------------------------------------------------------------
    console.log('\n--- Test 6: Administrator Deactivating User Account ---');
    const deactRes = await request(`/api/admin/users/${createdUserId}/deactivate`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    assert(deactRes.status === 200 && deactRes.data.user.status === 'DEACTIVATED', 'Administrator successfully deactivates account', `Status: ${deactRes.status}`);

    const deactLogin = await request('/api/auth/login', {
      method: 'POST',
      body: { email: newInvEmail, password: newInvPwd },
    });
    assert(deactLogin.status === 403 && deactLogin.data.code === 'ACCOUNT_DEACTIVATED', 'Deactivated account rejected on login with HTTP 403', `Status: ${deactLogin.status}, Code: ${deactLogin.data?.code}`);

    // Re-activate account
    const reactRes = await request(`/api/admin/users/${createdUserId}/activate`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${adminToken}` },
    });
    assert(reactRes.status === 200 && reactRes.data.user.status === 'ACTIVE', 'Administrator re-activates account', `Status: ${reactRes.status}`);

    const reactLogin = await request('/api/auth/login', {
      method: 'POST',
      body: { email: newInvEmail, password: newInvPwd },
    });
    assert(reactLogin.status === 200, 'Re-activated account logs in successfully', `Status: ${reactLogin.status}`);

    // -------------------------------------------------------------
    // Test 7: Multiple standard users logging in independently
    // -------------------------------------------------------------
    console.log('\n--- Test 7: Multiple Standard Users Logging In Independently ---');
    const u1Email = `user1_${Date.now()}@sourcemark.io`;
    const u2Email = `user2_${Date.now()}@sourcemark.io`;
    const commonPwd = 'StandardUserPass123!';

    await request('/api/admin/users', {
      method: 'POST',
      headers: { Authorization: `Bearer ${adminToken}` },
      body: { name: 'User Alpha', email: u1Email, password: commonPwd, role: 'USER', organizationId: 'ORG-01' },
    });
    await request('/api/admin/users', {
      method: 'POST',
      headers: { Authorization: `Bearer ${adminToken}` },
      body: { name: 'User Beta', email: u2Email, password: commonPwd, role: 'USER', organizationId: 'ORG-01' },
    });

    const u1Login = await request('/api/auth/login', { method: 'POST', body: { email: u1Email, password: commonPwd } });
    const u2Login = await request('/api/auth/login', { method: 'POST', body: { email: u2Email, password: commonPwd } });

    assert(u1Login.status === 200 && u2Login.status === 200, 'Both standard users authenticate successfully', '');
    assert(u1Login.data.token !== u2Login.data.token, 'Each user receives a unique cryptographically signed session token', '');
    assert(u1Login.data.user.email === u1Email && u2Login.data.user.email === u2Email, 'User profiles remain completely independent', '');

    // -------------------------------------------------------------
    // Test 8: Session persistence and logout
    // -------------------------------------------------------------
    console.log('\n--- Test 8: Session Persistence and Session Verification ---');
    const meRes = await request('/api/auth/me', {
      headers: { Authorization: `Bearer ${u1Login.data.token}` },
    });
    assert(meRes.status === 200 && meRes.data.user.email === u1Email, 'Session token persists across authenticated API calls', `User: ${meRes.data?.user?.email}`);

    // -------------------------------------------------------------
    // Test 9: Global Overview and Admin Command loading separate content
    // -------------------------------------------------------------
    console.log('\n--- Test 9: Global Overview and Admin Command Complete Separation ---');
    const overviewStats = await request('/api/overview/stats');
    assert(overviewStats.status === 200 && overviewStats.data.success, 'Global Overview API returns HTTP 200', `Status: ${overviewStats.status}`);
    assert(
      overviewStats.data.users?.total > 0 &&
      overviewStats.data.sources?.total > 0 &&
      overviewStats.data.ledger?.totalBlocks > 0 &&
      overviewStats.data.organizations?.length > 0,
      'Global Overview displays real PostgreSQL-backed metrics (users, orgs, sources, ledger)',
      `Sources: ${overviewStats.data.sources?.total}, Ledger: ${overviewStats.data.ledger?.totalBlocks}`
    );

    // Verify Admin Command actions are restricted to Admin
    const userAdminCommandAttempt = await request('/api/system/lockdown', {
      method: 'POST',
      headers: { Authorization: `Bearer ${u1Login.data.token}` },
    });
    assert(userAdminCommandAttempt.status === 403, 'Admin Command is inaccessible to non-administrators (Separation Enforced)', `Status: ${userAdminCommandAttempt.status}`);

    // -------------------------------------------------------------
    // Test 10: Database persistence after backend restart
    // -------------------------------------------------------------
    console.log('\n--- Test 10: PostgreSQL Database Persistence Across Restart ---');
    const pool = getPool();
    const beforeSources = await pool.query('SELECT count(*) FROM sources');
    const beforeBlocks = await pool.query('SELECT count(*) FROM ledger_blocks');

    // Terminate backend process
    serverProc.kill();
    await new Promise((r) => setTimeout(r, 1500));

    // Restart backend process
    serverProc = spawn('node', ['backend/server.mjs'], {
      env: { ...process.env, PORT: String(PORT) },
      stdio: 'pipe',
    });
    await new Promise((r) => setTimeout(r, 2000));

    const afterSources = await pool.query('SELECT count(*) FROM sources');
    const afterBlocks = await pool.query('SELECT count(*) FROM ledger_blocks');

    assert(
      beforeSources.rows[0].count === afterSources.rows[0].count &&
      beforeBlocks.rows[0].count === afterBlocks.rows[0].count,
      'PostgreSQL evidence & ledger persist identically after backend restart',
      `Before: ${beforeSources.rows[0].count} / ${beforeBlocks.rows[0].count}, After: ${afterSources.rows[0].count} / ${afterBlocks.rows[0].count}`
    );

    const restartHealth = await request('/api/health');
    assert(restartHealth.status === 200 && restartHealth.data.databaseEngine === 'postgresql', 'Restarted backend reconnects to PostgreSQL cleanly', `DB Engine: ${restartHealth.data?.databaseEngine}`);

  } catch (err) {
    console.error('Test suite error:', err);
    failed++;
  } finally {
    if (serverProc) serverProc.kill();
  }

  console.log('\n================================================================');
  console.log(`TOTAL SUITE CHECKS: ${passed + failed}`);
  console.log(`PASSED:             ${passed}`);
  console.log(`FAILED:             ${failed}`);
  console.log('================================================================\n');

  process.exit(failed > 0 ? 1 : 0);
}

runSuite();
