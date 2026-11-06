import { keySecurityService } from '../src/services/keySecurity.js';
import { ledgerStorage } from '../src/services/ledgerStorage.js';
import { workflowService } from '../src/services/workflowService.js';
import { authService, DEFAULT_ACCOUNTS, ENTERPRISE_ROLES } from '../src/services/authService.js';

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

console.log('================================================================');
console.log('   SOURCEMARK RUNTIME RENDER READINESS VERIFICATION            ');
console.log('================================================================\n');

// 1. Check getTrustedRegistry() method and return value
assert(
  typeof keySecurityService.getTrustedRegistry === 'function',
  'keySecurityService.getTrustedRegistry is defined',
  'Method missing on keySecurityService'
);

const trustedKeys = keySecurityService.getTrustedRegistry();
assert(
  Array.isArray(trustedKeys) && trustedKeys.length > 0,
  'keySecurityService.getTrustedRegistry() returns key array',
  `Returned: ${typeof trustedKeys}`
);

// 2. Check getKeys() equivalence
const keys = keySecurityService.getKeys();
assert(
  Array.isArray(keys) && keys.length === trustedKeys.length,
  'keySecurityService.getKeys() returns matching key count',
  `keys.length = ${keys.length}, trustedKeys.length = ${trustedKeys.length}`
);

// 3. Check ledgerStorage methods called on AdminDashboard mount
const blocks = ledgerStorage.getLedgerBlocks();
const sources = ledgerStorage.getSources();
assert(Array.isArray(blocks), 'ledgerStorage.getLedgerBlocks() returns array', `Returned: ${typeof blocks}`);
assert(Array.isArray(sources), 'ledgerStorage.getSources() returns array', `Returned: ${typeof sources}`);

// 4. Initial auth state (Unauthenticated -> Login page)
authService.logout();
assert(
  authService.getCurrentUser() === null,
  'Initial session is null (Unauthenticated visitors see Login screen)',
  `authService.getCurrentUser() = ${JSON.stringify(authService.getCurrentUser())}`
);
assert(
  authService.isAuthenticated() === false,
  'authService.isAuthenticated() is false before login',
  'Should be false'
);

// 5. Test login and dashboard service readiness for all six roles
for (const acc of DEFAULT_ACCOUNTS) {
  await authService.login(acc.email, acc.password);
  const currentUser = authService.getCurrentUser();
  assert(
    currentUser && currentUser.role === acc.role,
    `Login for ${acc.role} succeeds with correct clearance`,
    `Role: ${currentUser?.role}`
  );

  // Role-specific runtime checks
  if (acc.role === ENTERPRISE_ROLES.ADMINISTRATOR) {
    const adminKeys = keySecurityService.getTrustedRegistry();
    assert(Array.isArray(adminKeys), 'Admin Dashboard: keySecurityService.getTrustedRegistry() succeeds', '');
  } else if (acc.role === ENTERPRISE_ROLES.FORENSIC_INVESTIGATOR) {
    const cases = await workflowService.getCases();
    assert(Array.isArray(cases), 'Investigator Dashboard: workflowService.getCases() succeeds', '');
  } else if (acc.role === ENTERPRISE_ROLES.SOC_ANALYST) {
    const alerts = await workflowService.getAlerts();
    assert(Array.isArray(alerts), 'SOC Dashboard: workflowService.getAlerts() succeeds', '');
  } else if (acc.role === ENTERPRISE_ROLES.AUDITOR) {
    const chainValidation = ledgerStorage.validateLedgerChain();
    assert(typeof chainValidation === 'object', 'Auditor Dashboard: ledgerStorage.validateLedgerChain() succeeds', '');
  } else if (acc.role === ENTERPRISE_ROLES.ORGANIZATION_MANAGER) {
    const approvals = await workflowService.getApprovals();
    assert(Array.isArray(approvals), 'Org Manager Dashboard: workflowService.getApprovals() succeeds', '');
  } else if (acc.role === ENTERPRISE_ROLES.USER) {
    const userSrcs = ledgerStorage.getSources();
    assert(Array.isArray(userSrcs), 'User Dashboard: ledgerStorage.getSources() succeeds', '');
  }
}

// Reset auth to clean state
authService.logout();

console.log('\n================================================================');
console.log(`TOTAL READINESS CHECKS: ${passed + failed}`);
console.log(`PASSED:                 ${passed}`);
console.log(`FAILED:                 ${failed}`);
console.log('================================================================\n');

if (failed > 0) process.exit(1);
