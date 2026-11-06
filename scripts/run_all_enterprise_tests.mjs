/**
 * Master Enterprise Test Suite Runner
 * Executes all 6 test suites and provides unified scorecard.
 */

import { execSync } from 'node:child_process';

const suites = [
  { name: 'PKI Trust & Investigation Audit', file: 'scripts/test_pki_trust_investigation.mjs', tests: 5 },
  { name: 'Final Security & Private Key Audit', file: 'scripts/test_final_security_audit.mjs', tests: 10 },
  { name: 'Trusted Timestamp Authority Suite', file: 'scripts/test_trusted_timestamp.mjs', tests: 8 },
  { name: '16-Scenario Security Matrix', file: 'scripts/security_validation_16.mjs', tests: 16 },
  { name: 'Comprehensive Functional Audit Suite', file: 'scripts/audit_suite.mjs', tests: 29 },
  { name: 'Enterprise Multi-Role & RBAC Security Suite', file: 'scripts/test_enterprise_multi_role.mjs', tests: 8 },
  { name: 'Server-Side RBAC & Boundary Suite', file: 'scripts/test_server_side_rbac.mjs', tests: 48 },
  { name: 'PostgreSQL Relational Schema & Migration Suite', file: 'scripts/test_postgres_integration.mjs', tests: 27 },
  { name: 'PostgreSQL Application Integration & ACID Suite', file: 'scripts/test_phase4_integration.mjs', tests: 47 },
  { name: 'Enterprise Key Management & KMS/HSM Security Suite', file: 'scripts/test_phase5_kms_security.mjs', tests: 10 },
  { name: 'External Trusted Timestamp Authority Suite (RFC 3161)', file: 'scripts/test_phase6_tsa_integration.mjs', tests: 11 },
  { name: 'Independent WORM Storage & Checkpoint Anchoring (Phase 7)', file: 'scripts/test_phase7_worm_checkpoints.mjs', tests: 12 },
  { name: 'Phase 8 Final Enterprise Security & E2E Audit', file: 'scripts/test_phase8_enterprise_security_audit.mjs', tests: 30 },
];

console.log('================================================================');
console.log('       SOURCEMARK ENTERPRISE MASTER TEST VERIFICATION           ');
console.log('================================================================\n');

let totalTests = 0;
let totalPassed = 0;
let totalFailed = 0;

for (const s of suites) {
  process.stdout.write(`Executing: ${s.name} (${s.file})... `);
  try {
    const out = execSync(`node ${s.file}`, { stdio: 'pipe' }).toString();
    console.log('✓ PASS');
    totalTests += s.tests;
    totalPassed += s.tests;
  } catch (err) {
    console.log('✗ FAIL');
    console.error(err.stdout ? err.stdout.toString() : err.message);
    totalTests += s.tests;
    totalFailed += s.tests;
  }
}

console.log('\n----------------------------------------------------------------');
console.log(`TOTAL SUITES EXECUTED: ${suites.length}`);
console.log(`TOTAL TESTS:           ${totalTests}`);
console.log(`PASSED:                ${totalPassed}`);
console.log(`FAILED:                ${totalFailed}`);
console.log(`SUCCESS RATE:          ${((totalPassed / totalTests) * 100).toFixed(1)}%`);
console.log('================================================================\n');

if (totalFailed > 0) process.exit(1);

