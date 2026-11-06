-- Migration 002: Seed Initial Enterprise Roles, Permissions, and Default Organizations

-- Insert Organizations
INSERT INTO organizations (id, name, department) VALUES
('ORG-01', 'Federal Geointelligence Agency', 'Orbital Reconnaissance'),
('ORG-02', 'Cyber Defense Operations', 'Incident Response'),
('ORG-03', 'Global Audit & Forensics Corp', 'Digital Compliance')
ON CONFLICT (id) DO NOTHING;

-- Insert Roles
INSERT INTO roles (name, description) VALUES
('ADMINISTRATOR', 'Full enterprise security, system lockdown, key revocation, and user administration'),
('FORENSIC_INVESTIGATOR', 'Lead forensic inspection, deep file analysis, and investigation case management'),
('SOC_ANALYST', 'Real-time security monitoring, threat containment, and credential quarantine'),
('AUDITOR', 'Immutable audit log scrutiny, non-repudiation verification, and compliance report generation'),
('ORGANIZATION_MANAGER', 'Department asset custody, contributor authorization, and derivative approvals'),
('USER', 'Digital content registration, Ed25519 signature creation, and verification')
ON CONFLICT (name) DO NOTHING;

-- Insert Permissions
INSERT INTO permissions (name, description) VALUES
('users:read', 'Read enterprise user directory'),
('users:write', 'Create, update, or assign roles to users'),
('users:delete', 'Deactivate or delete users'),
('roles:assign', 'Assign roles to users'),
('system:lockdown', 'Engage or disengage emergency system lockdown'),
('keys:revoke', 'Administratively revoke cryptographic signing keys'),
('keys:approve', 'Approve keys in PKI Trust Registry'),
('keys:inspect', 'Inspect public key details and statuses'),
('keys:quarantine', 'Quarantine compromised credentials in SOC'),
('keys:view_own', 'View personal signing keys'),
('ledger:read', 'Read blockchain ledger blocks'),
('ledger:verify', 'Cryptographically verify ledger Merkle links'),
('ledger:rollback', 'Detect and repair ledger rollbacks'),
('sources:read', 'Read registered source provenance records'),
('sources:write', 'Update source metadata'),
('sources:register', 'Register and sign new digital sources'),
('sources:verify', 'Run cryptographic verification on file hashes'),
('investigations:read', 'View forensic investigation cases'),
('investigations:write', 'Create and add examiner notes to investigation cases'),
('investigations:close', 'Resolve and close forensic cases'),
('evidence:export', 'Export chain of custody forensic evidence packages'),
('alerts:read', 'Read SOC security threat alerts'),
('alerts:contain', 'Execute containment and quarantine threats'),
('alerts:dismiss', 'Dismiss verified false-positive alerts'),
('approvals:read', 'View derivative approval requests'),
('approvals:decide', 'Approve or reject derivative transformation requests'),
('approvals:request', 'Submit derivative authorization requests'),
('team:read', 'View department team members and assets'),
('team:manage', 'Manage department team members'),
('audit:read', 'Inspect immutable audit logs'),
('audit:export', 'Export compliance packages'),
('compliance:generate', 'Generate NIST/ISO compliance certificates'),
('system:status', 'View system telemetry and health status')
ON CONFLICT (name) DO NOTHING;

