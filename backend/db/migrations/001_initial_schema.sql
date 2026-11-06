-- Migration 001: Initial Relational Schema for SourceMark Enterprise Provenance Engine
-- Creates all normalized tables, foreign keys, unique constraints, and indexes.

CREATE TABLE IF NOT EXISTS schema_migrations (
    version VARCHAR(64) PRIMARY KEY,
    applied_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS organizations (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    department VARCHAR(255),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS roles (
    name VARCHAR(64) PRIMARY KEY,
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS permissions (
    name VARCHAR(64) PRIMARY KEY,
    description TEXT
);

CREATE TABLE IF NOT EXISTS role_permissions (
    role_name VARCHAR(64) REFERENCES roles(name) ON DELETE CASCADE,
    permission_name VARCHAR(64) REFERENCES permissions(name) ON DELETE CASCADE,
    PRIMARY KEY (role_name, permission_name)
);

CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    role VARCHAR(64) REFERENCES roles(name),
    organization_id VARCHAR(64) REFERENCES organizations(id),
    salt VARCHAR(128) NOT NULL,
    password_hash VARCHAR(256) NOT NULL,
    status VARCHAR(32) DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'SUSPENDED', 'DEACTIVATED')),
    mfa_enabled BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sessions (
    id VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(64) REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(256) NOT NULL,
    ip_address VARCHAR(64),
    user_agent TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS signing_keys (
    key_id VARCHAR(64) PRIMARY KEY,
    public_key_hex VARCHAR(128) UNIQUE NOT NULL,
    owner_id VARCHAR(64) REFERENCES users(id),
    owner_name VARCHAR(255),
    organization_id VARCHAR(64) REFERENCES organizations(id),
    status VARCHAR(32) DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'REVOKED', 'COMPROMISED', 'ROTATED')),
    compromised_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    revocation_reason TEXT,
    replacement_key_id VARCHAR(64),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sources (
    id VARCHAR(64) PRIMARY KEY,
    file_name VARCHAR(512) NOT NULL,
    file_type VARCHAR(128) DEFAULT 'application/octet-stream',
    file_size BIGINT NOT NULL CHECK (file_size >= 0),
    file_size_formatted VARCHAR(32),
    sha256 VARCHAR(64) NOT NULL,
    signature TEXT NOT NULL,
    key_id VARCHAR(64) REFERENCES signing_keys(key_id),
    public_key VARCHAR(128) NOT NULL,
    creator_id VARCHAR(64) REFERENCES users(id),
    creator_email VARCHAR(255),
    organization_id VARCHAR(64) REFERENCES organizations(id),
    category VARCHAR(128) DEFAULT 'General',
    description TEXT,
    source_origin TEXT,
    status VARCHAR(64) DEFAULT 'ACTIVE_REGISTERED',
    verification_count INT DEFAULT 0 CHECK (verification_count >= 0),
    last_verified_at TIMESTAMPTZ,
    registered_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS file_versions (
    version_id VARCHAR(64) PRIMARY KEY,
    source_id VARCHAR(64) REFERENCES sources(id) ON DELETE CASCADE,
    version_number INT NOT NULL,
    file_name VARCHAR(512) NOT NULL,
    sha256 VARCHAR(64) NOT NULL,
    signature TEXT,
    transformation_reason TEXT,
    custodian_approval_token TEXT,
    status VARCHAR(32) DEFAULT 'AUTHORIZED' CHECK (status IN ('AUTHORIZED', 'UNAUTHORIZED', 'PENDING')),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ledger_blocks (
    id VARCHAR(64) PRIMARY KEY,
    block_number INT UNIQUE NOT NULL CHECK (block_number >= 1),
    type VARCHAR(64) NOT NULL,
    title VARCHAR(512) NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    prev_hash VARCHAR(64) NOT NULL,
    current_hash VARCHAR(64) NOT NULL,
    status VARCHAR(32) DEFAULT 'CONFIRMED',
    verified BOOLEAN DEFAULT TRUE,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS checkpoints (
    id VARCHAR(64) PRIMARY KEY,
    checkpoint_hash VARCHAR(64) NOT NULL,
    block_height INT NOT NULL,
    authority_name VARCHAR(255) NOT NULL,
    authority_signature TEXT NOT NULL,
    merkle_root VARCHAR(64) NOT NULL,
    is_production_grade BOOLEAN DEFAULT FALSE,
    timestamp TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS investigations (
    id VARCHAR(64) PRIMARY KEY,
    title VARCHAR(512) NOT NULL,
    source_id VARCHAR(64),
    organization_id VARCHAR(64) REFERENCES organizations(id),
    severity VARCHAR(32) DEFAULT 'MEDIUM' CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    status VARCHAR(32) DEFAULT 'UNDER_INVESTIGATION' CHECK (status IN ('UNDER_INVESTIGATION', 'AWAITING_EVIDENCE', 'RESOLVED', 'CLOSED')),
    assigned_to VARCHAR(64) REFERENCES users(id),
    assigned_to_name VARCHAR(255),
    created_by VARCHAR(64) REFERENCES users(id),
    created_by_name VARCHAR(255),
    evidence_hash VARCHAR(64),
    altered_hash VARCHAR(64),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS investigation_notes (
    id SERIAL PRIMARY KEY,
    case_id VARCHAR(64) REFERENCES investigations(id) ON DELETE CASCADE,
    author VARCHAR(255) NOT NULL,
    text TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS soc_alerts (
    id VARCHAR(64) PRIMARY KEY,
    title VARCHAR(512) NOT NULL,
    severity VARCHAR(32) NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    source_id VARCHAR(64),
    organization_id VARCHAR(64) REFERENCES organizations(id),
    status VARCHAR(32) DEFAULT 'NEW' CHECK (status IN ('NEW', 'ACTIVE', 'CONTAINED', 'DISMISSED')),
    type VARCHAR(64) NOT NULL,
    description TEXT,
    contained BOOLEAN DEFAULT FALSE,
    contained_at TIMESTAMPTZ,
    contained_by VARCHAR(255),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS derivative_approvals (
    id VARCHAR(64) PRIMARY KEY,
    title VARCHAR(512) NOT NULL,
    source_id VARCHAR(64),
    organization_id VARCHAR(64) REFERENCES organizations(id),
    requested_by VARCHAR(64) REFERENCES users(id),
    requested_by_name VARCHAR(255),
    status VARCHAR(32) DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED')),
    department VARCHAR(255),
    reason TEXT,
    decided_by VARCHAR(255),
    decided_at TIMESTAMPTZ,
    decision_reason TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id VARCHAR(64) PRIMARY KEY,
    action VARCHAR(128) NOT NULL,
    actor VARCHAR(255) NOT NULL,
    role VARCHAR(64) NOT NULL,
    details TEXT,
    ip_address VARCHAR(64),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS system_state (
    key VARCHAR(64) PRIMARY KEY,
    value JSONB NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sources_sha256 ON sources(sha256);
CREATE INDEX IF NOT EXISTS idx_sources_org ON sources(organization_id);
CREATE INDEX IF NOT EXISTS idx_ledger_blocks_num ON ledger_blocks(block_number);
CREATE INDEX IF NOT EXISTS idx_investigations_org ON investigations(organization_id);
CREATE INDEX IF NOT EXISTS idx_approvals_org ON derivative_approvals(organization_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);

