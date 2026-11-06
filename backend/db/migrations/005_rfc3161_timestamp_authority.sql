-- SourceMark Schema Migration 005: RFC 3161 Trusted Timestamp Authority Integration
-- Standards Compliance: RFC 3161 (TSP), ISO/IEC 18014, ETSI EN 319 422, NIST SP 800-86

-- 1. Timestamp Tokens Table (Immutable Provenance Temporal Evidence)
CREATE TABLE IF NOT EXISTS timestamp_tokens (
    id VARCHAR(64) PRIMARY KEY,
    source_id VARCHAR(64) REFERENCES sources(id) ON DELETE SET NULL,
    ledger_block_id VARCHAR(64) REFERENCES ledger_blocks(id) ON DELETE SET NULL,
    signing_key_id VARCHAR(64),
    sha256_imprint VARCHAR(64) NOT NULL,
    tsa_provider_url VARCHAR(512),
    tsa_authority VARCHAR(255),
    policy_id VARCHAR(128),
    serial_number VARCHAR(128),
    generation_time TIMESTAMP WITH TIME ZONE NOT NULL,
    nonce VARCHAR(128),
    token_der_base64 TEXT,
    validation_status VARCHAR(64) NOT NULL DEFAULT 'UNVERIFIED',
    validation_details TEXT,
    cert_subject VARCHAR(512),
    cert_issuer VARCHAR(512),
    cert_serial VARCHAR(128),
    cert_expires_at TIMESTAMP WITH TIME ZONE,
    is_simulated BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 2. Add TSA Reference Columns to Sources
ALTER TABLE sources ADD COLUMN IF NOT EXISTS tsa_token_id VARCHAR(64) REFERENCES timestamp_tokens(id) ON DELETE SET NULL;
ALTER TABLE sources ADD COLUMN IF NOT EXISTS tsa_timestamp TIMESTAMP WITH TIME ZONE;
ALTER TABLE sources ADD COLUMN IF NOT EXISTS tsa_status VARCHAR(64) DEFAULT 'UNVERIFIED';
ALTER TABLE sources ADD COLUMN IF NOT EXISTS tsa_authority VARCHAR(255);

-- 3. Add TSA Reference Columns to Ledger Blocks
ALTER TABLE ledger_blocks ADD COLUMN IF NOT EXISTS tsa_token_id VARCHAR(64) REFERENCES timestamp_tokens(id) ON DELETE SET NULL;
ALTER TABLE ledger_blocks ADD COLUMN IF NOT EXISTS tsa_timestamp TIMESTAMP WITH TIME ZONE;

-- 4. Fast Query & Forensic Audit Indexes
CREATE INDEX IF NOT EXISTS idx_timestamp_tokens_source ON timestamp_tokens(source_id);
CREATE INDEX IF NOT EXISTS idx_timestamp_tokens_block ON timestamp_tokens(ledger_block_id);
CREATE INDEX IF NOT EXISTS idx_timestamp_tokens_imprint ON timestamp_tokens(sha256_imprint);
CREATE INDEX IF NOT EXISTS idx_timestamp_tokens_status ON timestamp_tokens(validation_status);
CREATE INDEX IF NOT EXISTS idx_sources_tsa_token ON sources(tsa_token_id);
CREATE INDEX IF NOT EXISTS idx_ledger_blocks_tsa_token ON ledger_blocks(tsa_token_id);

