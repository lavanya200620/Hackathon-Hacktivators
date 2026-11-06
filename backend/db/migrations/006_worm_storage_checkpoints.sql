-- SourceMark Schema Migration 006: Independent WORM Storage & Checkpoint Anchoring
-- Standards Compliance: SEC Rule 17a-4(f), FINRA Rule 4511(c), ISO/IEC 27037:2012, NIST SP 800-86

-- 1. Extend Checkpoints Table for KMS Signature & Independent WORM Anchor Linkage
ALTER TABLE checkpoints ADD COLUMN IF NOT EXISTS authority_key_id VARCHAR(64);
ALTER TABLE checkpoints ADD COLUMN IF NOT EXISTS prev_checkpoint_id VARCHAR(64);
ALTER TABLE checkpoints ADD COLUMN IF NOT EXISTS prev_checkpoint_hash VARCHAR(64);
ALTER TABLE checkpoints ADD COLUMN IF NOT EXISTS total_blocks INT DEFAULT 0;
ALTER TABLE checkpoints ADD COLUMN IF NOT EXISTS canonical_payload TEXT;
ALTER TABLE checkpoints ADD COLUMN IF NOT EXISTS worm_storage_id VARCHAR(128);
ALTER TABLE checkpoints ADD COLUMN IF NOT EXISTS worm_status VARCHAR(64) DEFAULT 'UNCONFIGURED';
ALTER TABLE checkpoints ADD COLUMN IF NOT EXISTS worm_vault_path VARCHAR(512);
ALTER TABLE checkpoints ADD COLUMN IF NOT EXISTS worm_retention_until TIMESTAMP WITH TIME ZONE;
ALTER TABLE checkpoints ADD COLUMN IF NOT EXISTS tsa_token_id VARCHAR(64) REFERENCES timestamp_tokens(id) ON DELETE SET NULL;
ALTER TABLE checkpoints ADD COLUMN IF NOT EXISTS verification_status VARCHAR(64) DEFAULT 'VALID';
ALTER TABLE checkpoints ADD COLUMN IF NOT EXISTS last_verified_at TIMESTAMP WITH TIME ZONE;

-- 2. Checkpoint Continuous Verification & Rollback Incident Log
CREATE TABLE IF NOT EXISTS checkpoint_verifications (
    id VARCHAR(64) PRIMARY KEY,
    checkpoint_id VARCHAR(64) REFERENCES checkpoints(id) ON DELETE CASCADE,
    verifier VARCHAR(255) NOT NULL,
    status VARCHAR(64) NOT NULL, -- VALID, ROLLBACK_DETECTED, TAMPER_DETECTED, BROKEN_CHAIN
    expected_hash VARCHAR(64),
    actual_hash VARCHAR(64),
    expected_height INT,
    actual_height INT,
    divergence_type VARCHAR(64),
    details TEXT,
    is_worm_consistent BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 3. Indexes for Audit Trails and Fast Forensic Verification
CREATE INDEX IF NOT EXISTS idx_checkpoints_hash ON checkpoints(checkpoint_hash);
CREATE INDEX IF NOT EXISTS idx_checkpoints_height ON checkpoints(block_height);
CREATE INDEX IF NOT EXISTS idx_checkpoints_worm_status ON checkpoints(worm_status);
CREATE INDEX IF NOT EXISTS idx_checkpoints_tsa_token ON checkpoints(tsa_token_id);
CREATE INDEX IF NOT EXISTS idx_checkpoint_verifications_chk ON checkpoint_verifications(checkpoint_id);
CREATE INDEX IF NOT EXISTS idx_checkpoint_verifications_status ON checkpoint_verifications(status);

