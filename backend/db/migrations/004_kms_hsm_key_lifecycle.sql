-- SourceMark Migration 004: Enterprise Key Management & HSM/KMS Lifecycle
-- Enforces lifecycle tracking, KMS provider isolation, and auditability

ALTER TABLE signing_keys ADD COLUMN IF NOT EXISTS kms_provider VARCHAR(64) DEFAULT 'enterprise-vault';
ALTER TABLE signing_keys ADD COLUMN IF NOT EXISTS kms_key_arn VARCHAR(255);
ALTER TABLE signing_keys ADD COLUMN IF NOT EXISTS algorithm VARCHAR(64) DEFAULT 'Ed25519';
ALTER TABLE signing_keys ADD COLUMN IF NOT EXISTS usage_count INT DEFAULT 0;
ALTER TABLE signing_keys ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ;

-- Index for fast status and organization lookups
CREATE INDEX IF NOT EXISTS idx_signing_keys_status ON signing_keys(status);
CREATE INDEX IF NOT EXISTS idx_signing_keys_org ON signing_keys(organization_id);
CREATE INDEX IF NOT EXISTS idx_signing_keys_kms ON signing_keys(kms_provider);

