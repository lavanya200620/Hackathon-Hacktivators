-- SourceMark Migration 003: Phase 4 Application Integration
-- Adds virtual demo asset distinction and performance indexes

ALTER TABLE sources ADD COLUMN IF NOT EXISTS is_virtual_demo BOOLEAN DEFAULT FALSE;

-- Ensure demonstration and mock sources are flagged as virtual demos
UPDATE sources 
SET is_virtual_demo = TRUE 
WHERE id = 'SRC-98214' 
   OR creator_email = 'system@sourcemark.io' 
   OR description ILIKE '%demo%' 
   OR description ILIKE '%sample%'
   OR description ILIKE '%synthetic%';

-- Add index on is_virtual_demo for fast filtering
CREATE INDEX IF NOT EXISTS idx_sources_is_virtual_demo ON sources(is_virtual_demo);

