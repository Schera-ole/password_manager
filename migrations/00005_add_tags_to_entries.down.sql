-- Drop tags index
DROP INDEX IF EXISTS idx_entries_tags;

-- Drop tags column from entries table
ALTER TABLE entries DROP COLUMN IF EXISTS tags;
