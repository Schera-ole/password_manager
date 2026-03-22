-- Add tags column to entries table
ALTER TABLE entries ADD COLUMN tags TEXT[] DEFAULT '{}';

-- Create GIN index for efficient array operations (OR logic filtering)
CREATE INDEX idx_entries_tags ON entries USING GIN (tags);
