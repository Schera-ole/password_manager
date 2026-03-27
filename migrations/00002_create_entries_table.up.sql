-- Create entries table
CREATE TABLE IF NOT EXISTS entries (
    id UUID PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL REFERENCES users(email) ON DELETE CASCADE,
    title TEXT NOT NULL,
    description TEXT,
    entry_type SMALLINT NOT NULL,
    meta JSONB NOT NULL DEFAULT '{}',
    encrypted_blob BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    version BIGINT NOT NULL DEFAULT 1
);

-- Create index on user_id for faster lookups
CREATE INDEX IF NOT EXISTS idx_entries_user_id ON entries(user_id);

-- Create index on entry_type for filtering
CREATE INDEX IF NOT EXISTS idx_entries_type ON entries(entry_type);

-- Create index on created_at for sorting
CREATE INDEX IF NOT EXISTS idx_entries_created_at ON entries(created_at);

-- Update updated_at timestamp on row update
CREATE OR REPLACE FUNCTION update_entries_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_entries_updated_at
    BEFORE UPDATE ON entries
    FOR EACH ROW
    EXECUTE FUNCTION update_entries_updated_at();
