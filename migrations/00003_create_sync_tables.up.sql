-- Create sync_log table
CREATE TABLE IF NOT EXISTS sync_log (
    id BIGSERIAL PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL REFERENCES users(email) ON DELETE CASCADE,
    entry_id UUID NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    version BIGINT NOT NULL DEFAULT 1
);

-- Create index on user_id for faster lookups
CREATE INDEX IF NOT EXISTS idx_sync_log_user_id ON sync_log(user_id);

-- Create index on timestamp for filtering by time
CREATE INDEX IF NOT EXISTS idx_sync_log_timestamp ON sync_log(timestamp);

-- Create index on entry_id for faster lookups
CREATE INDEX IF NOT EXISTS idx_sync_log_entry_id ON sync_log(entry_id);
