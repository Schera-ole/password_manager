package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/lib/pq"

	"github.com/Schera-ole/password_manager/internal/server/errors"
	model "github.com/Schera-ole/password_manager/internal/shared/models"
)

// DBStorage implements the Repository interface using a PostgreSQL database.
type DBStorage struct {
	db *sql.DB
}

// NewDBStorage creates a new database storage instance.
func NewDBStorage(dsn string) (*DBStorage, error) {
	dbConnect, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	return &DBStorage{db: dbConnect}, nil
}

// Close releases any resources held by the database storage.
func (storage *DBStorage) Close() error {
	return storage.db.Close()
}

// SetDBConfig configures the database connection pool settings.
func (storage *DBStorage) SetDBConfig(maxOpenConns, maxIdleConns int, connMaxLifetime time.Duration) {
	storage.db.SetMaxOpenConns(maxOpenConns)
	storage.db.SetMaxIdleConns(maxIdleConns)
	storage.db.SetConnMaxLifetime(connMaxLifetime)
}

// Ping checks the database connection health.
func (storage *DBStorage) Ping(ctx context.Context) error {
	err := storage.db.PingContext(ctx)
	if err != nil {
		return fmt.Errorf("%w: %v", errors.ErrDatabaseConnection, err)
	}
	return nil
}

// GetUserByEmail retrieves a user by their email address.
func (s *DBStorage) GetUserByEmail(ctx context.Context, email string) (model.User, error) {
	query := `SELECT email, password_hash, enc_salt, created_at, updated_at FROM users WHERE email = $1`
	var user model.User
	err := s.db.QueryRowContext(ctx, query, email).Scan(
		&user.Email,
		&user.PasswordHash,
		&user.EncSalt,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return model.User{}, fmt.Errorf("%w: user not found", errors.ErrQueryExecution)
		}
		return model.User{}, fmt.Errorf("%w: %v", errors.ErrQueryExecution, err)
	}
	return user, nil
}

// CreateUser creates a new user in the database.
func (s *DBStorage) CreateUser(ctx context.Context, user model.User) error {
	query := `INSERT INTO users (email, password_hash, enc_salt, created_at, updated_at) VALUES ($1, $2, $3, $4, $5)`
	_, err := s.db.ExecContext(ctx, query,
		user.Email,
		user.PasswordHash,
		user.EncSalt,
		user.CreatedAt,
		user.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("%w: %v", errors.ErrQueryExecution, err)
	}
	return nil
}

// SetEntry stores a single entry value
func (s *DBStorage) SetEntry(ctx context.Context, entry model.Entry) error {
	query := `INSERT INTO entries (id, user_id, title, description, entry_type, meta, encrypted_blob, created_at, updated_at, expires_at, version, tags)
              VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
              ON CONFLICT (id) DO UPDATE SET
                  title = $3, description = $4, entry_type = $5, meta = $6,
                  encrypted_blob = $7, updated_at = $9, expires_at = $10, version = $11, tags = $12`
	// Marshal meta to JSON for storage
	metaJSON, err := json.Marshal(entry.Meta)
	if err != nil {
		return fmt.Errorf("%w: %v", errors.ErrQueryExecution, err)
	}
	_, err = s.db.ExecContext(ctx, query,
		entry.ID,
		entry.UserID,
		entry.Title,
		entry.Description,
		entry.Type,
		string(metaJSON), // store as JSON string
		entry.EncryptedBlob,
		entry.CreatedAt,
		entry.UpdatedAt,
		entry.ExpiresAt,
		entry.Version,
		entry.Tags,
	)
	if err != nil {
		return fmt.Errorf("%w: %v", errors.ErrQueryExecution, err)
	}
	return nil
}

// GetEntry retrieves a single entry by ID
func (s *DBStorage) GetEntry(ctx context.Context, entryID string) (model.Entry, error) {
	query := `SELECT id, user_id, title, description, entry_type, meta, encrypted_blob, created_at, updated_at, expires_at, version, tags
	          FROM entries WHERE id = $1`
	var entry model.Entry
	var metaJSON string
	var tagsArray []string
	err := s.db.QueryRowContext(ctx, query, entryID).Scan(
		&entry.ID,
		&entry.UserID,
		&entry.Title,
		&entry.Description,
		&entry.Type,
		&metaJSON,
		&entry.EncryptedBlob,
		&entry.CreatedAt,
		&entry.UpdatedAt,
		&entry.ExpiresAt,
		&entry.Version,
		&tagsArray,
	)
	entry.Tags = tagsArray
	if err != nil {
		if err == sql.ErrNoRows {
			return model.Entry{}, fmt.Errorf("%w: entry not found", errors.ErrQueryExecution)
		}
		return model.Entry{}, fmt.Errorf("%w: %v", errors.ErrQueryExecution, err)
	}

	// Parse JSON meta
	entry.Meta = make(model.Meta)
	if err := json.Unmarshal([]byte(metaJSON), &entry.Meta); err != nil {
		return model.Entry{}, fmt.Errorf("%w: failed to parse meta: %v", errors.ErrQueryExecution, err)
	}

	return entry, nil
}

// GetEntries retrieves multiple entries by their IDs
// Returns a map of entryID -> Entry for efficient lookup
func (s *DBStorage) GetEntries(ctx context.Context, entryIDs []string) (map[string]model.Entry, error) {
	if len(entryIDs) == 0 {
		return make(map[string]model.Entry), nil
	}

	// Use ANY with array parameter for batch retrieval
	query := `SELECT id, user_id, title, description, entry_type, meta, encrypted_blob, created_at, updated_at, expires_at, version, tags
	          FROM entries WHERE id = ANY($1)`

	rows, err := s.db.QueryContext(ctx, query, pq.Array(entryIDs))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errors.ErrQueryExecution, err)
	}
	defer rows.Close()

	entries := make(map[string]model.Entry)
	for rows.Next() {
		var entry model.Entry
		var metaJSON string
		var tagsArray []string
		err := rows.Scan(
			&entry.ID,
			&entry.UserID,
			&entry.Title,
			&entry.Description,
			&entry.Type,
			&metaJSON,
			&entry.EncryptedBlob,
			&entry.CreatedAt,
			&entry.UpdatedAt,
			&entry.ExpiresAt,
			&entry.Version,
			&tagsArray,
		)
		entry.Tags = tagsArray
		if err != nil {
			return nil, fmt.Errorf("%w: %v", errors.ErrQueryExecution, err)
		}

		// Parse JSON meta
		entry.Meta = make(model.Meta)
		if err := json.Unmarshal([]byte(metaJSON), &entry.Meta); err != nil {
			return nil, fmt.Errorf("%w: failed to parse meta: %v", errors.ErrQueryExecution, err)
		}

		entries[entry.ID] = entry
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: %v", errors.ErrQueryExecution, err)
	}

	return entries, nil
}

// DeleteEntry removes an entry by ID
func (s *DBStorage) DeleteEntry(ctx context.Context, entryID string) error {
	query := `DELETE FROM entries WHERE id = $1`
	_, err := s.db.ExecContext(ctx, query, entryID)
	if err != nil {
		return fmt.Errorf("%w: %v", errors.ErrQueryExecution, err)
	}
	return nil
}

// ListEntries retrieves all entries for a user with optional tags filter
func (s *DBStorage) ListEntries(ctx context.Context, userID string, tags []string) ([]model.Entry, error) {
	query := `SELECT id, user_id, title, description, entry_type, meta, encrypted_blob, created_at, updated_at, expires_at, version, tags
	          FROM entries WHERE user_id = $1`
	args := []interface{}{userID}

	// Add tags filter if provided (OR logic - entries with ANY of the tags)
	if len(tags) > 0 {
		query += ` AND tags && $2::text[]`
		args = append(args, tags)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errors.ErrQueryExecution, err)
	}
	defer rows.Close()

	var entries []model.Entry
	for rows.Next() {
		var entry model.Entry
		var metaJSON string
		var tagsArray []string
		err := rows.Scan(
			&entry.ID,
			&entry.UserID,
			&entry.Title,
			&entry.Description,
			&entry.Type,
			&metaJSON,
			&entry.EncryptedBlob,
			&entry.CreatedAt,
			&entry.UpdatedAt,
			&entry.ExpiresAt,
			&entry.Version,
			&tagsArray,
		)
		entry.Tags = tagsArray
		if err != nil {
			return nil, fmt.Errorf("%w: %v", errors.ErrQueryExecution, err)
		}

		// Parse JSON meta
		entry.Meta = make(model.Meta)
		if err := json.Unmarshal([]byte(metaJSON), &entry.Meta); err != nil {
			return nil, fmt.Errorf("%w: failed to parse meta: %v", errors.ErrQueryExecution, err)
		}

		entries = append(entries, entry)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: %v", errors.ErrQueryExecution, err)
	}

	return entries, nil
}

// GetSyncLog retrieves sync log entries for a user since a given time
func (s *DBStorage) GetSyncLog(ctx context.Context, userID string, since time.Time, limit int) ([]model.SyncLog, error) {
	query := `SELECT id, user_id, entry_id, timestamp, version
	          FROM sync_log WHERE user_id = $1 AND timestamp > $2 ORDER BY timestamp ASC LIMIT $3`
	args := []interface{}{userID, since, limit}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errors.ErrQueryExecution, err)
	}
	defer rows.Close()

	var logs []model.SyncLog
	for rows.Next() {
		var log model.SyncLog
		err := rows.Scan(
			&log.ID,
			&log.UserID,
			&log.EntryID,
			&log.Timestamp,
			&log.Version,
		)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", errors.ErrQueryExecution, err)
		}
		logs = append(logs, log)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: %v", errors.ErrQueryExecution, err)
	}

	return logs, nil
}

// AddSyncLog adds a new sync log entry
func (s *DBStorage) AddSyncLog(ctx context.Context, log model.SyncLog) error {
	query := `INSERT INTO sync_log (user_id, entry_id, timestamp, version) VALUES ($1, $2, $3, $4)`
	_, err := s.db.ExecContext(ctx, query,
		log.UserID,
		log.EntryID,
		log.Timestamp,
		log.Version,
	)
	if err != nil {
		return fmt.Errorf("%w: %v", errors.ErrQueryExecution, err)
	}
	return nil
}

// StoreAccessToken stores a new access token in the database.
func (s *DBStorage) StoreAccessToken(ctx context.Context, userID, deviceID, accessToken string, expiresAt time.Time) error {
	query := `INSERT INTO access_tokens (user_id, device_id, access_token, created_at, expires_at) VALUES ($1, $2, $3, $4, $5)`
	_, err := s.db.ExecContext(ctx, query,
		userID,
		deviceID,
		accessToken,
		time.Now(),
		expiresAt,
	)
	if err != nil {
		return fmt.Errorf("%w: %v", errors.ErrQueryExecution, err)
	}
	return nil
}

// GetAccessToken retrieves an access token by device ID.
func (s *DBStorage) GetAccessToken(ctx context.Context, deviceID string) (string, error) {
	query := `SELECT access_token FROM access_tokens WHERE device_id = $1 AND revoked_at IS NULL AND expires_at > NOW()`
	var token string
	err := s.db.QueryRowContext(ctx, query, deviceID).Scan(&token)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("%w: token not found", errors.ErrQueryExecution)
		}
		return "", fmt.Errorf("%w: %v", errors.ErrQueryExecution, err)
	}
	return token, nil
}

// RevokeAccessToken revokes an access token by device ID.
func (s *DBStorage) RevokeAccessToken(ctx context.Context, deviceID string) error {
	query := `UPDATE access_tokens SET revoked_at = NOW() WHERE device_id = $1`
	_, err := s.db.ExecContext(ctx, query, deviceID)
	if err != nil {
		return fmt.Errorf("%w: %v", errors.ErrQueryExecution, err)
	}
	return nil
}

// RevokeAllAccessTokens revokes all access tokens for a user.
func (s *DBStorage) RevokeAllAccessTokens(ctx context.Context, userID string) error {
	query := `UPDATE access_tokens SET revoked_at = NOW() WHERE user_id = $1`
	_, err := s.db.ExecContext(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("%w: %v", errors.ErrQueryExecution, err)
	}
	return nil
}

// GetActiveAccessToken retrieves an active access token for a specific user and device.
func (s *DBStorage) GetActiveAccessToken(ctx context.Context, userID, deviceID string) (string, error) {
	query := `SELECT access_token FROM access_tokens WHERE user_id = $1 AND device_id = $2 AND revoked_at IS NULL AND expires_at > NOW()`
	var token string
	err := s.db.QueryRowContext(ctx, query, userID, deviceID).Scan(&token)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("%w: token not found", errors.ErrQueryExecution)
		}
		return "", fmt.Errorf("%w: %v", errors.ErrQueryExecution, err)
	}
	return token, nil
}

// GetActiveAccessTokens retrieves all active access tokens for a user.
func (s *DBStorage) GetActiveAccessTokens(ctx context.Context, userID string) ([]string, error) {
	query := `SELECT access_token FROM access_tokens WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > NOW()`
	rows, err := s.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errors.ErrQueryExecution, err)
	}
	defer rows.Close()

	var tokens []string
	for rows.Next() {
		var token string
		if err := rows.Scan(&token); err != nil {
			return nil, fmt.Errorf("%w: %v", errors.ErrQueryExecution, err)
		}
		tokens = append(tokens, token)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: %v", errors.ErrQueryExecution, err)
	}

	return tokens, nil
}
