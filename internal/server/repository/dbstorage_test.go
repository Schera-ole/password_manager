package repository

import (
	"context"
	"database/sql"
	"database/sql/driver"
	stdErr "errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	srvErr "github.com/Schera-ole/password_manager/internal/server/errors"
	model "github.com/Schera-ole/password_manager/internal/shared/models"
)

// helper to create DBStorage with sqlmock
func newMockStorage(t *testing.T) (*DBStorage, sqlmock.Sqlmock) {
	db, mock, err := sqlmock.New(sqlmock.ValueConverterOption(CustomValueConverter{}))
	if err != nil {
		t.Fatalf("failed to open sqlmock: %v", err)
	}
	storage := &DBStorage{db: db}
	return storage, mock
}

// CustomValueConverter handles conversion of []string to PostgreSQL arrays
type CustomValueConverter struct{}

func (CustomValueConverter) ConvertValue(v interface{}) (driver.Value, error) {
	switch v := v.(type) {
	case []string:
		// Convert []string to PostgreSQL array format
		if len(v) == 0 {
			return "{}", nil
		}
		// Escape special characters and format as PostgreSQL array
		elements := make([]string, len(v))
		for i, s := range v {
			// Escape quotes and backslashes
			s = strings.ReplaceAll(s, `\`, `\\`)
			s = strings.ReplaceAll(s, `"`, `\"`)
			elements[i] = `"` + s + `"`
		}
		return "{" + strings.Join(elements, ",") + "}", nil
	default:
		return driver.DefaultParameterConverter.ConvertValue(v)
	}
}

func TestPing(t *testing.T) {
	storage, mock := newMockStorage(t)
	mock.ExpectPing()
	if err := storage.Ping(context.Background()); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestGetUserByEmail_Success(t *testing.T) {
	storage, mock := newMockStorage(t)
	rows := sqlmock.NewRows([]string{"email", "password_hash", "enc_salt", "created_at", "updated_at"}).
		AddRow("test@example.com", "hash", "salt", time.Now(), time.Now())
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT email, password_hash, enc_salt, created_at, updated_at FROM users WHERE email = $1`)).
		WithArgs("test@example.com").WillReturnRows(rows)

	user, err := storage.GetUserByEmail(context.Background(), "test@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user.Email != "test@example.com" {
		t.Fatalf("unexpected email: %s", user.Email)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestGetUserByEmail_NotFound(t *testing.T) {
	storage, mock := newMockStorage(t)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT email, password_hash, enc_salt, created_at, updated_at FROM users WHERE email = $1`)).
		WithArgs("missing@example.com").WillReturnError(sql.ErrNoRows)

	_, err := storage.GetUserByEmail(context.Background(), "missing@example.com")
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !stdErr.Is(err, srvErr.ErrQueryExecution) {
		t.Fatalf("expected ErrQueryExecution, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestCreateUser(t *testing.T) {
	storage, mock := newMockStorage(t)
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO users (email, password_hash, enc_salt, created_at, updated_at) VALUES ($1, $2, $3, $4, $5)`)).
		WithArgs("u@example.com", "hash", "salt", sqlmock.AnyArg(), sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(1, 1))

	user := model.User{Email: "u@example.com", PasswordHash: "hash", EncSalt: "salt", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := storage.CreateUser(context.Background(), user); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestSetEntry(t *testing.T) {
	storage, mock := newMockStorage(t)
	// Fix the regex to match the actual query
	query := `INSERT INTO entries (id, user_id, title, description, entry_type, meta, encrypted_blob, created_at, updated_at, expires_at, version, tags) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) ON CONFLICT (id) DO UPDATE SET title = $3, description = $4, entry_type = $5, meta = $6, encrypted_blob = $7, updated_at = $9, expires_at = $10, version = $11, tags = $12`
	mock.ExpectExec(regexp.QuoteMeta(query)).
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), "title", "desc", model.EntryTypeLogin, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), []string{"tag1"}).
		WillReturnResult(sqlmock.NewResult(1, 1))

	expires := time.Now().Add(time.Hour)
	entry := model.Entry{ID: "1", UserID: "u", Title: "title", Description: "desc", Type: model.EntryTypeLogin, Meta: model.Meta{"k": "v"}, EncryptedBlob: []byte{0x01}, CreatedAt: time.Now(), UpdatedAt: time.Now(), ExpiresAt: &expires, Version: 1, Tags: []string{"tag1"}}
	if err := storage.SetEntry(context.Background(), entry); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestDeleteEntry_Success(t *testing.T) {
	storage, mock := newMockStorage(t)
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM entries WHERE id = $1`)).
		WithArgs("1").WillReturnResult(sqlmock.NewResult(1, 1))

	err := storage.DeleteEntry(context.Background(), "1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestDeleteEntry_Error(t *testing.T) {
	storage, mock := newMockStorage(t)
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM entries WHERE id = $1`)).
		WithArgs("1").WillReturnError(stdErr.New("database error"))

	err := storage.DeleteEntry(context.Background(), "1")
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !stdErr.Is(err, srvErr.ErrQueryExecution) {
		t.Fatalf("expected ErrQueryExecution, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestListEntries_MetaParseError(t *testing.T) {
	storage, mock := newMockStorage(t)
	// For sqlmock, we need to use PostgreSQL array format for the tags column
	rows := sqlmock.NewRows([]string{"id", "user_id", "title", "description", "entry_type", "meta", "encrypted_blob", "created_at", "updated_at", "expires_at", "version", "tags"}).
		AddRow("1", "u", "title", "desc", model.EntryTypeLogin, "{invalid json", []byte{0x01}, time.Now(), time.Now(), time.Now().Add(time.Hour), 1, "{}")
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT id, user_id, title, description, entry_type, meta, encrypted_blob, created_at, updated_at, expires_at, version, tags
	          FROM entries WHERE user_id = $1`)).
		WithArgs("u").WillReturnRows(rows)

	_, err := storage.ListEntries(context.Background(), "u", nil)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !stdErr.Is(err, srvErr.ErrQueryExecution) {
		t.Fatalf("expected ErrQueryExecution, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestGetSyncLog_Success(t *testing.T) {
	storage, mock := newMockStorage(t)
	now := time.Now()
	rows := sqlmock.NewRows([]string{"id", "user_id", "entry_id", "timestamp", "version"}).
		AddRow(1, "u", "e1", now, 1).
		AddRow(2, "u", "e2", now.Add(time.Minute), 2)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT id, user_id, entry_id, timestamp, version
	          FROM sync_log WHERE user_id = $1 AND timestamp > $2 ORDER BY timestamp ASC LIMIT $3`)).
		WithArgs("u", now.Add(-time.Hour), 100).WillReturnRows(rows)

	logs, err := storage.GetSyncLog(context.Background(), "u", now.Add(-time.Hour), 100)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(logs) != 2 {
		t.Fatalf("expected 2 logs, got %d", len(logs))
	}
	if logs[0].ID != 1 || logs[1].ID != 2 {
		t.Fatalf("unexpected log IDs: %d, %d", logs[0].ID, logs[1].ID)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestGetSyncLog_Error(t *testing.T) {
	storage, mock := newMockStorage(t)
	now := time.Now()
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT id, user_id, entry_id, timestamp, version
	          FROM sync_log WHERE user_id = $1 AND timestamp > $2 ORDER BY timestamp ASC LIMIT $3`)).
		WithArgs("u", now.Add(-time.Hour), 100).WillReturnError(stdErr.New("database error"))

	_, err := storage.GetSyncLog(context.Background(), "u", now.Add(-time.Hour), 100)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !stdErr.Is(err, srvErr.ErrQueryExecution) {
		t.Fatalf("expected ErrQueryExecution, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestAddSyncLog_Success(t *testing.T) {
	storage, mock := newMockStorage(t)
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO sync_log (user_id, entry_id, timestamp, version) VALUES ($1, $2, $3, $4)`)).
		WithArgs("u", "e1", sqlmock.AnyArg(), int64(1)).WillReturnResult(sqlmock.NewResult(1, 1))

	log := model.SyncLog{UserID: "u", EntryID: "e1", Timestamp: time.Now(), Version: 1}
	if err := storage.AddSyncLog(context.Background(), log); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestAddSyncLog_Error(t *testing.T) {
	storage, mock := newMockStorage(t)
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO sync_log (user_id, entry_id, timestamp, version) VALUES ($1, $2, $3, $4)`)).
		WithArgs("u", "e1", sqlmock.AnyArg(), int64(1)).WillReturnError(stdErr.New("database error"))

	log := model.SyncLog{UserID: "u", EntryID: "e1", Timestamp: time.Now(), Version: 1}
	err := storage.AddSyncLog(context.Background(), log)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !stdErr.Is(err, srvErr.ErrQueryExecution) {
		t.Fatalf("expected ErrQueryExecution, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestStoreAccessToken_Success(t *testing.T) {
	storage, mock := newMockStorage(t)
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO access_tokens (user_id, device_id, access_token, created_at, expires_at) VALUES ($1, $2, $3, $4, $5)`)).
		WithArgs("u", "device1", "token123", sqlmock.AnyArg(), sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(1, 1))

	expires := time.Now().Add(time.Hour)
	err := storage.StoreAccessToken(context.Background(), "u", "device1", "token123", expires)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestStoreAccessToken_Error(t *testing.T) {
	storage, mock := newMockStorage(t)
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO access_tokens (user_id, device_id, access_token, created_at, expires_at) VALUES ($1, $2, $3, $4, $5)`)).
		WithArgs("u", "device1", "token123", sqlmock.AnyArg(), sqlmock.AnyArg()).WillReturnError(stdErr.New("database error"))

	expires := time.Now().Add(time.Hour)
	err := storage.StoreAccessToken(context.Background(), "u", "device1", "token123", expires)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !stdErr.Is(err, srvErr.ErrQueryExecution) {
		t.Fatalf("expected ErrQueryExecution, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestGetAccessToken_Success(t *testing.T) {
	storage, mock := newMockStorage(t)
	rows := sqlmock.NewRows([]string{"access_token"}).
		AddRow("token123")
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT access_token FROM access_tokens WHERE device_id = $1 AND revoked_at IS NULL AND expires_at > NOW()`)).
		WithArgs("device1").WillReturnRows(rows)

	token, err := storage.GetAccessToken(context.Background(), "device1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "token123" {
		t.Fatalf("unexpected token: %s", token)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestGetAccessToken_NotFound(t *testing.T) {
	storage, mock := newMockStorage(t)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT access_token FROM access_tokens WHERE device_id = $1 AND revoked_at IS NULL AND expires_at > NOW()`)).
		WithArgs("device1").WillReturnError(sql.ErrNoRows)

	_, err := storage.GetAccessToken(context.Background(), "device1")
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !stdErr.Is(err, srvErr.ErrQueryExecution) {
		t.Fatalf("expected ErrQueryExecution, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestRevokeAccessToken_Success(t *testing.T) {
	storage, mock := newMockStorage(t)
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE access_tokens SET revoked_at = NOW() WHERE device_id = $1`)).
		WithArgs("device1").WillReturnResult(sqlmock.NewResult(1, 1))

	err := storage.RevokeAccessToken(context.Background(), "device1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestRevokeAccessToken_Error(t *testing.T) {
	storage, mock := newMockStorage(t)
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE access_tokens SET revoked_at = NOW() WHERE device_id = $1`)).
		WithArgs("device1").WillReturnError(stdErr.New("database error"))

	err := storage.RevokeAccessToken(context.Background(), "device1")
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !stdErr.Is(err, srvErr.ErrQueryExecution) {
		t.Fatalf("expected ErrQueryExecution, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestRevokeAllAccessTokens_Success(t *testing.T) {
	storage, mock := newMockStorage(t)
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE access_tokens SET revoked_at = NOW() WHERE user_id = $1`)).
		WithArgs("u").WillReturnResult(sqlmock.NewResult(1, 1))

	err := storage.RevokeAllAccessTokens(context.Background(), "u")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestRevokeAllAccessTokens_Error(t *testing.T) {
	storage, mock := newMockStorage(t)
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE access_tokens SET revoked_at = NOW() WHERE user_id = $1`)).
		WithArgs("u").WillReturnError(stdErr.New("database error"))

	err := storage.RevokeAllAccessTokens(context.Background(), "u")
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !stdErr.Is(err, srvErr.ErrQueryExecution) {
		t.Fatalf("expected ErrQueryExecution, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestGetActiveAccessToken_Success(t *testing.T) {
	storage, mock := newMockStorage(t)
	rows := sqlmock.NewRows([]string{"access_token"}).
		AddRow("token123")
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT access_token FROM access_tokens WHERE user_id = $1 AND device_id = $2 AND revoked_at IS NULL AND expires_at > NOW()`)).
		WithArgs("u", "device1").WillReturnRows(rows)

	token, err := storage.GetActiveAccessToken(context.Background(), "u", "device1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "token123" {
		t.Fatalf("unexpected token: %s", token)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestGetActiveAccessToken_NotFound(t *testing.T) {
	storage, mock := newMockStorage(t)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT access_token FROM access_tokens WHERE user_id = $1 AND device_id = $2 AND revoked_at IS NULL AND expires_at > NOW()`)).
		WithArgs("u", "device1").WillReturnError(sql.ErrNoRows)

	_, err := storage.GetActiveAccessToken(context.Background(), "u", "device1")
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !stdErr.Is(err, srvErr.ErrQueryExecution) {
		t.Fatalf("expected ErrQueryExecution, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestGetActiveAccessTokens_Success(t *testing.T) {
	storage, mock := newMockStorage(t)
	rows := sqlmock.NewRows([]string{"access_token"}).
		AddRow("token123").
		AddRow("token456")
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT access_token FROM access_tokens WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > NOW()`)).
		WithArgs("u").WillReturnRows(rows)

	tokens, err := storage.GetActiveAccessTokens(context.Background(), "u")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tokens) != 2 {
		t.Fatalf("expected 2 tokens, got %d", len(tokens))
	}
	if tokens[0] != "token123" || tokens[1] != "token456" {
		t.Fatalf("unexpected tokens: %v", tokens)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestGetActiveAccessTokens_Error(t *testing.T) {
	storage, mock := newMockStorage(t)
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT access_token FROM access_tokens WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > NOW()`)).
		WithArgs("u").WillReturnError(stdErr.New("database error"))

	_, err := storage.GetActiveAccessTokens(context.Background(), "u")
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !stdErr.Is(err, srvErr.ErrQueryExecution) {
		t.Fatalf("expected ErrQueryExecution, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}
