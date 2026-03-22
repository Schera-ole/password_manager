package service

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/Schera-ole/password_manager/internal/server/auth"
	"github.com/Schera-ole/password_manager/internal/server/errors"
	model "github.com/Schera-ole/password_manager/internal/shared/models"
	authpb "github.com/Schera-ole/password_manager/internal/shared/pb/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// mockRepository is a mock implementation of the Repository interface
type mockRepository struct {
	users        map[string]model.User
	entries      map[string]model.Entry
	syncLogs     []model.SyncLog
	accessTokens map[string]string    // deviceID -> token
	tokenExpiry  map[string]time.Time // deviceID -> expiry
	tokenRevoked map[string]bool      // deviceID -> revoked
}

func newMockRepository() *mockRepository {
	return &mockRepository{
		users:        make(map[string]model.User),
		entries:      make(map[string]model.Entry),
		accessTokens: make(map[string]string),
		tokenExpiry:  make(map[string]time.Time),
		tokenRevoked: make(map[string]bool),
	}
}

func (m *mockRepository) SetEntry(ctx context.Context, entry model.Entry) error {
	m.entries[entry.ID] = entry
	return nil
}

func (m *mockRepository) GetEntry(ctx context.Context, entryID string) (model.Entry, error) {
	if entry, ok := m.entries[entryID]; ok {
		return entry, nil
	}
	return model.Entry{}, errors.ErrQueryExecution
}

func (m *mockRepository) DeleteEntry(ctx context.Context, entryID string) error {
	delete(m.entries, entryID)
	return nil
}

func (m *mockRepository) ListEntries(ctx context.Context, userID string, tags []string) ([]model.Entry, error) {
	var entries []model.Entry
	for _, entry := range m.entries {
		if entry.UserID == userID {
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

func (m *mockRepository) GetSyncLog(ctx context.Context, userID string, since time.Time, limit int) ([]model.SyncLog, error) {
	var logs []model.SyncLog
	for _, log := range m.syncLogs {
		if log.UserID == userID && log.Timestamp.After(since) {
			logs = append(logs, log)
		}
	}
	return logs, nil
}

func (m *mockRepository) AddSyncLog(ctx context.Context, log model.SyncLog) error {
	m.syncLogs = append(m.syncLogs, log)
	return nil
}

func (m *mockRepository) Ping(ctx context.Context) error {
	return nil
}

func (m *mockRepository) Close() error {
	return nil
}

func (m *mockRepository) GetUserByEmail(ctx context.Context, email string) (model.User, error) {
	if user, ok := m.users[email]; ok {
		return user, nil
	}
	return model.User{}, errors.ErrQueryExecution
}

func (m *mockRepository) CreateUser(ctx context.Context, user model.User) error {
	m.users[user.Email] = user
	return nil
}

func (m *mockRepository) StoreAccessToken(ctx context.Context, userID, deviceID, accessToken string, expiresAt time.Time) error {
	m.accessTokens[deviceID] = accessToken
	m.tokenExpiry[deviceID] = expiresAt
	m.tokenRevoked[deviceID] = false
	return nil
}

func (m *mockRepository) GetAccessToken(ctx context.Context, deviceID string) (string, error) {
	if revoked, ok := m.tokenRevoked[deviceID]; ok && revoked {
		return "", errors.ErrQueryExecution
	}
	if token, ok := m.accessTokens[deviceID]; ok {
		if expiry, ok := m.tokenExpiry[deviceID]; ok && expiry.After(time.Now()) {
			return token, nil
		}
	}
	return "", errors.ErrQueryExecution
}

func (m *mockRepository) RevokeAccessToken(ctx context.Context, deviceID string) error {
	m.tokenRevoked[deviceID] = true
	return nil
}

func (m *mockRepository) RevokeAllAccessTokens(ctx context.Context, userID string) error {
	for deviceID := range m.accessTokens {
		m.tokenRevoked[deviceID] = true
	}
	return nil
}

func (m *mockRepository) GetActiveAccessToken(ctx context.Context, userID, deviceID string) (string, error) {
	return m.GetAccessToken(ctx, deviceID)
}

func (m *mockRepository) GetActiveAccessTokens(ctx context.Context, userID string) ([]string, error) {
	var tokens []string
	for deviceID, revoked := range m.tokenRevoked {
		if !revoked {
			if token, ok := m.accessTokens[deviceID]; ok {
				if expiry, ok := m.tokenExpiry[deviceID]; ok && expiry.After(time.Now()) {
					tokens = append(tokens, token)
				}
			}
		}
	}
	return tokens, nil
}

func TestNewPasswordService(t *testing.T) {
	repo := newMockRepository()
	service := NewPasswordService(repo)

	if service == nil {
		t.Error("Expected non-nil service")
	}
}

func TestPasswordService_SetEntry(t *testing.T) {
	repo := newMockRepository()
	service := NewPasswordService(repo)

	ctx := context.Background()
	entry := model.Entry{
		ID:            "test-entry-1",
		UserID:        "user1@example.com",
		Title:         "Test Entry",
		Type:          model.EntryTypeLogin,
		EncryptedBlob: []byte("encrypted data"),
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		Version:       1,
	}

	err := service.SetEntry(ctx, entry)
	if err != nil {
		t.Fatalf("SetEntry failed: %v", err)
	}

	// Verify entry was stored
	storedEntry, err := service.GetEntry(ctx, entry.ID)
	if err != nil {
		t.Fatalf("GetEntry failed: %v", err)
	}

	if storedEntry.Title != entry.Title {
		t.Errorf("Expected title '%s', got '%s'", entry.Title, storedEntry.Title)
	}
}

func TestPasswordService_GetEntry(t *testing.T) {
	repo := newMockRepository()
	service := NewPasswordService(repo)

	ctx := context.Background()
	entry := model.Entry{
		ID:            "test-entry-1",
		UserID:        "user1@example.com",
		Title:         "Test Entry",
		Type:          model.EntryTypeLogin,
		EncryptedBlob: []byte("encrypted data"),
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		Version:       1,
	}

	// Try to get non-existent entry
	_, err := service.GetEntry(ctx, "non-existent")
	if err == nil {
		t.Error("Expected error for non-existent entry")
	}

	// Add entry and try again
	err = service.SetEntry(ctx, entry)
	if err != nil {
		t.Fatalf("SetEntry failed: %v", err)
	}

	storedEntry, err := service.GetEntry(ctx, entry.ID)
	if err != nil {
		t.Fatalf("GetEntry failed: %v", err)
	}

	if storedEntry.ID != entry.ID {
		t.Errorf("Expected ID '%s', got '%s'", entry.ID, storedEntry.ID)
	}
}

func TestPasswordService_DeleteEntry(t *testing.T) {
	repo := newMockRepository()
	service := NewPasswordService(repo)

	ctx := context.Background()
	entry := model.Entry{
		ID:            "test-entry-1",
		UserID:        "user1@example.com",
		Title:         "Test Entry",
		Type:          model.EntryTypeLogin,
		EncryptedBlob: []byte("encrypted data"),
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		Version:       1,
	}

	err := service.SetEntry(ctx, entry)
	if err != nil {
		t.Fatalf("SetEntry failed: %v", err)
	}

	err = service.DeleteEntry(ctx, entry.ID)
	if err != nil {
		t.Fatalf("DeleteEntry failed: %v", err)
	}

	// Verify entry was deleted
	_, err = service.GetEntry(ctx, entry.ID)
	if err == nil {
		t.Error("Expected error for deleted entry")
	}
}

func TestPasswordService_ListEntries(t *testing.T) {
	repo := newMockRepository()
	service := NewPasswordService(repo)

	ctx := context.Background()
	userID := "user1@example.com"

	// Create multiple entries for the same user
	for i := 0; i < 3; i++ {
		entry := model.Entry{
			ID:            "test-entry-" + string(rune(i+'0')),
			UserID:        userID,
			Title:         "Test Entry " + string(rune(i+'0')),
			Type:          model.EntryTypeLogin,
			EncryptedBlob: []byte("encrypted data"),
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
			Version:       1,
		}
		err := service.SetEntry(ctx, entry)
		if err != nil {
			t.Fatalf("SetEntry failed: %v", err)
		}
	}

	entries, err := service.ListEntries(ctx, userID, nil)
	if err != nil {
		t.Fatalf("ListEntries failed: %v", err)
	}

	if len(entries) != 3 {
		t.Errorf("Expected 3 entries, got %d", len(entries))
	}
}

func TestNewUserService(t *testing.T) {
	repo := newMockRepository()
	tokenMgr := auth.NewJWTTokenManagerForTesting()
	service := NewUserService(repo, tokenMgr)

	if service == nil {
		t.Error("Expected non-nil service")
	}
}

func TestUserService_Register(t *testing.T) {
	repo := newMockRepository()
	tokenMgr := auth.NewJWTTokenManagerForTesting()
	service := NewUserService(repo, tokenMgr)

	ctx := context.Background()

	// Generate a valid password hash in format: base64(salt)$base64(hash)
	pwdSalt := []byte("testsalt1234567890123456789012") // 32 bytes
	hash := []byte("testhash123456789012345678901234")  // 32 bytes
	passwordHash := fmt.Sprintf("%s$%s",
		base64.StdEncoding.EncodeToString(pwdSalt),
		base64.StdEncoding.EncodeToString(hash),
	)

	req := authpb.RegisterRequest_builder{
		Email:        "test@example.com",
		PasswordHash: passwordHash,
	}.Build()

	resp, err := service.Register(ctx, req)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	if resp == nil {
		t.Error("Expected non-nil response")
	}

	// Verify user was created
	user, err := repo.GetUserByEmail(ctx, "test@example.com")
	if err != nil {
		t.Fatalf("GetUserByEmail failed: %v", err)
	}

	if user.Email != "test@example.com" {
		t.Errorf("Expected email 'test@example.com', got '%s'", user.Email)
	}
}

func TestUserService_Register_InvalidEmail(t *testing.T) {
	repo := newMockRepository()
	tokenMgr := auth.NewJWTTokenManagerForTesting()
	service := NewUserService(repo, tokenMgr)

	ctx := context.Background()

	// Generate a valid password hash in format: base64(salt)$base64(hash)
	pwdSalt := []byte("testsalt1234567890123456789012") // 32 bytes
	hash := []byte("testhash123456789012345678901234")  // 32 bytes
	passwordHash := fmt.Sprintf("%s$%s",
		base64.StdEncoding.EncodeToString(pwdSalt),
		base64.StdEncoding.EncodeToString(hash),
	)

	req := authpb.RegisterRequest_builder{
		Email:        "", // Empty email
		PasswordHash: passwordHash,
	}.Build()

	_, err := service.Register(ctx, req)
	if err == nil {
		t.Error("Expected error for empty email")
	}

	st := status.Convert(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument code, got %v", st.Code())
	}
}

func TestUserService_Login(t *testing.T) {
	repo := newMockRepository()
	tokenMgr := auth.NewJWTTokenManagerForTesting()
	service := NewUserService(repo, tokenMgr)

	ctx := context.Background()

	// First register a user with a valid password hash
	// Generate password hash using the same algorithm as the server
	password := "testpassword123"
	pwdSalt, err := auth.GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt failed: %v", err)
	}
	hash, err := auth.HashPassword(password, pwdSalt)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}
	passwordHash := auth.EncodePasswordHash(pwdSalt, hash)

	req := authpb.RegisterRequest_builder{
		Email:        "test@example.com",
		PasswordHash: passwordHash,
	}.Build()
	_, err = service.Register(ctx, req)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Then login with the correct password
	loginReq := authpb.LoginRequest_builder{
		Email:    "test@example.com",
		Password: password,
	}.Build()

	resp, err := service.Login(ctx, loginReq)
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	if resp == nil {
		t.Error("Expected non-nil response")
	}

	if resp.GetAccessToken() == "" {
		t.Error("Expected non-empty access token")
	}

}

func TestUserService_Login_InvalidCredentials(t *testing.T) {
	repo := newMockRepository()
	tokenMgr := auth.NewJWTTokenManagerForTesting()
	service := NewUserService(repo, tokenMgr)

	ctx := context.Background()

	// Try to login with non-existent user
	req := authpb.LoginRequest_builder{
		Email:    "nonexistent@example.com",
		Password: "password",
	}.Build()

	_, err := service.Login(ctx, req)
	if err == nil {
		t.Error("Expected error for invalid credentials")
	}

	st := status.Convert(err)
	if st.Code() != codes.NotFound {
		t.Errorf("Expected NotFound code, got %v", st.Code())
	}
}

func TestNewCommonService(t *testing.T) {
	repo := newMockRepository()
	tokenMgr := auth.NewJWTTokenManagerForTesting()
	service := NewCommonService(repo, tokenMgr)

	if service == nil {
		t.Error("Expected non-nil service")
	}
}

func TestUserService_Register_InvalidEmailFormat(t *testing.T) {
	repo := newMockRepository()
	tokenMgr := auth.NewJWTTokenManagerForTesting()
	service := NewUserService(repo, tokenMgr)

	ctx := context.Background()

	// Generate a valid password hash in format: base64(salt)$base64(hash)
	pwdSalt := []byte("testsalt1234567890123456789012") // 32 bytes
	hash := []byte("testhash123456789012345678901234")  // 32 bytes
	passwordHash := fmt.Sprintf("%s$%s",
		base64.StdEncoding.EncodeToString(pwdSalt),
		base64.StdEncoding.EncodeToString(hash),
	)

	req := authpb.RegisterRequest_builder{
		Email:        "invalid-email", // Invalid email format
		PasswordHash: passwordHash,
	}.Build()

	_, err := service.Register(ctx, req)
	if err == nil {
		t.Error("Expected error for invalid email format")
	}

	st := status.Convert(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument code, got %v", st.Code())
	}
}

func TestUserService_Login_EmptyPassword(t *testing.T) {
	repo := newMockRepository()
	tokenMgr := auth.NewJWTTokenManagerForTesting()
	service := NewUserService(repo, tokenMgr)

	ctx := context.Background()

	// First register a user
	pwdSalt := []byte("testsalt1234567890123456789012")
	hash := []byte("testhash123456789012345678901234")
	passwordHash := fmt.Sprintf("%s$%s",
		base64.StdEncoding.EncodeToString(pwdSalt),
		base64.StdEncoding.EncodeToString(hash),
	)

	req := authpb.RegisterRequest_builder{
		Email:        "test@example.com",
		PasswordHash: passwordHash,
	}.Build()
	_, err := service.Register(ctx, req)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Then login with empty password
	loginReq := authpb.LoginRequest_builder{
		Email:    "test@example.com",
		Password: "", // Empty password
	}.Build()

	_, err = service.Login(ctx, loginReq)
	if err == nil {
		t.Error("Expected error for empty password")
	}

	st := status.Convert(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument code, got %v", st.Code())
	}
}

func TestUserService_Logout(t *testing.T) {
	repo := newMockRepository()
	tokenMgr := auth.NewJWTTokenManagerForTesting()
	service := NewUserService(repo, tokenMgr)

	ctx := context.Background()

	logoutReq := authpb.LogoutRequest_builder{
		DeviceId: "test-device-id",
	}.Build()

	resp, err := service.Logout(ctx, logoutReq)
	if err != nil {
		t.Fatalf("Logout failed: %v", err)
	}

	if resp == nil {
		t.Error("Expected non-nil response")
	}
}

func TestPasswordService_SetEntry_SyncLog(t *testing.T) {
	repo := newMockRepository()
	service := NewPasswordService(repo)

	ctx := context.Background()
	userID := "user1@example.com"

	entry := model.Entry{
		ID:            "test-entry-sync",
		UserID:        userID,
		Title:         "Test Entry for Sync",
		Type:          model.EntryTypeLogin,
		EncryptedBlob: []byte("encrypted data"),
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		Version:       1,
	}

	err := service.SetEntry(ctx, entry)
	if err != nil {
		t.Fatalf("SetEntry failed: %v", err)
	}

	// Verify sync log was created
	since := entry.UpdatedAt.Add(-1 * time.Hour)
	logs, err := repo.GetSyncLog(ctx, userID, since, 10)
	if err != nil {
		t.Fatalf("GetSyncLog failed: %v", err)
	}

	if len(logs) != 1 {
		t.Errorf("Expected 1 sync log, got %d", len(logs))
	}

	if len(logs) > 0 {
		if logs[0].EntryID != entry.ID {
			t.Errorf("Expected entry ID '%s', got '%s'", entry.ID, logs[0].EntryID)
		}
		if logs[0].Version != entry.Version {
			t.Errorf("Expected version %d, got %d", entry.Version, logs[0].Version)
		}
	}
}
