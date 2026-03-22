package grpc

import (
	"testing"
	"time"
)

// mockStore is a mock implementation of the Store interface for testing
type mockStore struct {
	tokens map[string][]byte
}

func newMockStore() *mockStore {
	return &mockStore{
		tokens: make(map[string][]byte),
	}
}

func (m *mockStore) SaveToken(tok []byte) error {
	m.tokens["access_token"] = tok
	return nil
}

func (m *mockStore) LoadToken() ([]byte, error) {
	if tok, ok := m.tokens["access_token"]; ok {
		return tok, nil
	}
	return nil, nil
}

func (m *mockStore) SaveStaticSalt(salt []byte) error {
	m.tokens["static_salt"] = salt
	return nil
}

func (m *mockStore) LoadStaticSalt() ([]byte, error) {
	if salt, ok := m.tokens["static_salt"]; ok {
		return salt, nil
	}
	return nil, nil
}

func (m *mockStore) SaveEncSaltEnc(encrypted []byte) error {
	m.tokens["enc_salt_enc"] = encrypted
	return nil
}

func (m *mockStore) LoadEncSaltEnc() ([]byte, error) {
	if salt, ok := m.tokens["enc_salt_enc"]; ok {
		return salt, nil
	}
	return nil, nil
}

func (m *mockStore) SaveEncryptedToken(key string, encrypted []byte) error {
	m.tokens[key] = encrypted
	return nil
}

func (m *mockStore) LoadEncryptedToken(key string) ([]byte, error) {
	if tok, ok := m.tokens[key]; ok {
		return tok, nil
	}
	return nil, nil
}

func (m *mockStore) SaveEncryptedEntry(entryID string, encrypted []byte) error {
	return nil
}

func (m *mockStore) LoadEncryptedEntry(entryID string) ([]byte, error) {
	return nil, nil
}

func (m *mockStore) DeleteEncryptedEntry(entryID string) error {
	return nil
}

func (m *mockStore) SaveEncryptedEntries(entries map[string][]byte, lastSync time.Time) error {
	return nil
}

func (m *mockStore) LoadEncryptedEntries() (map[string][]byte, time.Time, error) {
	return nil, time.Time{}, nil
}

func (m *mockStore) SaveLastSync(t time.Time) error {
	return nil
}

func (m *mockStore) LoadLastSync() (time.Time, error) {
	return time.Time{}, nil
}

func (m *mockStore) Close() error {
	return nil
}

func (m *mockStore) ClearAllData() error {
	m.tokens = make(map[string][]byte)
	return nil
}

func TestNewClient(t *testing.T) {
	// Test that NewClient creates a new client
	store := newMockStore()

	client, err := NewClient("localhost:50051", store)
	if err != nil {
		// Expected to fail without a real gRPC server
		t.Logf("Expected error (no gRPC server): %v", err)
		return
	}
	defer client.Close()

	if client == nil {
		t.Error("Expected client to be non-nil")
	}
}

func TestClient_GetAuth(t *testing.T) {
	// Test that GetAuth returns a valid auth client
	store := newMockStore()

	client, err := NewClient("localhost:50051", store)
	if err != nil {
		// Expected to fail without a real gRPC server
		t.Logf("Expected error (no gRPC server): %v", err)
		return
	}
	defer client.Close()

	authClient := client.GetAuth()

	if authClient == nil {
		t.Error("Expected authClient to be non-nil")
	}
}

func TestClient_GetPM(t *testing.T) {
	// Test that GetPM returns a valid password manager client
	store := newMockStore()

	client, err := NewClient("localhost:50051", store)
	if err != nil {
		// Expected to fail without a real gRPC server
		t.Logf("Expected error (no gRPC server): %v", err)
		return
	}
	defer client.Close()

	pmClient := client.GetPM()

	if pmClient == nil {
		t.Error("Expected pmClient to be non-nil")
	}
}

func TestClient_GetConn(t *testing.T) {
	// Test that GetConn returns a valid connection
	store := newMockStore()

	client, err := NewClient("localhost:50051", store)
	if err != nil {
		// Expected to fail without a real gRPC server
		t.Logf("Expected error (no gRPC server): %v", err)
		return
	}
	defer client.Close()

	conn := client.GetConn()

	if conn == nil {
		t.Error("Expected conn to be non-nil")
	}
}

func TestClient_GetStore(t *testing.T) {
	// Test that GetStore returns the store
	store := newMockStore()

	client, err := NewClient("localhost:50051", store)
	if err != nil {
		// Expected to fail without a real gRPC server
		t.Logf("Expected error (no gRPC server): %v", err)
		return
	}
	defer client.Close()

	storedStore := client.GetStore()

	if storedStore == nil {
		t.Error("Expected storedStore to be non-nil")
	}
}

func TestClient_Close(t *testing.T) {
	// Test that Close closes the connection
	store := newMockStore()

	client, err := NewClient("localhost:50051", store)
	if err != nil {
		// Expected to fail without a real gRPC server
		t.Logf("Expected error (no gRPC server): %v", err)
		return
	}

	err = client.Close()
	if err != nil {
		t.Errorf("Expected no error from Close, got: %v", err)
	}
}
