package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// mockBoltStore is a mock implementation of the Store interface for testing
type mockBoltStore struct {
	tokens         map[string][]byte
	salts          map[string][]byte
	cache          []byte
	entries        map[string][]byte
	lastSync       time.Time
	encryptedToken map[string][]byte
}

func newMockBoltStore() *mockBoltStore {
	return &mockBoltStore{
		tokens:         make(map[string][]byte),
		salts:          make(map[string][]byte),
		entries:        make(map[string][]byte),
		encryptedToken: make(map[string][]byte),
	}
}

func (m *mockBoltStore) SaveToken(tok []byte) error {
	m.tokens["access_token"] = tok
	return nil
}

func (m *mockBoltStore) LoadToken() ([]byte, error) {
	if tok, ok := m.tokens["access_token"]; ok {
		return tok, nil
	}
	return nil, nil
}

func (m *mockBoltStore) SaveStaticSalt(salt []byte) error {
	m.salts["static_salt"] = salt
	return nil
}

func (m *mockBoltStore) LoadStaticSalt() ([]byte, error) {
	if salt, ok := m.salts["static_salt"]; ok {
		return salt, nil
	}
	return nil, nil
}

func (m *mockBoltStore) SaveEncSaltEnc(encrypted []byte) error {
	m.salts["enc_salt_enc"] = encrypted
	return nil
}

func (m *mockBoltStore) LoadEncSaltEnc() ([]byte, error) {
	if salt, ok := m.salts["enc_salt_enc"]; ok {
		return salt, nil
	}
	return nil, nil
}

func (m *mockBoltStore) SaveEncryptedToken(key string, encrypted []byte) error {
	m.encryptedToken[key] = encrypted
	return nil
}

func (m *mockBoltStore) LoadEncryptedToken(key string) ([]byte, error) {
	if tok, ok := m.encryptedToken[key]; ok {
		return tok, nil
	}
	return nil, nil
}

func (m *mockBoltStore) SaveEncryptedEntry(entryID string, encrypted []byte) error {
	m.entries[entryID] = encrypted
	return nil
}

func (m *mockBoltStore) LoadEncryptedEntry(entryID string) ([]byte, error) {
	if entry, ok := m.entries[entryID]; ok {
		return entry, nil
	}
	return nil, nil
}

func (m *mockBoltStore) DeleteEncryptedEntry(entryID string) error {
	delete(m.entries, entryID)
	return nil
}

func (m *mockBoltStore) SaveEncryptedEntries(entries map[string][]byte, lastSync time.Time) error {
	for id, entry := range entries {
		m.entries[id] = entry
	}
	m.lastSync = lastSync
	return nil
}

func (m *mockBoltStore) LoadEncryptedEntries() (map[string][]byte, time.Time, error) {
	return m.entries, m.lastSync, nil
}

func (m *mockBoltStore) SaveLastSync(t time.Time) error {
	m.lastSync = t
	return nil
}

func (m *mockBoltStore) LoadLastSync() (time.Time, error) {
	return m.lastSync, nil
}

func (m *mockBoltStore) Close() error {
	return nil
}

func TestMockBoltStore_SaveLoadToken(t *testing.T) {
	store := newMockBoltStore()

	token := []byte("test-token")
	if err := store.SaveToken(token); err != nil {
		t.Fatalf("Failed to save token: %v", err)
	}

	loadedToken, err := store.LoadToken()
	if err != nil {
		t.Fatalf("Failed to load token: %v", err)
	}

	if string(loadedToken) != string(token) {
		t.Errorf("Loaded token does not match saved token")
		t.Logf("Expected: %s", string(token))
		t.Logf("Got: %s", string(loadedToken))
	}
}

func TestMockBoltStore_SaveLoadStaticSalt(t *testing.T) {
	store := newMockBoltStore()

	salt := []byte("test-static-salt")
	if err := store.SaveStaticSalt(salt); err != nil {
		t.Fatalf("Failed to save static_salt: %v", err)
	}

	loadedSalt, err := store.LoadStaticSalt()
	if err != nil {
		t.Fatalf("Failed to load static_salt: %v", err)
	}

	if string(loadedSalt) != string(salt) {
		t.Errorf("Loaded static_salt does not match saved static_salt")
	}
}

func TestMockBoltStore_SaveLoadEncSaltEnc(t *testing.T) {
	store := newMockBoltStore()

	encrypted := []byte("test-enc-salt-enc")
	if err := store.SaveEncSaltEnc(encrypted); err != nil {
		t.Fatalf("Failed to save enc_salt_enc: %v", err)
	}

	loaded, err := store.LoadEncSaltEnc()
	if err != nil {
		t.Fatalf("Failed to load enc_salt_enc: %v", err)
	}

	if string(loaded) != string(encrypted) {
		t.Errorf("Loaded enc_salt_enc does not match saved enc_salt_enc")
	}
}

func TestMockBoltStore_SaveLoadEncryptedToken(t *testing.T) {
	store := newMockBoltStore()

	key := "access_token"
	encrypted := []byte("test-encrypted-token")
	if err := store.SaveEncryptedToken(key, encrypted); err != nil {
		t.Fatalf("Failed to save encrypted token: %v", err)
	}

	loaded, err := store.LoadEncryptedToken(key)
	if err != nil {
		t.Fatalf("Failed to load encrypted token: %v", err)
	}

	if string(loaded) != string(encrypted) {
		t.Errorf("Loaded encrypted token does not match saved encrypted token")
	}
}

func TestMockBoltStore_SaveLoadEncryptedEntry(t *testing.T) {
	store := newMockBoltStore()

	entryID := "test-entry-id"
	encrypted := []byte("test-encrypted-entry")
	if err := store.SaveEncryptedEntry(entryID, encrypted); err != nil {
		t.Fatalf("Failed to save encrypted entry: %v", err)
	}

	loaded, err := store.LoadEncryptedEntry(entryID)
	if err != nil {
		t.Fatalf("Failed to load encrypted entry: %v", err)
	}

	if string(loaded) != string(encrypted) {
		t.Errorf("Loaded encrypted entry does not match saved encrypted entry")
	}
}

func TestMockBoltStore_DeleteEncryptedEntry(t *testing.T) {
	store := newMockBoltStore()

	entryID := "test-entry-id"
	encrypted := []byte("test-encrypted-entry")

	// Save entry
	if err := store.SaveEncryptedEntry(entryID, encrypted); err != nil {
		t.Fatalf("Failed to save encrypted entry: %v", err)
	}

	// Delete entry
	if err := store.DeleteEncryptedEntry(entryID); err != nil {
		t.Fatalf("Failed to delete encrypted entry: %v", err)
	}

	// Try to load deleted entry
	loaded, err := store.LoadEncryptedEntry(entryID)
	if err != nil {
		t.Fatalf("Failed to load deleted entry: %v", err)
	}

	if loaded != nil {
		t.Errorf("Loaded entry should be nil after deletion")
	}
}

func TestMockBoltStore_SaveLoadEncryptedEntries(t *testing.T) {
	store := newMockBoltStore()

	entries := map[string][]byte{
		"entry1": []byte("encrypted-data-1"),
		"entry2": []byte("encrypted-data-2"),
		"entry3": []byte("encrypted-data-3"),
	}
	lastSync := time.Now()

	if err := store.SaveEncryptedEntries(entries, lastSync); err != nil {
		t.Fatalf("Failed to save encrypted entries: %v", err)
	}

	loadedEntries, loadedLastSync, err := store.LoadEncryptedEntries()
	if err != nil {
		t.Fatalf("Failed to load encrypted entries: %v", err)
	}

	if len(loadedEntries) != len(entries) {
		t.Errorf("Loaded entries count does not match saved entries count")
		t.Logf("Expected: %d, Got: %d", len(entries), len(loadedEntries))
	}

	// Verify each entry
	for id, expected := range entries {
		if loaded, ok := loadedEntries[id]; ok {
			if string(loaded) != string(expected) {
				t.Errorf("Entry %s does not match", id)
			}
		} else {
			t.Errorf("Entry %s not found in loaded entries", id)
		}
	}

	// Check last sync time (within 1 second tolerance)
	diff := loadedLastSync.Sub(lastSync)
	if diff < -time.Second || diff > time.Second {
		t.Errorf("Last sync time mismatch")
		t.Logf("Expected: %v, Got: %v", lastSync, loadedLastSync)
	}
}

func TestMockBoltStore_SaveLoadLastSync(t *testing.T) {
	store := newMockBoltStore()

	lastSync := time.Now()
	if err := store.SaveLastSync(lastSync); err != nil {
		t.Fatalf("Failed to save last sync: %v", err)
	}

	loaded, err := store.LoadLastSync()
	if err != nil {
		t.Fatalf("Failed to load last sync: %v", err)
	}

	// Check last sync time (within 1 second tolerance)
	diff := loaded.Sub(lastSync)
	if diff < -time.Second || diff > time.Second {
		t.Errorf("Last sync time mismatch")
		t.Logf("Expected: %v, Got: %v", lastSync, loaded)
	}
}

// Integration tests for BoltStore
func TestBoltStore_Integration(t *testing.T) {
	// Create a temporary directory for the test database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	// Create a new BoltStore
	store, err := NewBoltStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create BoltStore: %v", err)
	}
	defer store.Close()

	// Test SaveToken and LoadToken
	token := []byte("test-token")
	if err := store.SaveToken(token); err != nil {
		t.Fatalf("Failed to save token: %v", err)
	}

	loadedToken, err := store.LoadToken()
	if err != nil {
		t.Fatalf("Failed to load token: %v", err)
	}

	if string(loadedToken) != string(token) {
		t.Errorf("Loaded token does not match saved token")
	}

	// Test SaveStaticSalt and LoadStaticSalt
	staticSalt := []byte("test-static-salt")
	if err := store.SaveStaticSalt(staticSalt); err != nil {
		t.Fatalf("Failed to save static_salt: %v", err)
	}

	loadedSalt, err := store.LoadStaticSalt()
	if err != nil {
		t.Fatalf("Failed to load static_salt: %v", err)
	}

	if string(loadedSalt) != string(staticSalt) {
		t.Errorf("Loaded static_salt does not match saved static_salt")
	}
}

func TestBoltStore_MultipleOperations(t *testing.T) {
	// Create a temporary directory for the test database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	// Create a new BoltStore
	store, err := NewBoltStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create BoltStore: %v", err)
	}
	defer store.Close()

	// Perform multiple operations
	operations := []struct {
		name  string
		key   string
		value []byte
	}{
		{"token1", "key1", []byte("value1")},
		{"token2", "key2", []byte("value2")},
		{"token3", "key3", []byte("value3")},
	}

	for _, op := range operations {
		if err := store.SaveEncryptedToken(op.key, op.value); err != nil {
			t.Fatalf("Failed to save %s: %v", op.name, err)
		}

		loaded, err := store.LoadEncryptedToken(op.key)
		if err != nil {
			t.Fatalf("Failed to load %s: %v", op.name, err)
		}

		if string(loaded) != string(op.value) {
			t.Errorf("%s: loaded value does not match saved value", op.name)
		}
	}
}

func TestBoltStore_ConcurrentAccess(t *testing.T) {
	// Create a temporary directory for the test database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	// Create a new BoltStore
	store, err := NewBoltStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create BoltStore: %v", err)
	}
	defer store.Close()

	// Test concurrent access (BoltDB is safe for concurrent reads)
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(id int) {
			// Save a token
			token := []byte("token-" + string(rune(id)))
			if err := store.SaveEncryptedToken("key-"+string(rune(id)), token); err != nil {
				t.Errorf("Failed to save token %d: %v", id, err)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestNewBoltStore_InvalidPath(t *testing.T) {
	// Test that NewBoltStore returns an error for an invalid path
	_, err := NewBoltStore("/invalid/path/that/does/not/exist/test.db")
	if err == nil {
		t.Error("Expected error for invalid path")
	}
}

func TestBoltStore_Close(t *testing.T) {
	// Create a temporary directory for the test database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	// Create a new BoltStore
	store, err := NewBoltStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create BoltStore: %v", err)
	}

	// Close the store
	if err := store.Close(); err != nil {
		t.Fatalf("Failed to close BoltStore: %v", err)
	}

	// Try to use the store after closing
	if err := store.SaveToken([]byte("test")); err == nil {
		t.Error("Expected error when using closed store")
	}
}

func TestBoltStore_CreateDirectory(t *testing.T) {
	// Create a temporary directory for the test database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "subdir", "test.db")

	// Create a new BoltStore - it should create the directory
	store, err := NewBoltStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create BoltStore: %v", err)
	}
	defer store.Close()

	// Verify the directory was created
	if _, err := os.Stat(filepath.Dir(dbPath)); os.IsNotExist(err) {
		t.Error("Expected directory to be created")
	}
}
