package encryption

import (
	"testing"

	"github.com/Schera-ole/password_manager/internal/client/crypto"
	"github.com/Schera-ole/password_manager/internal/shared/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestService_EncryptEntry(t *testing.T) {
	service := NewService()

	// Generate a key for testing
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	data := []byte("test data")
	encrypted, err := service.EncryptEntry(key, data)

	require.NoError(t, err)
	assert.NotNil(t, encrypted)
	assert.NotEqual(t, data, encrypted)
	assert.True(t, len(encrypted) > len(data)) // Encrypted data includes nonce
}

func TestService_DecryptEntry(t *testing.T) {
	service := NewService()

	// Generate a key for testing
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	originalData := []byte("test data")
	encrypted, err := service.EncryptEntry(key, originalData)
	require.NoError(t, err)

	decrypted, err := service.DecryptEntry(key, encrypted)
	require.NoError(t, err)
	assert.Equal(t, originalData, decrypted)
}

func TestService_EncryptAndMarshalEntry(t *testing.T) {
	service := NewService()

	// Generate a key for testing
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	entry := models.Entry{
		ID:    "test-id",
		Title: "Test Entry",
		Type:  models.EntryTypeLogin,
		Meta:  map[string]string{"key": "value"},
	}

	encrypted, err := service.EncryptAndMarshalEntry(key, entry)
	require.NoError(t, err)
	assert.NotNil(t, encrypted)
}

func TestService_DecryptAndUnmarshalEntry(t *testing.T) {
	service := NewService()

	// Generate a key for testing
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	originalEntry := models.Entry{
		ID:    "test-id",
		Title: "Test Entry",
		Type:  models.EntryTypeLogin,
		Meta:  map[string]string{"key": "value"},
	}

	encrypted, err := service.EncryptAndMarshalEntry(key, originalEntry)
	require.NoError(t, err)

	decryptedEntry, err := service.DecryptAndUnmarshalEntry(key, encrypted)
	require.NoError(t, err)
	assert.Equal(t, originalEntry.ID, decryptedEntry.ID)
	assert.Equal(t, originalEntry.Title, decryptedEntry.Title)
	assert.Equal(t, originalEntry.Type, decryptedEntry.Type)
	assert.Equal(t, originalEntry.Meta, decryptedEntry.Meta)
}

func TestService_DeriveEncKey(t *testing.T) {
	service := NewService()

	password := "test-password"
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i)
	}

	key, err := service.DeriveEncKey(password, salt)
	require.NoError(t, err)
	assert.NotNil(t, key)
	assert.Equal(t, 32, len(key)) // KeySize constant from crypto package
}

func TestService_DecryptEntry_InvalidData(t *testing.T) {
	service := NewService()

	// Generate a key for testing
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	// Test with too short data
	_, err := service.DecryptEntry(key, []byte("short"))
	assert.Error(t, err)
}

func TestService_DecryptEncSalt(t *testing.T) {
	service := NewService()

	// Generate test data
	password := "test-password"
	staticSalt, err := crypto.GenerateStaticSalt()
	require.NoError(t, err)

	encSalt, err := crypto.GenerateStaticSalt()
	require.NoError(t, err)

	// Derive masterKey from password and static_salt
	masterKey, err := crypto.DeriveKey(password, staticSalt)
	require.NoError(t, err)
	defer crypto.ZeroMemory(masterKey)

	// Create encryptor with masterKey and encrypt encSalt
	encryptor := crypto.NewEncryptorFromKey(masterKey)
	encSaltEnc, err := encryptor.Encrypt(encSalt)
	require.NoError(t, err)
	defer crypto.ZeroMemory(encSaltEnc)

	// Now test our decryption method
	decryptedEncSalt, err := service.DecryptEncSalt(encSaltEnc, password, staticSalt)
	require.NoError(t, err)
	assert.Equal(t, encSalt, decryptedEncSalt)
}
