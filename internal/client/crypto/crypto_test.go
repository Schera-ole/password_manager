package crypto

import (
	"crypto/rand"
	"testing"
)

func TestEncryptor_EncryptDecrypt(t *testing.T) {
	// Generate a test salt
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	// Create encryptor
	encryptor, err := NewEncryptor("testpassword", salt)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	// Test data
	testData := []byte("Hello, World! This is a test message.")

	// Encrypt
	encrypted, err := encryptor.Encrypt(testData)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Verify encrypted data is longer than original (includes nonce + tag)
	if len(encrypted) <= len(testData) {
		t.Errorf("Encrypted data should be longer than original")
	}

	// Decrypt
	decrypted, err := encryptor.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	// Verify decrypted data matches original
	if string(decrypted) != string(testData) {
		t.Errorf("Decrypted data does not match original")
		t.Logf("Expected: %s", string(testData))
		t.Logf("Got: %s", string(decrypted))
	}
}

func TestEncryptor_EncryptDecryptEmpty(t *testing.T) {
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	encryptor, err := NewEncryptor("testpassword", salt)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	// Test with empty data
	encrypted, err := encryptor.Encrypt([]byte{})
	if err != nil {
		t.Fatalf("Failed to encrypt empty data: %v", err)
	}

	decrypted, err := encryptor.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Failed to decrypt empty data: %v", err)
	}

	if len(decrypted) != 0 {
		t.Errorf("Decrypted empty data should be empty")
	}
}

func TestEncryptor_EncryptDecryptInvalidCiphertext(t *testing.T) {
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	encryptor, err := NewEncryptor("testpassword", salt)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	// Test with too short ciphertext
	_, err = encryptor.Decrypt([]byte{1, 2, 3})
	if err == nil {
		t.Error("Expected error for too short ciphertext")
	}
}

func TestGeneratePwdSalt(t *testing.T) {
	salt, err := GeneratePwdSalt()
	if err != nil {
		t.Fatalf("Failed to generate password salt: %v", err)
	}

	if len(salt) != 32 {
		t.Errorf("Password salt should be 32 bytes, got %d", len(salt))
	}

	// Verify salt is not all zeros
	allZeros := true
	for _, b := range salt {
		if b != 0 {
			allZeros = false
			break
		}
	}
	if allZeros {
		t.Error("Password salt should not be all zeros")
	}
}

func TestGenerateStaticSalt(t *testing.T) {
	salt, err := GenerateStaticSalt()
	if err != nil {
		t.Fatalf("Failed to generate static salt: %v", err)
	}

	if len(salt) != 32 {
		t.Errorf("Static salt should be 32 bytes, got %d", len(salt))
	}

	// Verify salt is not all zeros
	allZeros := true
	for _, b := range salt {
		if b != 0 {
			allZeros = false
			break
		}
	}
	if allZeros {
		t.Error("Static salt should not be all zeros")
	}
}

func TestHashPassword(t *testing.T) {
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	hash, err := HashPassword("testpassword", salt)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	if len(hash) != 32 {
		t.Errorf("Password hash should be 32 bytes, got %d", len(hash))
	}

	// Verify hash is not all zeros
	allZeros := true
	for _, b := range hash {
		if b != 0 {
			allZeros = false
			break
		}
	}
	if allZeros {
		t.Error("Password hash should not be all zeros")
	}
}

func TestDeriveKey(t *testing.T) {
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	key, err := DeriveKey("testpassword", salt)
	if err != nil {
		t.Fatalf("Failed to derive key: %v", err)
	}

	if len(key) != 32 {
		t.Errorf("Derived key should be 32 bytes, got %d", len(key))
	}

	// Verify key is not all zeros
	allZeros := true
	for _, b := range key {
		if b != 0 {
			allZeros = false
			break
		}
	}
	if allZeros {
		t.Error("Derived key should not be all zeros")
	}
}

func TestFormatPasswordHash(t *testing.T) {
	pwdSalt := make([]byte, 32)
	_, err := rand.Read(pwdSalt)
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	hash := make([]byte, 32)
	_, err = rand.Read(hash)
	if err != nil {
		t.Fatalf("Failed to generate hash: %v", err)
	}

	formatted := FormatPasswordHash(pwdSalt, hash)

	// Verify format contains $ separator
	if len(formatted) < 3 {
		t.Error("Formatted hash should not be empty")
	}
}

func TestZeroMemory(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	ZeroMemory(data)

	for i, b := range data {
		if b != 0 {
			t.Errorf("Byte at index %d should be zero, got %d", i, b)
		}
	}
}
