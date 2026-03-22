package auth

import (
	"testing"
)

func TestHashPassword(t *testing.T) {
	salt := make([]byte, 32)
	password := "testpassword"

	hash, err := HashPassword(password, salt)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	if len(hash) != Argon2KeyLen {
		t.Errorf("Expected hash length %d, got %d", Argon2KeyLen, len(hash))
	}
}

func TestGenerateSalt(t *testing.T) {
	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt failed: %v", err)
	}

	if len(salt) != 32 {
		t.Errorf("Expected salt length 32, got %d", len(salt))
	}
}

func TestEncodePasswordHash(t *testing.T) {
	salt := []byte("testsalt1234567890123456789012")
	hash := []byte("testhash123456789012345678901234")

	encoded := EncodePasswordHash(salt, hash)
	if encoded == "" {
		t.Error("Expected non-empty encoded hash")
	}
}

func TestDecodePasswordHash(t *testing.T) {
	salt := []byte("testsalt1234567890123456789012")
	hash := []byte("testhash123456789012345678901234")

	encoded := EncodePasswordHash(salt, hash)
	decodedSalt, decodedHash, err := DecodePasswordHash(encoded)
	if err != nil {
		t.Fatalf("DecodePasswordHash failed: %v", err)
	}

	if string(decodedSalt) != string(salt) {
		t.Error("Decoded salt doesn't match original")
	}

	if string(decodedHash) != string(hash) {
		t.Error("Decoded hash doesn't match original")
	}
}

func TestVerifyPassword(t *testing.T) {
	salt := make([]byte, 32)
	password := "testpassword123"

	hash, err := HashPassword(password, salt)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	encoded := EncodePasswordHash(salt, hash)

	isValid, err := VerifyPassword(encoded, password)
	if err != nil {
		t.Fatalf("VerifyPassword failed: %v", err)
	}

	if !isValid {
		t.Error("Expected password to be valid")
	}

	// Test with wrong password
	isValid, err = VerifyPassword(encoded, "wrongpassword")
	if err != nil {
		t.Fatalf("VerifyPassword failed: %v", err)
	}

	if isValid {
		t.Error("Expected password to be invalid")
	}
}

func TestVerifyPasswordInvalidFormat(t *testing.T) {
	_, err := VerifyPassword("invalidformat", "password")
	if err == nil {
		t.Error("Expected error for invalid format")
	}
}
