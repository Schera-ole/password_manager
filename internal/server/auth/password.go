package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/argon2"
)

const (
	Argon2Time    = 3         // iterations
	Argon2Memory  = 64 * 1024 // 64 MB
	Argon2Threads = 4         // parallelism
	Argon2KeyLen  = 32        // 256-bit key
)

// HashPassword hashes a password using Argon2id, returns the hash as a byte slice
func HashPassword(password string, salt []byte) ([]byte, error) {

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		Argon2Time,
		Argon2Memory,
		Argon2Threads,
		Argon2KeyLen,
	)

	return hash, nil
}

// GenerateSalt generates a random salt for encryption
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}
	return salt, nil
}

// EncodePasswordHash encodes salt and hash as base64(salt)$base64(hash)
func EncodePasswordHash(salt, hash []byte) string {
	return fmt.Sprintf("%s$%s",
		base64.StdEncoding.EncodeToString(salt),
		base64.StdEncoding.EncodeToString(hash),
	)
}

// DecodePasswordHash decodes base64(salt)$base64(hash) format
func DecodePasswordHash(encoded string) ([]byte, []byte, error) {
	parts := splitOnFirstByte([]byte(encoded), '$')
	if len(parts) != 2 {
		return nil, nil, fmt.Errorf("invalid password hash format")
	}

	salt, err := base64.StdEncoding.DecodeString(string(parts[0]))
	if err != nil {
		return nil, nil, fmt.Errorf("decode salt: %w", err)
	}

	hash, err := base64.StdEncoding.DecodeString(string(parts[1]))
	if err != nil {
		return nil, nil, fmt.Errorf("decode hash: %w", err)
	}

	return salt, hash, nil
}

// VerifyPassword verifies a password against the stored hash
// The stored hash format is base64(salt)$base64(hash)
func VerifyPassword(storedHash, password string) (bool, error) {
	salt, hash, err := DecodePasswordHash(storedHash)
	if err != nil {
		fmt.Printf("  Failed to decode password hash: %v\n", err)
		return false, err
	}

	// Compute hash of provided password
	computedHash, err := HashPassword(password, salt)
	if err != nil {
		fmt.Printf("  Failed to compute hash: %v\n", err)
		return false, err
	}

	// Use constant-time comparison
	result := constantTimeCompare(hash, computedHash)
	fmt.Printf("  Comparison result: %t\n", result)
	return result, nil
}

// splitOnFirstByte splits a byte slice on the first occurrence of sep
func splitOnFirstByte(data []byte, sep byte) [][]byte {
	for i, b := range data {
		if b == sep {
			return [][]byte{data[:i], data[i+1:]}
		}
	}
	return [][]byte{data}
}

// constantTimeCompare compares two byte slices in constant time
func constantTimeCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	result := 0
	for i := range a {
		result |= int(a[i]) ^ int(b[i])
	}
	return result == 0
}
