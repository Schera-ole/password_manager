package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

const (
	NonceSize = 12 // Size nonce for AES-GCM
	KeySize   = 32 // Size key (256 bit)
)

// Encryptor - structure for encode data
type Encryptor struct {
	key []byte
}

// NewEncryptor create new encryptor from mater password
func NewEncryptor(password string, salt []byte) (*Encryptor, error) {
	// Create key from password with Argon2id
	key := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, KeySize)
	return &Encryptor{key: key}, nil
}

// Encrypt encrypts data
func (e *Encryptor) Encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Generate random nonce
	nonce := make([]byte, NonceSize)
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	// Encrypt and concatenate nonce + ciphertext + tag
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypted data
func (e *Encryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < NonceSize {
		return nil, errors.New("ciphertext too short")
	}

	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := ciphertext[:NonceSize]
	// other — ciphertext + tag
	data := ciphertext[NonceSize:]

	return gcm.Open(nil, nonce, data, nil)
}

// NewEncryptorFromKey creates a new Encryptor from an existing key
func NewEncryptorFromKey(key []byte) *Encryptor {
	return &Encryptor{key: key}
}

// GeneratePwdSalt generates a random password salt (32 bytes)
func GeneratePwdSalt() ([]byte, error) {
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, fmt.Errorf("generate pwd_salt: %w", err)
	}
	return salt, nil
}

// HashPassword hashes the password using Argon2id
func HashPassword(password string, salt []byte) ([]byte, error) {

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		3,       // iterations
		64*1024, // memory: 64 MB
		4,       // parallelism
		32,      // key length: 32 bytes
	)

	return hash, nil
}

// FormatPasswordHash formats the password hash as base64(salt)$base64(hash)
func FormatPasswordHash(pwdSalt, hash []byte) string {
	saltB64 := base64.StdEncoding.EncodeToString(pwdSalt)
	hashB64 := base64.StdEncoding.EncodeToString(hash)
	return fmt.Sprintf("%s$%s", saltB64, hashB64)
}

// ZeroMemory securely clears a byte slice
func ZeroMemory(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// GenerateStaticSalt generates a static salt (32 bytes) for key derivation
func GenerateStaticSalt() ([]byte, error) {
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, fmt.Errorf("generate static_salt: %w", err)
	}
	return salt, nil
}

// DeriveKey derives a key from password and salt using Argon2id
func DeriveKey(password string, salt []byte) ([]byte, error) {
	// Use Argon2id to derive a 32-byte key
	key := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, KeySize)
	return key, nil
}

// GenerateUUID generates a random UUID v4 string
func GenerateUUID() (string, error) {
	uuid := make([]byte, 16)
	_, err := rand.Read(uuid)
	if err != nil {
		return "", fmt.Errorf("generate uuid: %w", err)
	}
	// Set version 4 (0100xxxx)
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	// Set variant (10xxxxxx)
	uuid[8] = (uuid[8] & 0x3f) | 0x80
	// Format as UUID string
	return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:]), nil
}

// DecryptEncSalt decrypts enc_salt_enc using password and static_salt
func DecryptEncSalt(encSaltEnc []byte, password string, staticSalt []byte) ([]byte, error) {
	// Derive masterKey from password and static_salt
	masterKey, err := DeriveKey(password, staticSalt)
	if err != nil {
		return nil, fmt.Errorf("derive masterKey: %w", err)
	}
	defer ZeroMemory(masterKey)

	// Create encryptor with masterKey and decrypt
	encryptor := NewEncryptorFromKey(masterKey)
	encSalt, err := encryptor.Decrypt(encSaltEnc)
	if err != nil {
		return nil, fmt.Errorf("decrypt enc_salt: %w", err)
	}

	return encSalt, nil
}
