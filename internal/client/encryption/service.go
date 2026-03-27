// Package encryption provides a unified interface for all encryption operations
package encryption

import (
	"encoding/json"
	"fmt"

	"github.com/Schera-ole/password_manager/internal/client/crypto"
	"github.com/Schera-ole/password_manager/internal/shared/models"
)

// Service handles all encryption-related operations
type Service struct {
	// Dependencies would be injected here
}

// NewService creates a new encryption service
func NewService() *Service {
	return &Service{}
}

// EncryptEntry encrypts entry data using the provided key
func (s *Service) EncryptEntry(encKey []byte, data []byte) ([]byte, error) {
	encryptor := crypto.NewEncryptorFromKey(encKey)
	encryptedBlob, err := encryptor.Encrypt(data)
	if err != nil {
		return nil, fmt.Errorf("encrypt data: %w", err)
	}
	return encryptedBlob, nil
}

// DecryptEntry decrypts entry data using the provided key
func (s *Service) DecryptEntry(encKey []byte, encryptedData []byte) ([]byte, error) {
	if len(encryptedData) < crypto.NonceSize {
		return nil, fmt.Errorf("encrypted data too short")
	}

	encryptor := crypto.NewEncryptorFromKey(encKey)
	return encryptor.Decrypt(encryptedData)
}

// EncryptAndMarshalEntry encrypts and marshals an entry
func (s *Service) EncryptAndMarshalEntry(encKey []byte, entry models.Entry) ([]byte, error) {
	data, err := json.Marshal(entry)
	if err != nil {
		return nil, fmt.Errorf("marshal entry: %w", err)
	}

	return s.EncryptEntry(encKey, data)
}

// DecryptAndUnmarshalEntry decrypts and unmarshals an entry
func (s *Service) DecryptAndUnmarshalEntry(encKey []byte, encryptedData []byte) (models.Entry, error) {
	var entry models.Entry

	decrypted, err := s.DecryptEntry(encKey, encryptedData)
	if err != nil {
		return entry, fmt.Errorf("decrypt entry: %w", err)
	}

	if err := json.Unmarshal(decrypted, &entry); err != nil {
		return entry, fmt.Errorf("unmarshal entry: %w", err)
	}

	return entry, nil
}

// DeriveEncKey derives encryption key from password and salt
func (s *Service) DeriveEncKey(password string, salt []byte) ([]byte, error) {
	encKey, err := crypto.DeriveKey(password, salt)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}
	return encKey, nil
}

// DecryptEncSalt decrypts enc_salt_enc using password and static_salt
func (s *Service) DecryptEncSalt(encSaltEnc []byte, password string, staticSalt []byte) ([]byte, error) {
	// Derive masterKey from password and static_salt
	masterKey, err := s.DeriveEncKey(password, staticSalt)
	if err != nil {
		return nil, fmt.Errorf("derive master key: %w", err)
	}
	defer crypto.ZeroMemory(masterKey)

	// Decrypt enc_salt_enc using password and static_salt
	encSalt, err := crypto.DecryptEncSalt(encSaltEnc, password, staticSalt)
	if err != nil {
		return nil, fmt.Errorf("decrypt enc salt: %w", err)
	}

	return encSalt, nil
}
