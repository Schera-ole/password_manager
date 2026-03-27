package store

import (
	"time"
)

type Store interface {
	// Token
	SaveToken(tok []byte) error
	LoadToken() ([]byte, error)

	// Static salt (plaintext, for key derivation)
	SaveStaticSalt(salt []byte) error
	LoadStaticSalt() ([]byte, error)

	// Encrypted enc_salt (encrypted with masterKey)
	SaveEncSaltEnc(encrypted []byte) error
	LoadEncSaltEnc() ([]byte, error)

	// Encrypted tokens (encrypted with encKey)
	SaveEncryptedToken(key string, encrypted []byte) error
	LoadEncryptedToken(key string) ([]byte, error)

	// Encrypted entries cache (entries are encrypted with encKey before saving)
	SaveEncryptedEntry(entryID string, encrypted []byte) error
	LoadEncryptedEntry(entryID string) ([]byte, error)
	DeleteEncryptedEntry(entryID string) error
	SaveEncryptedEntries(entries map[string][]byte, lastSync time.Time) error
	LoadEncryptedEntries() (map[string][]byte, time.Time, error)

	// Last sync time for tracking when the client last synced with the server
	SaveLastSync(time.Time) error
	LoadLastSync() (time.Time, error)

	// Server certificate hash for TLS cert pinning
	SaveServerCertHash(serverAddr, hash string) error
	LoadServerCertHash(serverAddr string) (string, error)

	// Close DB
	Close() error

	// ClearAllData clears all stored data including cache
	ClearAllData() error
}
