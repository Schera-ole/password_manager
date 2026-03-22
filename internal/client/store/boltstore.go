package store

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"go.etcd.io/bbolt"
)

// BoltStore implements Store interface using BoltDB
type BoltStore struct {
	db *bbolt.DB
}

// NewBoltStore creates a new BoltDB store
func NewBoltStore(dbPath string) (*BoltStore, error) {
	// Ensure directory exists
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create db directory: %w", err)
	}

	db, err := bbolt.Open(dbPath, 0600, nil)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	// Create buckets if they don't exist
	if err := db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("tokens"))
		if err != nil {
			return fmt.Errorf("create tokens bucket: %w", err)
		}
		_, err = tx.CreateBucketIfNotExists([]byte("salts"))
		if err != nil {
			return fmt.Errorf("create salts bucket: %w", err)
		}
		_, err = tx.CreateBucketIfNotExists([]byte("cache"))
		if err != nil {
			return fmt.Errorf("create cache bucket: %w", err)
		}
		return nil
	}); err != nil {
		db.Close()
		return nil, err
	}

	return &BoltStore{db: db}, nil
}

// SaveToken saves the authentication token
func (s *BoltStore) SaveToken(tok []byte) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("tokens"))
		return b.Put([]byte("access_token"), tok)
	})
}

// LoadToken loads the authentication token
func (s *BoltStore) LoadToken() ([]byte, error) {
	var token []byte
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("tokens"))
		token = make([]byte, len(b.Get([]byte("access_token"))))
		copy(token, b.Get([]byte("access_token")))
		return nil
	})
	return token, err
}

// SaveStaticSalt saves the static salt
func (s *BoltStore) SaveStaticSalt(salt []byte) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("salts"))
		return b.Put([]byte("static_salt"), salt)
	})
}

// LoadStaticSalt loads the static salt
func (s *BoltStore) LoadStaticSalt() ([]byte, error) {
	var salt []byte
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("salts"))
		salt = make([]byte, len(b.Get([]byte("static_salt"))))
		copy(salt, b.Get([]byte("static_salt")))
		return nil
	})
	return salt, err
}

// SaveEncSaltEnc saves the encrypted enc_salt
func (s *BoltStore) SaveEncSaltEnc(encrypted []byte) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("salts"))
		return b.Put([]byte("enc_salt_enc"), encrypted)
	})
}

// LoadEncSaltEnc loads the encrypted enc_salt
func (s *BoltStore) LoadEncSaltEnc() ([]byte, error) {
	var encrypted []byte
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("salts"))
		encrypted = make([]byte, len(b.Get([]byte("enc_salt_enc"))))
		copy(encrypted, b.Get([]byte("enc_salt_enc")))
		return nil
	})
	return encrypted, err
}

// SaveEncryptedToken saves an encrypted token
func (s *BoltStore) SaveEncryptedToken(key string, encrypted []byte) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("tokens"))
		return b.Put([]byte(key), encrypted)
	})
}

// LoadEncryptedToken loads an encrypted token
func (s *BoltStore) LoadEncryptedToken(key string) ([]byte, error) {
	var encrypted []byte
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("tokens"))
		encrypted = make([]byte, len(b.Get([]byte(key))))
		copy(encrypted, b.Get([]byte(key)))
		return nil
	})
	return encrypted, err
}

// SaveEncryptedEntry saves an encrypted entry to cache
func (s *BoltStore) SaveEncryptedEntry(entryID string, encrypted []byte) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("cache"))
		if err != nil {
			return fmt.Errorf("create cache bucket: %w", err)
		}
		return b.Put([]byte("entry/"+entryID), encrypted)
	})
}

// LoadEncryptedEntry loads an encrypted entry from cache by ID
func (s *BoltStore) LoadEncryptedEntry(entryID string) ([]byte, error) {
	var encrypted []byte
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("cache"))
		if b == nil {
			return fmt.Errorf("cache bucket not found")
		}
		encrypted = make([]byte, len(b.Get([]byte("entry/"+entryID))))
		copy(encrypted, b.Get([]byte("entry/"+entryID)))
		return nil
	})
	return encrypted, err
}

// DeleteEncryptedEntry deletes an encrypted entry from cache by ID
func (s *BoltStore) DeleteEncryptedEntry(entryID string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("cache"))
		if b == nil {
			return fmt.Errorf("cache bucket not found")
		}
		return b.Delete([]byte("entry/" + entryID))
	})
}

// SaveEncryptedEntries saves multiple encrypted entries to cache
func (s *BoltStore) SaveEncryptedEntries(entries map[string][]byte, lastSync time.Time) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("cache"))
		if err != nil {
			return fmt.Errorf("create cache bucket: %w", err)
		}

		// Save each entry
		for entryID, encrypted := range entries {
			if err := b.Put([]byte("entry/"+entryID), encrypted); err != nil {
				return fmt.Errorf("save entry: %w", err)
			}
		}

		// Save metadata
		meta := struct {
			LastSync time.Time `json:"last_sync"`
			Count    int       `json:"count"`
		}{LastSync: lastSync, Count: len(entries)}
		metaBytes, err := json.Marshal(meta)
		if err != nil {
			return fmt.Errorf("marshal meta: %w", err)
		}
		return b.Put([]byte("meta"), metaBytes)
	})
}

// LoadEncryptedEntries loads all encrypted entries from cache
func (s *BoltStore) LoadEncryptedEntries() (map[string][]byte, time.Time, error) {
	entries := make(map[string][]byte)
	var lastSync time.Time

	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("cache"))
		if b == nil {
			return fmt.Errorf("cache bucket not found")
		}

		// Load metadata
		metaBytes := b.Get([]byte("meta"))
		if metaBytes != nil {
			var meta struct {
				LastSync time.Time `json:"last_sync"`
				Count    int       `json:"count"`
			}
			if err := json.Unmarshal(metaBytes, &meta); err == nil {
				lastSync = meta.LastSync
			}
		}

		// Iterate over all entries
		cursor := b.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			if string(k) == "meta" {
				continue
			}
			if len(k) < 6 || string(k[:6]) != "entry/" {
				continue
			}
			entryID := string(k[6:])
			entries[entryID] = v
		}

		return nil
	})

	return entries, lastSync, err
}

// SaveLastSync saves the last sync time
func (s *BoltStore) SaveLastSync(t time.Time) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("cache"))
		if err != nil {
			return fmt.Errorf("create cache bucket: %w", err)
		}
		meta := struct {
			LastSync time.Time `json:"last_sync"`
		}{LastSync: t}
		metaBytes, err := json.Marshal(meta)
		if err != nil {
			return fmt.Errorf("marshal meta: %w", err)
		}
		return b.Put([]byte("last_sync"), metaBytes)
	})
}

// LoadLastSync loads the last sync time
func (s *BoltStore) LoadLastSync() (time.Time, error) {
	var lastSync time.Time
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("cache"))
		if b == nil {
			return fmt.Errorf("cache bucket not found")
		}
		metaBytes := b.Get([]byte("last_sync"))
		if metaBytes != nil {
			var meta struct {
				LastSync time.Time `json:"last_sync"`
			}
			if err := json.Unmarshal(metaBytes, &meta); err == nil {
				lastSync = meta.LastSync
			}
		}
		return nil
	})
	return lastSync, err
}

// Close closes the database connection
func (s *BoltStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// SaveEncKey saves the encrypted master key
func (s *BoltStore) SaveEncKey(key []byte) error {
	encoded := base64.StdEncoding.EncodeToString(key)
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("cache"))
		return b.Put([]byte("enc_key"), []byte(encoded))
	})
}

// LoadEncKey loads the encrypted master key
func (s *BoltStore) LoadEncKey() ([]byte, error) {
	var encoded string
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("cache"))
		encoded = string(b.Get([]byte("enc_key")))
		return nil
	})
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(encoded)
}

// ClearAllData clears all stored data including cache
func (s *BoltStore) ClearAllData() error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		// Clear tokens bucket
		tokensBucket := tx.Bucket([]byte("tokens"))
		if tokensBucket != nil {
			tokensBucket.Delete([]byte("access_token"))
			tokensBucket.Delete([]byte("refresh_token"))
		}

		// Clear salts bucket
		saltsBucket := tx.Bucket([]byte("salts"))
		if saltsBucket != nil {
			saltsBucket.Delete([]byte("enc_salt"))
			saltsBucket.Delete([]byte("pwd_salt"))
			saltsBucket.Delete([]byte("enc_salt_enc"))
		}

		// Clear cache bucket
		cacheBucket := tx.Bucket([]byte("cache"))
		if cacheBucket != nil {
			cacheBucket.Delete([]byte("data"))
			cacheBucket.Delete([]byte("enc_key"))
			cacheBucket.Delete([]byte("last_sync"))

			// Delete all entry entries
			cursor := cacheBucket.Cursor()
			for k, _ := cursor.First(); k != nil; k, _ = cursor.Next() {
				if string(k[:6]) == "entry/" {
					cacheBucket.Delete(k)
				}
			}
		}

		return nil
	})
}
