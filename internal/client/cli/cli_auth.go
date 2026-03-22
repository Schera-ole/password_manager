package cli

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Schera-ole/password_manager/internal/client/crypto"
	"github.com/Schera-ole/password_manager/internal/client/grpc"
	"github.com/Schera-ole/password_manager/internal/shared/models"
	authpb "github.com/Schera-ole/password_manager/internal/shared/pb/auth"
	pmpb "github.com/Schera-ole/password_manager/internal/shared/pb/pm"
	"github.com/golang-jwt/jwt/v5"
)

// Register registers a new user
func (s *cliService) Register(email string, password string) error {
	// Generate static salt - stored in plaintext, used for key derivation
	staticSalt, err := crypto.GenerateStaticSalt()
	if err != nil {
		return fmt.Errorf("generate static_salt: %w", err)
	}
	defer crypto.ZeroMemory(staticSalt)

	// Save static_salt to store
	if err := s.app.Store.SaveStaticSalt(staticSalt); err != nil {
		return fmt.Errorf("save static_salt: %w", err)
	}

	// Generate password salt (pwd_salt) for hashing
	pwdSalt, err := crypto.GeneratePwdSalt()
	if err != nil {
		return fmt.Errorf("generate pwd_salt: %w", err)
	}
	defer crypto.ZeroMemory(pwdSalt)

	// Hash password using Argon2id
	hash, err := crypto.HashPassword(password, pwdSalt)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	defer crypto.ZeroMemory(hash)

	// Format password_hash as base64(salt)$base64(hash)
	passwordHash := crypto.FormatPasswordHash(pwdSalt, hash)

	request := authpb.RegisterRequest_builder{
		Email:        email,
		PasswordHash: passwordHash,
	}.Build()

	client := s.app.GRPC
	authClient := client.GetAuth()
	_, err = authClient.Register(s.app.Context(), request)
	if err != nil {
		return fmt.Errorf("register on server: %w", err)
	}

	return nil
}

// Login logs in an existing user
func (s *cliService) Login(email string, password string) error {
	// Clear all existing data before logging in to ensure user isolation
	if err := s.app.Store.ClearAllData(); err != nil {
		return fmt.Errorf("clear existing data: %w", err)
	}

	// Load static_salt from store (or generate new one for new user)
	staticSalt, err := s.app.Store.LoadStaticSalt()
	fmt.Printf("  StaticSalt: %s\n", staticSalt)
	if err != nil {
		// Generate new static salt if not found
		staticSalt, err = crypto.GenerateStaticSalt()
		fmt.Printf("  StaticSalt: %s\n", staticSalt)
		if err != nil {
			return fmt.Errorf("generate static_salt: %w", err)
		}
		defer crypto.ZeroMemory(staticSalt)

		// Save static_salt to store
		if err := s.app.Store.SaveStaticSalt(staticSalt); err != nil {
			return fmt.Errorf("save static_salt: %w", err)
		}
	}

	// Derive masterKey from password and static_salt
	masterKey, err := s.encryptor.DeriveEncKey(password, staticSalt)
	if err != nil {
		return fmt.Errorf("derive masterKey: %w", err)
	}
	defer crypto.ZeroMemory(masterKey)

	// Generate device ID (using static salt as device identifier). Use base64 encoding of static salt as device ID
	deviceID := base64.StdEncoding.EncodeToString(staticSalt)
	defer crypto.ZeroMemory(staticSalt)

	request := authpb.LoginRequest_builder{
		Email:    email,
		Password: password,
		DeviceId: deviceID,
	}.Build()

	client := s.app.GRPC
	authClient := client.GetAuth()
	response, err := authClient.Login(s.app.Context(), request)
	if err != nil {
		return fmt.Errorf("login on server: %w", err)
	}

	// enc_salt from server response - save it encrypted with masterKey
	encSaltFromServer := []byte(response.GetEncSalt())

	// Encrypt enc_salt with masterKey
	encSaltEnc, err := s.encryptor.EncryptEntry(masterKey, encSaltFromServer)
	if err != nil {
		return fmt.Errorf("encrypt enc_salt: %w", err)
	}
	defer crypto.ZeroMemory(encSaltEnc)

	if err := s.app.Store.SaveEncSaltEnc(encSaltEnc); err != nil {
		return fmt.Errorf("save enc_salt_enc: %w", err)
	}

	// Derive encKey from password and enc_salt from server
	encKey, err := s.encryptor.DeriveEncKey(password, encSaltFromServer)
	if err != nil {
		return fmt.Errorf("derive encKey: %w", err)
	}
	defer crypto.ZeroMemory(encKey)

	// Encrypt and save access_token with encKey
	encryptedAccessToken, err := s.encryptor.EncryptEntry(encKey, []byte(response.GetAccessToken()))
	if err != nil {
		return fmt.Errorf("encrypt access_token: %w", err)
	}
	defer crypto.ZeroMemory(encryptedAccessToken)

	if err := s.app.Store.SaveEncryptedToken("access_token", encryptedAccessToken); err != nil {
		return fmt.Errorf("save access_token: %w", err)
	}

	return nil
}

// Logout logs out the current user
func (s *cliService) Logout() error {
	// Load static_salt from store to get device ID
	staticSalt, err := s.app.Store.LoadStaticSalt()
	if err != nil {
		return fmt.Errorf("load static_salt: %w", err)
	}
	defer crypto.ZeroMemory(staticSalt)

	// Derive device ID from static salt
	deviceID := base64.StdEncoding.EncodeToString(staticSalt)

	// Send logout request to server to revoke access token
	request := authpb.LogoutRequest_builder{
		DeviceId: deviceID,
	}.Build()
	client := s.app.GRPC
	authClient := client.GetAuth()
	if _, err := authClient.Logout(s.app.Context(), request); err != nil {
		// Log the error but continue with local cleanup
		fmt.Fprintf(os.Stderr, "Warning: failed to revoke token on server: %v\n", err)
	}

	if err := s.app.Store.ClearAllData(); err != nil {
		return fmt.Errorf("clear all data: %w", err)
	}

	return nil
}

// GetJWT gets the JWT token from the encrypted store
func (s *cliService) GetJWT(password string) (string, error) {
	// Load static_salt from store
	staticSalt, err := s.app.Store.LoadStaticSalt()
	if err != nil {
		return "", fmt.Errorf("load static_salt: %w", err)
	}
	defer crypto.ZeroMemory(staticSalt)

	// Derive masterKey from password and static_salt
	masterKey, err := s.encryptor.DeriveEncKey(password, staticSalt)
	if err != nil {
		return "", fmt.Errorf("derive masterKey: %w", err)
	}
	defer crypto.ZeroMemory(masterKey)

	// Load and decrypt enc_salt_enc to get enc_salt
	encSaltEnc, err := s.app.Store.LoadEncSaltEnc()
	if err != nil {
		return "", fmt.Errorf("load enc_salt_enc: %w", err)
	}
	if len(encSaltEnc) < crypto.NonceSize {
		return "", fmt.Errorf("enc_salt_enc not found or invalid")
	}

	// Decrypt enc_salt_enc using password and static_salt
	encSalt, err := s.encryptor.DecryptEncSalt(encSaltEnc, password, staticSalt)
	if err != nil {
		return "", fmt.Errorf("decrypt enc_salt: %w", err)
	}
	defer crypto.ZeroMemory(encSalt)

	// Derive encKey from password and enc_salt
	encKey, err := s.encryptor.DeriveEncKey(password, encSalt)
	if err != nil {
		return "", fmt.Errorf("derive encKey: %w", err)
	}
	defer crypto.ZeroMemory(encKey)

	// Load and decrypt access_token
	encryptedToken, err := s.app.Store.LoadEncryptedToken("access_token")
	if err != nil {
		return "", fmt.Errorf("load access_token: %w", err)
	}
	if encryptedToken == nil || len(encryptedToken) < crypto.NonceSize {
		return "", fmt.Errorf("access_token not found or invalid")
	}

	// Decrypt access_token with encKey
	decryptedToken, err := s.encryptor.DecryptEntry(encKey, encryptedToken)
	if err != nil {
		return "", fmt.Errorf("decrypt access_token: %w", err)
	}
	defer crypto.ZeroMemory(decryptedToken)

	return string(decryptedToken), nil
}

// deriveEncKey derives encKey from password and enc_salt
func (s *cliService) deriveEncKey(password string) ([]byte, error) {
	// Load static_salt from store
	staticSalt, err := s.app.Store.LoadStaticSalt()
	if err != nil {
		return nil, fmt.Errorf("load static_salt: %w", err)
	}
	defer crypto.ZeroMemory(staticSalt)

	// Derive masterKey from password and static_salt
	masterKey, err := s.encryptor.DeriveEncKey(password, staticSalt)
	if err != nil {
		return nil, fmt.Errorf("derive masterKey: %w", err)
	}
	defer crypto.ZeroMemory(masterKey)

	// Load and decrypt enc_salt_enc to get enc_salt
	encSaltEnc, err := s.app.Store.LoadEncSaltEnc()
	if err != nil {
		return nil, fmt.Errorf("load enc_salt_enc: %w", err)
	}
	if len(encSaltEnc) < crypto.NonceSize {
		return nil, fmt.Errorf("enc_salt_enc not found or invalid")
	}

	// Decrypt enc_salt_enc using password and static_salt
	encSalt, err := s.encryptor.DecryptEncSalt(encSaltEnc, password, staticSalt)
	if err != nil {
		return nil, fmt.Errorf("decrypt enc_salt: %w", err)
	}
	defer crypto.ZeroMemory(encSalt)

	// Derive encKey from password and enc_salt
	encKey, err := s.encryptor.DeriveEncKey(password, encSalt)
	if err != nil {
		return nil, fmt.Errorf("derive encKey: %w", err)
	}
	defer crypto.ZeroMemory(encKey)

	return encKey, nil
}

// getEncKeyFromContext gets password from context and derives encKey from it
func (s *cliService) getEncKeyFromContext(ctx context.Context) ([]byte, error) {
	password, err := grpc.GetPasswordOrError(ctx)
	if err != nil {
		return nil, fmt.Errorf("get password: %w", err)
	}
	defer crypto.ZeroMemory([]byte(password))

	encKey, err := s.deriveEncKey(password)
	if err != nil {
		return nil, fmt.Errorf("derive encKey: %w", err)
	}
	defer crypto.ZeroMemory(encKey)

	return encKey, nil
}

// loadUserID loads the user ID from the access token or store
func (s *cliService) loadUserID(ctx context.Context) (string, error) {
	// Derive encKey from password in context
	encKey, err := s.getEncKeyFromContext(ctx)
	if err != nil {
		return "", fmt.Errorf("get encKey: %w", err)
	}

	// Load and decrypt access token
	encryptedToken, err := s.app.Store.LoadEncryptedToken("access_token")
	if err != nil {
		return "", fmt.Errorf("load access_token: %w", err)
	}
	if encryptedToken == nil || len(encryptedToken) < crypto.NonceSize {
		return "", fmt.Errorf("access_token not found")
	}

	// Decrypt access token
	encryptor := crypto.NewEncryptorFromKey(encKey)
	decryptedToken, err := encryptor.Decrypt(encryptedToken)
	if err != nil {
		return "", fmt.Errorf("decrypt access_token: %w", err)
	}
	defer crypto.ZeroMemory(decryptedToken)

	// Parse JWT and extract user_id claim
	token, _, err := new(jwt.Parser).ParseUnverified(string(decryptedToken), jwt.MapClaims{})
	if err != nil {
		return "", fmt.Errorf("parse JWT: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("invalid JWT claims")
	}

	userID, ok := claims["user_id"].(string)
	if !ok {
		return "", fmt.Errorf("user_id claim not found or not string")
	}

	return userID, nil
}

// saveEntryToCache saves a single entry to BoltDB cache (encrypted with encKey)
func (s *cliService) saveEntryToCache(ctx context.Context, entry models.Entry) error {
	// Derive encKey from password in context
	encKey, err := s.getEncKeyFromContext(ctx)
	if err != nil {
		return fmt.Errorf("get encKey: %w", err)
	}

	// Encrypt and marshal entry
	encrypted, err := s.encryptor.EncryptAndMarshalEntry(encKey, entry)
	if err != nil {
		return fmt.Errorf("encrypt entry: %w", err)
	}

	// Save to cache
	return s.app.Store.SaveEncryptedEntry(entry.ID, encrypted)
}

// loadEntriesFromCache loads entries from BoltDB cache
func (s *cliService) loadEntriesFromCache(ctx context.Context) ([]models.Entry, time.Time, error) {
	// Derive encKey from password in context
	encKey, err := s.getEncKeyFromContext(ctx)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("get encKey: %w", err)
	}

	entriesMap, lastSync, err := s.app.Store.LoadEncryptedEntries()
	if err != nil {
		return nil, time.Time{}, err
	}

	entries := make([]models.Entry, 0, len(entriesMap))
	for _, encrypted := range entriesMap {
		// Decrypt and unmarshal entry
		entry, err := s.encryptor.DecryptAndUnmarshalEntry(encKey, encrypted)
		if err != nil {
			continue
		}
		entries = append(entries, entry)
	}

	return entries, lastSync, nil
}

// saveEntriesToCache saves entries to BoltDB cache (encrypted with encKey)
func (s *cliService) saveEntriesToCache(ctx context.Context, entries []models.Entry) error {
	// Derive encKey from password in context
	encKey, err := s.getEncKeyFromContext(ctx)
	if err != nil {
		return fmt.Errorf("get encKey: %w", err)
	}

	entriesMap := make(map[string][]byte)
	for _, entry := range entries {
		// Encrypt and marshal entry
		encrypted, err := s.encryptor.EncryptAndMarshalEntry(encKey, entry)
		if err != nil {
			return fmt.Errorf("encrypt entry: %w", err)
		}

		entriesMap[entry.ID] = encrypted
	}

	// Save to cache
	return s.app.Store.SaveEncryptedEntries(entriesMap, time.Now())
}

// saveEntryToCacheWithResult saves entry to cache and prints success message
func (s *cliService) saveEntryToCacheWithResult(ctx context.Context, entry *models.Entry) error {
	if err := s.saveEntryToCache(ctx, *entry); err != nil {
		fmt.Printf("Warning: failed to cache entry: %v\n", err)
	}
	fmt.Printf("Entry saved successfully!\n")
	fmt.Printf("ID: %s\n", entry.ID)
	fmt.Printf("Title: %s\n", entry.Title)
	if entry.Description != "" {
		fmt.Printf("Description: %s\n", entry.Description)
	}
	if len(entry.Tags) > 0 {
		fmt.Printf("Tags: %s\n", strings.Join(entry.Tags, ", "))
	}
	return nil
}

// encryptEntryData encrypts entry data using encKey
func (s *cliService) encryptEntryData(encKey []byte, data []byte) ([]byte, error) {
	encryptedBlob, err := s.encryptor.EncryptEntry(encKey, data)
	if err != nil {
		return nil, fmt.Errorf("encrypt data: %w", err)
	}
	defer crypto.ZeroMemory(encryptedBlob)
	return encryptedBlob, nil
}

// createEntryInternal creates an entry with the given data and sends to server
func (s *cliService) createEntryInternal(ctx context.Context, entry *models.Entry) error {
	protoEntry := entryToProto(entry)
	pmClient := s.app.GRPC.GetPM()
	request := pmpb.CreateEntryRequest_builder{Entry: protoEntry}.Build()
	_, err := pmClient.CreateEntry(ctx, request)
	if err != nil {
		if !isNetworkError(err) {
			return fmt.Errorf("create entry: %w", err)
		}
		if err := s.saveEntryToCache(ctx, *entry); err != nil {
			fmt.Printf("Warning: failed to cache entry for offline sync: %v\n", err)
		}
		return fmt.Errorf("server is unavailable. Entry saved locally for later sync")
	}
	return s.saveEntryToCacheWithResult(ctx, entry)
}

// updateEntryInternal updates an entry with the given data and sends to server
func (s *cliService) updateEntryInternal(ctx context.Context, entry *models.Entry) error {
	protoEntry := entryToProto(entry)
	pmClient := s.app.GRPC.GetPM()
	request := pmpb.UpdateEntryRequest_builder{Entry: protoEntry}.Build()
	_, err := pmClient.UpdateEntry(ctx, request)
	if err != nil {
		if !isNetworkError(err) {
			return fmt.Errorf("update entry: %w", err)
		}
		if err := s.saveEntryToCache(ctx, *entry); err != nil {
			fmt.Printf("Warning: failed to cache entry for offline sync: %v\n", err)
		}
		return fmt.Errorf("server is unavailable. Entry saved locally for later sync")
	}
	return s.saveEntryToCacheWithResult(ctx, entry)
}

// getEntryFromServerOrCache gets entry from server, falls back to cache if unavailable
func (s *cliService) getEntryFromServerOrCache(ctx context.Context, entryID string, encKey []byte) (*models.Entry, error) {
	pmClient := s.app.GRPC.GetPM()
	getRequest := pmpb.GetEntryRequest_builder{EntryId: entryID}.Build()
	getResponse, err := pmClient.GetEntry(ctx, getRequest)

	if err != nil {
		if !isNetworkError(err) {
			return nil, fmt.Errorf("get entry from server: %w", err)
		}

		encryptedEntry, loadErr := s.app.Store.LoadEncryptedEntry(entryID)
		if loadErr != nil {
			return nil, fmt.Errorf("load encrypted entry from cache: %w", loadErr)
		}

		// Decrypt and unmarshal entry
		cachedEntry, decryptErr := s.encryptor.DecryptAndUnmarshalEntry(encKey, encryptedEntry)
		if decryptErr != nil {
			return nil, fmt.Errorf("decrypt entry: %w", decryptErr)
		}
		fmt.Printf("Using cached entry (server unavailable)\n")
		return &cachedEntry, nil
	}

	serverEntry := getResponse.GetEntry()
	return &models.Entry{
		ID:            serverEntry.GetId(),
		UserID:        serverEntry.GetUserId(),
		Title:         serverEntry.GetTitle(),
		Description:   serverEntry.GetDescription(),
		Tags:          serverEntry.GetTags(),
		Type:          models.EntryType(serverEntry.GetEntryType()),
		Meta:          protoStructToMeta(serverEntry.GetMeta()),
		EncryptedBlob: serverEntry.GetEncryptedBlob(),
		CreatedAt:     serverEntry.GetCreatedAt().AsTime(),
		UpdatedAt:     time.Now(),
		Version:       int64(serverEntry.GetVersion()),
	}, nil
}
