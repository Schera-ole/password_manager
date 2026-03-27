package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Schera-ole/password_manager/internal/client/crypto"
	"github.com/Schera-ole/password_manager/internal/client/grpc"
	"github.com/Schera-ole/password_manager/internal/shared/models"
	pmpb "github.com/Schera-ole/password_manager/internal/shared/pb/pm"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ListEntries lists all entries for the current user
func (s *cliService) ListEntries(ctx context.Context) ([]models.Entry, error) {
	// Get PM client from gRPC connection
	pmClient := s.app.GRPC.GetPM()

	// Create request
	request := pmpb.ListEntriesRequest_builder{}.Build()

	// Call gRPC service - interceptor will add JWT token automatically
	response, err := pmClient.ListEntries(ctx, request)
	if err != nil {
		// Check if it's a network error
		if !isNetworkError(err) {
			return nil, fmt.Errorf("list entries: %w", err)
		}

		// Try to load from cache
		entries, _, err := s.loadEntriesFromCache(ctx)
		if err != nil {
			return nil, fmt.Errorf("load entries from cache: %w", err)
		}
		return entries, nil
	}

	// Convert response to models.Entry
	entries := make([]models.Entry, 0, len(response.GetEntries()))
	for _, e := range response.GetEntries() {
		entries = append(entries, models.Entry{
			ID:            e.GetId(),
			UserID:        e.GetUserId(),
			Title:         e.GetTitle(),
			Description:   e.GetDescription(),
			Tags:          e.GetTags(),
			Type:          models.EntryType(e.GetEntryType()),
			Meta:          protoStructToMeta(e.GetMeta()),
			EncryptedBlob: e.GetEncryptedBlob(),
			CreatedAt:     e.GetCreatedAt().AsTime(),
			UpdatedAt:     e.GetUpdatedAt().AsTime(),
			ExpiresAt: func() *time.Time {
				if e.GetExpiresAt() != nil {
					t := e.GetExpiresAt().AsTime()
					return &t
				}
				return nil
			}(),
			Version: int64(e.GetVersion()),
		})
	}

	// Save to cache
	if err := s.saveEntriesToCache(ctx, entries); err != nil {
		fmt.Printf("Warning: failed to cache entries: %v\n", err)
	}

	return entries, nil
}

// GetEntry gets a single entry by ID
func (s *cliService) GetEntry(ctx context.Context, entryID string) (models.Entry, error) {
	// Get PM client from gRPC connection
	pmClient := s.app.GRPC.GetPM()

	// Create request
	request := pmpb.GetEntryRequest_builder{EntryId: entryID}.Build()

	// Call gRPC service
	response, err := pmClient.GetEntry(ctx, request)
	if err != nil {
		// Check if it's a network error
		if !isNetworkError(err) {
			return models.Entry{}, fmt.Errorf("get entry: %w", err)
		}

		// Try to load from cache
		encryptedEntry, err := s.app.Store.LoadEncryptedEntry(entryID)
		if err != nil {
			return models.Entry{}, fmt.Errorf("load encrypted entry from cache: %w", err)
		}

		// Get password from context
		password, err := grpc.GetPasswordOrError(ctx)
		if err != nil {
			return models.Entry{}, fmt.Errorf("get password from context: %w", err)
		}

		// Derive encKey from password
		encKey, err := s.deriveEncKey(password)
		if err != nil {
			return models.Entry{}, fmt.Errorf("derive encryption key: %w", err)
		}
		defer crypto.ZeroMemory(encKey)

		// Decrypt and unmarshal entry
		entry, err := s.encryptor.DecryptAndUnmarshalEntry(encKey, encryptedEntry)
		if err != nil {
			return models.Entry{}, fmt.Errorf("decrypt entry: %w", err)
		}

		return entry, nil
	}
	serverEntry := response.GetEntry()
	entry := models.Entry{
		ID:            serverEntry.GetId(),
		UserID:        serverEntry.GetUserId(),
		Title:         serverEntry.GetTitle(),
		Description:   serverEntry.GetDescription(),
		Tags:          serverEntry.GetTags(),
		Type:          models.EntryType(serverEntry.GetEntryType()),
		Meta:          protoStructToMeta(serverEntry.GetMeta()),
		EncryptedBlob: serverEntry.GetEncryptedBlob(),
		CreatedAt:     serverEntry.GetCreatedAt().AsTime(),
		UpdatedAt:     serverEntry.GetUpdatedAt().AsTime(),
		ExpiresAt: func() *time.Time {
			if serverEntry.GetExpiresAt() != nil {
				t := serverEntry.GetExpiresAt().AsTime()
				return &t
			}
			return nil
		}(),
		Version: int64(serverEntry.GetVersion()),
	}

	// Save to cache
	if err := s.saveEntryToCache(ctx, entry); err != nil {
		fmt.Printf("Warning: failed to cache entry: %v\n", err)
	}

	return entry, nil
}

// CreateEntry creates a new entry
func (s *cliService) CreateEntry(ctx context.Context) error {
	// Derive encKey from password in context
	encKey, err := s.getEncKeyFromContext(ctx)
	if err != nil {
		return fmt.Errorf("get encKey: %w", err)
	}

	userID, err := s.loadUserID(ctx)
	if err != nil {
		return fmt.Errorf("get user ID: %w", err)
	}

	entryInput, err := promptForEntryInput()
	if err != nil {
		return fmt.Errorf("prompt for entry: %w", err)
	}

	encryptedBlob, err := s.encryptEntryData(encKey, entryInput.Data)
	if err != nil {
		return err
	}

	// Generate UUID for entry ID
	entryID, err := crypto.GenerateUUID()
	if err != nil {
		return fmt.Errorf("generate UUID: %w", err)
	}

	// Create entry
	entry := &models.Entry{
		ID:            entryID,
		UserID:        userID,
		Title:         entryInput.Title,
		Description:   entryInput.Description,
		Tags:          entryInput.Tags,
		Type:          entryInput.EntryType,
		Meta:          entryInput.Meta,
		EncryptedBlob: encryptedBlob,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		Version:       1,
	}

	// Create entry and save to cache
	return s.createEntryInternal(ctx, entry)
}

// UpdateEntry updates an existing entry
func (s *cliService) UpdateEntry(ctx context.Context, entryID string) error {
	// Derive encKey from password in context
	encKey, err := s.getEncKeyFromContext(ctx)
	if err != nil {
		return fmt.Errorf("get encKey: %w", err)
	}

	userID, err := s.loadUserID(ctx)
	if err != nil {
		return fmt.Errorf("get user ID: %w", err)
	}

	existingEntry, err := s.getEntryFromServerOrCache(ctx, entryID, encKey)
	if err != nil {
		return err
	}

	if existingEntry == nil {
		return fmt.Errorf("entry not found: %s", entryID)
	}

	// Prompt for updated entry data
	fmt.Printf("\n--- Current Entry ---\n")
	fmt.Printf("ID: %s\n", existingEntry.ID)
	fmt.Printf("Title: %s\n", existingEntry.Title)
	fmt.Printf("Description: %s\n", existingEntry.Description)
	fmt.Printf("Type: %s\n", formatEntryTypeForUpdate(existingEntry.Type))
	fmt.Printf("Tags: %s\n", formatTagsForUpdate(existingEntry.Tags))
	fmt.Printf("\n--- Enter new values (press Enter to keep current) ---\n")

	// Prompt for updated entry data
	title, err := promptForUpdate("Title", existingEntry.Title)
	if err != nil {
		return fmt.Errorf("read title: %w", err)
	}

	description, err := promptForUpdate("Description", existingEntry.Description)
	if err != nil {
		return fmt.Errorf("read description: %w", err)
	}

	tagsStr, err := promptForUpdate("Tags (comma-separated)", strings.Join(existingEntry.Tags, ", "))
	if err != nil {
		return fmt.Errorf("read tags: %w", err)
	}
	var tags []string
	if tagsStr != "" {
		tags = strings.Split(tagsStr, ",")
		for i, tag := range tags {
			tags[i] = strings.TrimSpace(tag)
		}
		// Filter empty tags
		result := make([]string, 0, len(tags))
		for _, tag := range tags {
			if tag != "" {
				result = append(result, tag)
			}
		}
		tags = result
	}

	// Prompt for entry type
	fmt.Fprintln(os.Stderr, "\nSelect entry type (press Enter to keep current):")
	fmt.Fprintln(os.Stderr, "1) Login")
	fmt.Fprintln(os.Stderr, "2) Text")
	fmt.Fprintln(os.Stderr, "3) Binary")
	fmt.Fprintln(os.Stderr, "4) Card")
	fmt.Fprint(os.Stderr, "Select type: ")
	typeInput, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return fmt.Errorf("read entry type: %w", err)
	}
	typeInput = strings.TrimSpace(typeInput)
	var entryType models.EntryType
	if typeInput != "" {
		switch typeInput {
		case "1":
			entryType = models.EntryTypeLogin
		case "2":
			entryType = models.EntryTypeText
		case "3":
			entryType = models.EntryTypeBinary
		case "4":
			entryType = models.EntryTypeCard
		default:
			return fmt.Errorf("invalid entry type")
		}
	} else {
		entryType = existingEntry.Type
	}

	// Prompt for meta (simplified - just show current and allow override)
	fmt.Fprintln(os.Stderr, "\n--- Meta (key=value pairs, press Enter to keep current) ---")
	for k, v := range existingEntry.Meta {
		fmt.Printf("  %s=%s\n", k, v)
	}
	fmt.Fprint(os.Stderr, "Enter new meta (empty to keep current): ")
	metaInput, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return fmt.Errorf("read meta: %w", err)
	}
	var meta models.Meta
	metaInput = strings.TrimSpace(metaInput)
	if metaInput != "" {
		meta = make(models.Meta)
		pairs := strings.Split(metaInput, ",")
		for _, pair := range pairs {
			parts := strings.SplitN(pair, "=", 2)
			if len(parts) == 2 {
				meta[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	} else {
		meta = existingEntry.Meta
	}

	// Prompt for data (sensitive - will be encrypted)
	fmt.Fprintln(os.Stderr, "\n--- Data (sensitive, press Enter to keep current) ---")
	var data []byte
	switch entryType {
	case models.EntryTypeLogin:
		fmt.Fprintln(os.Stderr, "Current: [data present]")
		fmt.Fprint(os.Stderr, "Enter new login data (JSON format): ")
	case models.EntryTypeText:
		fmt.Fprintln(os.Stderr, "Current: [data present]")
		fmt.Fprint(os.Stderr, "Enter new text data: ")
	case models.EntryTypeBinary:
		fmt.Fprintln(os.Stderr, "Current: [data present]")
		fmt.Fprint(os.Stderr, "Enter new base64-encoded binary data: ")
	case models.EntryTypeCard:
		fmt.Fprintln(os.Stderr, "Current: [data present]")
		fmt.Fprint(os.Stderr, "Enter new card data (JSON format): ")
	}
	dataInput, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return fmt.Errorf("read data: %w", err)
	}
	dataInput = strings.TrimSpace(dataInput)
	if dataInput != "" {
		data = []byte(dataInput)
	} else {
		data = existingEntry.EncryptedBlob
	}

	// If data was changed, encrypt it; otherwise keep existing encrypted blob
	var encryptedBlob []byte
	if dataInput != "" {
		encryptedBlob, err = s.encryptEntryData(encKey, data)
		if err != nil {
			return err
		}
	} else {
		encryptedBlob = existingEntry.EncryptedBlob
	}

	// Create updated entry
	updatedEntry := &models.Entry{
		ID:            entryID,
		UserID:        userID,
		Title:         title,
		Description:   description,
		Tags:          tags,
		Type:          entryType,
		Meta:          meta,
		EncryptedBlob: encryptedBlob,
		CreatedAt:     existingEntry.CreatedAt,
		UpdatedAt:     time.Now(),
		Version:       existingEntry.Version + 1,
	}

	// Update entry and save to cache
	return s.updateEntryInternal(ctx, updatedEntry)
}

// DeleteEntry deletes an entry by ID
func (s *cliService) DeleteEntry(ctx context.Context, entryID string) error {
	pmClient := s.app.GRPC.GetPM()

	request := pmpb.DeleteEntryRequest_builder{EntryId: entryID}.Build()
	_, err := pmClient.DeleteEntry(ctx, request)
	if err != nil {
		// Check if server is unavailable (network error)
		if !isNetworkError(err) {
			return fmt.Errorf("delete entry: %w", err)
		}
		return fmt.Errorf("server is unavailable. Deletion is not possible. Client is in read-only mode")
	}

	// Delete entry from local cache
	if err := s.app.Store.DeleteEncryptedEntry(entryID); err != nil {
		return fmt.Errorf("delete entry from cache: %w", err)
	}

	return nil
}

// Sync synchronizes entries with the server
func (s *cliService) Sync(ctx context.Context) error {
	pmClient := s.app.GRPC.GetPM()

	// Load last sync time
	lastSync, err := s.app.Store.LoadLastSync()
	if err != nil {
		return fmt.Errorf("load last sync time: %w", err)
	}

	request := pmpb.SyncRequest_builder{Since: timestamppb.New(lastSync)}.Build()

	response, err := pmClient.Sync(ctx, request)
	if err != nil {
		if !isNetworkError(err) {
			return fmt.Errorf("sync: %w", err)
		}
		return fmt.Errorf("server is unavailable. Sync is not possible. Client is in read-only mode")
	}

	updatedCount := 0
	for _, e := range response.GetEntries() {
		entry := models.Entry{
			ID:            e.GetId(),
			UserID:        e.GetUserId(),
			Title:         e.GetTitle(),
			Description:   e.GetDescription(),
			Tags:          e.GetTags(),
			Type:          models.EntryType(e.GetEntryType()),
			Meta:          protoStructToMeta(e.GetMeta()),
			EncryptedBlob: e.GetEncryptedBlob(),
			CreatedAt:     e.GetCreatedAt().AsTime(),
			UpdatedAt:     e.GetUpdatedAt().AsTime(),
			ExpiresAt: func() *time.Time {
				if e.GetExpiresAt() != nil {
					t := e.GetExpiresAt().AsTime()
					return &t
				}
				return nil
			}(),
			Version: int64(e.GetVersion()),
		}

		// Save to cache
		if err := s.saveEntryToCache(ctx, entry); err != nil {
			fmt.Printf("Warning: failed to cache entry %s: %v\n", entry.ID, err)
		}
		updatedCount++
	}

	// Handle deleted entries
	deletedCount := 0
	for _, entryID := range response.GetDeletedEntryIds() {
		if err := s.app.Store.DeleteEncryptedEntry(entryID); err != nil {
			fmt.Printf("Warning: failed to delete entry from cache: %v\n", err)
		} else {
			deletedCount++
		}
	}

	// Update last sync time
	newLastSync := time.Now()
	if err := s.app.Store.SaveLastSync(newLastSync); err != nil {
		return fmt.Errorf("save last sync time: %w", err)
	}

	fmt.Printf("Sync completed. Updated: %d, Deleted: %d entries. Last sync time: %s\n", updatedCount, deletedCount, newLastSync.Format(time.RFC3339))
	return nil
}
