package service

import (
	"context"

	"github.com/Schera-ole/password_manager/internal/server/repository"
	model "github.com/Schera-ole/password_manager/internal/shared/models"
)

// PasswordService provides methods for managing passwords.
type PasswordService struct {
	repository repository.Repository
}

// NewPasswordService creates a new PasswordService with the specified repository.
func NewPasswordService(repo repository.Repository) *PasswordService {
	return &PasswordService{repository: repo}
}

func (ps *PasswordService) SetEntry(ctx context.Context, entry model.Entry) error {
	// Store the entry first
	err := ps.repository.SetEntry(ctx, entry)
	if err != nil {
		return err
	}

	// Add sync log entry for synchronization
	log := model.SyncLog{
		UserID:    entry.UserID,
		EntryID:   entry.ID,
		Timestamp: entry.UpdatedAt,
		Version:   entry.Version,
	}
	return ps.repository.AddSyncLog(ctx, log)
}

func (ps *PasswordService) GetEntry(ctx context.Context, entry_id string) (model.Entry, error) {
	return ps.repository.GetEntry(ctx, entry_id)
}

func (ps *PasswordService) GetEntries(ctx context.Context, entryIDs []string) (map[string]model.Entry, error) {
	return ps.repository.GetEntries(ctx, entryIDs)
}

func (ps *PasswordService) DeleteEntry(ctx context.Context, entryID string) error {
	// Get entry first to get user_id and version
	entry, err := ps.repository.GetEntry(ctx, entryID)
	if err != nil {
		return err
	}

	// Delete the entry
	err = ps.repository.DeleteEntry(ctx, entryID)
	if err != nil {
		return err
	}

	// Add sync log entry with version = -1 to mark deletion
	log := model.SyncLog{
		UserID:    entry.UserID,
		EntryID:   entryID,
		Timestamp: entry.UpdatedAt,
		Version:   -1, // Special version to indicate deletion
	}
	return ps.repository.AddSyncLog(ctx, log)
}

func (ps *PasswordService) ListEntries(ctx context.Context, userID string, tags []string) ([]model.Entry, error) {
	return ps.repository.ListEntries(ctx, userID, tags)
}
