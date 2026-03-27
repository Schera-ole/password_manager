// Package repository provides data storage interfaces and implementations for the pm system.
package repository

import (
	"context"
	"time"

	model "github.com/Schera-ole/password_manager/internal/shared/models"
)

// Repository defines the interface for password_manager storage implementations.
type Repository interface {
	// Entry-related methods
	SetEntry(ctx context.Context, entry model.Entry) error
	GetEntry(ctx context.Context, entry_id string) (model.Entry, error)
	GetEntries(ctx context.Context, entryIDs []string) (map[string]model.Entry, error)
	DeleteEntry(ctx context.Context, entry_id string) error
	ListEntries(ctx context.Context, userID string, tags []string) ([]model.Entry, error)

	// Sync-related methods
	GetSyncLog(ctx context.Context, userID string, since time.Time, limit int) ([]model.SyncLog, error)
	AddSyncLog(ctx context.Context, log model.SyncLog) error

	// Ping checks the repository connection
	Ping(ctx context.Context) error

	// Close releases any resources held by the repository
	Close() error

	// Access token-related methods for authentication
	StoreAccessToken(ctx context.Context, userID, deviceID, accessToken string, expiresAt time.Time) error
	GetAccessToken(ctx context.Context, deviceID string) (string, error)
	RevokeAccessToken(ctx context.Context, deviceID string) error
	RevokeAllAccessTokens(ctx context.Context, userID string) error
	GetActiveAccessToken(ctx context.Context, userID, deviceID string) (string, error)
	GetActiveAccessTokens(ctx context.Context, userID string) ([]string, error)

	// User-related methods for authentication
	GetUserByEmail(ctx context.Context, email string) (model.User, error)
	CreateUser(ctx context.Context, user model.User) error
}
