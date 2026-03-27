package service

import (
	"context"
	"time"

	"github.com/Schera-ole/password_manager/internal/server/auth"
	"github.com/Schera-ole/password_manager/internal/server/repository"
	model "github.com/Schera-ole/password_manager/internal/shared/models"
	authpb "github.com/Schera-ole/password_manager/internal/shared/pb/auth"
)

// CommonService combines UserService and PasswordService for operations
// that require both user management and password entry management.
type CommonService struct {
	userService     *UserService
	passwordService *PasswordService
	repository      repository.Repository
}

// NewCommonService creates a new CommonService with the specified repository.
// Both underlying services are initialized with the same repository instance.
func NewCommonService(repo repository.Repository, tokenMgr auth.TokenManager) *CommonService {
	return &CommonService{
		userService:     NewUserService(repo, tokenMgr),
		passwordService: NewPasswordService(repo),
		repository:      repo,
	}
}

// Register creates a new user in the system using UserService.
func (cs *CommonService) Register(ctx context.Context, req *authpb.RegisterRequest) (*authpb.RegisterResponse, error) {
	return cs.userService.Register(ctx, req)
}

// Login authenticates a user and returns tokens using UserService.
func (cs *CommonService) Login(ctx context.Context, req *authpb.LoginRequest) (*authpb.LoginResponse, error) {
	return cs.userService.Login(ctx, req)
}

// Logout revokes the access token via UserService.
func (cs *CommonService) Logout(ctx context.Context, req *authpb.LogoutRequest) (*authpb.LogoutResponse, error) {
	return cs.userService.Logout(ctx, req)
}

// SetEntry stores a password entry using PasswordService.
func (cs *CommonService) SetEntry(ctx context.Context, entry model.Entry) error {
	return cs.passwordService.SetEntry(ctx, entry)
}

// GetEntry retrieves a password entry using PasswordService.
func (cs *CommonService) GetEntry(ctx context.Context, entryID string) (model.Entry, error) {
	return cs.passwordService.GetEntry(ctx, entryID)
}

// GetEntries retrieves multiple password entries using PasswordService.
func (cs *CommonService) GetEntries(ctx context.Context, entryIDs []string) (map[string]model.Entry, error) {
	return cs.passwordService.GetEntries(ctx, entryIDs)
}

// DeleteEntry removes a password entry using PasswordService.
func (cs *CommonService) DeleteEntry(ctx context.Context, entryID string) error {
	return cs.passwordService.DeleteEntry(ctx, entryID)
}

// ListEntries retrieves all password entries using PasswordService.
func (cs *CommonService) ListEntries(ctx context.Context, userID string, tags []string) ([]model.Entry, error) {
	return cs.passwordService.ListEntries(ctx, userID, tags)
}

// GetSyncLog retrieves sync log entries using Repository.
func (cs *CommonService) GetSyncLog(ctx context.Context, userID string, since time.Time, limit int) ([]model.SyncLog, error) {
	return cs.repository.GetSyncLog(ctx, userID, since, limit)
}

// AddSyncLog adds a sync log entry using Repository.
func (cs *CommonService) AddSyncLog(ctx context.Context, log model.SyncLog) error {
	return cs.repository.AddSyncLog(ctx, log)
}

// Ping checks the database connection health.
func (cs *CommonService) Ping(ctx context.Context) error {
	return cs.repository.Ping(ctx)
}
