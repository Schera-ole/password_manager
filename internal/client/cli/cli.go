package cli

import (
	"context"

	"github.com/Schera-ole/password_manager/internal/client/app"
	"github.com/Schera-ole/password_manager/internal/client/encryption"
	"github.com/Schera-ole/password_manager/internal/shared/models"
)

type CLIService interface {
	Register(email string, password string) error
	Login(email string, password string) error
	Logout() error
	GetJWT(password string) (string, error)
	ListEntries(ctx context.Context) ([]models.Entry, error)
	GetEntry(ctx context.Context, entryID string) (models.Entry, error)
	CreateEntry(ctx context.Context) error
	UpdateEntry(ctx context.Context, entryID string) error
	DeleteEntry(ctx context.Context, entryID string) error
	Sync(ctx context.Context) error
}

type cliService struct {
	app       *app.App
	encryptor *encryption.Service
}

func NewCLIService(appInstance *app.App) CLIService {
	return &cliService{
		app:       appInstance,
		encryptor: encryption.NewService(),
	}
}
