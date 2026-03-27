package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Schera-ole/password_manager/internal/client/config"
	"github.com/Schera-ole/password_manager/internal/client/grpc"
	"github.com/Schera-ole/password_manager/internal/client/store"
)

// App represents the main application instance
type App struct {
	cfg   config.Config
	Store store.Store
	GRPC  *grpc.Client
}

// NewApp creates a new App instance with gRPC client and BoltDB store
func NewApp(serverAddr, dbPath string) (*App, error) {
	// Set default values if not provided
	if dbPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("user home: %w", err)
		}
		dbPath = filepath.Join(home, ".password_manager", "client.db")
	}

	// Create config with timeout from env var or default
	cfg := config.NewConfig(serverAddr, dbPath)

	// Initialize BoltDB store first (so we can pass it to gRPC client)
	boltStore, err := store.NewBoltStore(dbPath)
	if err != nil {
		return nil, fmt.Errorf("create BoltDB store: %w", err)
	}

	// Initialize gRPC client with store for interceptor
	grpcClient, err := grpc.NewClient(serverAddr, boltStore)
	if err != nil {
		boltStore.Close()
		return nil, fmt.Errorf("create gRPC client: %w", err)
	}

	// Context is created on-demand before gRPC calls to avoid timeout issues
	a := &App{
		cfg:   cfg,
		GRPC:  grpcClient,
		Store: boltStore,
	}
	return a, nil
}

// Close closes all resources
func (a *App) Close() error {
	var err error
	if a.GRPC != nil {
		if closeErr := a.GRPC.Close(); closeErr != nil {
			err = closeErr
		}
	}
	if a.Store != nil {
		if closeErr := a.Store.Close(); closeErr != nil {
			if err == nil {
				err = closeErr
			}
		}
	}
	return err
}

// Config returns the app configuration
func (a *App) Config() config.Config {
	return a.cfg
}

// ContextWithTimeout creates a new context with timeout for gRPC calls
func (a *App) ContextWithTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), a.cfg.Timeout)
}

// IsLoggedIn checks if the user is logged in by verifying stored tokens
func (a *App) IsLoggedIn() (bool, error) {
	token, err := a.Store.LoadToken()
	if err != nil {
		// If token is not found, user is not logged in (not an error)
		if err.Error() == "token not found" {
			return false, nil
		}
		return false, fmt.Errorf("load token: %w", err)
	}
	return len(token) > 0, nil
}
