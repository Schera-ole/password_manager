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
	cfg    config.Config
	Store  store.Store
	GRPC   *grpc.Client
	ctx    context.Context
	cancel context.CancelFunc
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

	// Create context with timeout from config
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)

	a := &App{
		cfg:    cfg,
		GRPC:   grpcClient,
		Store:  boltStore,
		ctx:    ctx,
		cancel: cancel,
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
	// Cancel the context to release resources
	if a.cancel != nil {
		a.cancel()
	}
	return err
}

// Config returns the app configuration
func (a *App) Config() config.Config {
	return a.cfg
}

// Context returns the app context with timeout
func (a *App) Context() context.Context {
	return a.ctx
}

// IsLoggedIn checks if the user is logged in by verifying stored tokens
func (a *App) IsLoggedIn() (bool, error) {
	token, err := a.Store.LoadToken()
	if err != nil {
		return false, fmt.Errorf("load token: %w", err)
	}
	return len(token) > 0, nil
}
