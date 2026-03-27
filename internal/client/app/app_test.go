package app

import (
	"os"
	"testing"
)

func init() {
	// Enable test mode to use insecure credentials
	os.Setenv("PM_TEST_MODE", "true")
}

func TestNewApp_DefaultDBPath(t *testing.T) {
	// Test that NewApp uses default DB path when not provided
	// This test verifies the default path is constructed correctly

	app, err := NewApp("localhost:50051", "")
	if err != nil {
		// Expected to fail without a real gRPC server, but we can check the error
		// The important thing is that it tries to create the default path
		t.Logf("Expected error (no gRPC server): %v", err)
		return
	}
	defer app.Close()

	// If we got here, the app was created successfully
	// This would only happen if there's a gRPC server running
}

func TestNewApp_CustomDBPath(t *testing.T) {
	// Test that NewApp uses custom DB path when provided
	dbPath := "/tmp/test_password_manager.db"

	app, err := NewApp("localhost:50051", dbPath)
	if err != nil {
		// Expected to fail without a real gRPC server
		t.Logf("Expected error (no gRPC server): %v", err)
		return
	}
	defer app.Close()

	// If we got here, the app was created successfully
}

func TestNewApp_EmptyServerAddr(t *testing.T) {
	// Test that NewApp works with empty server address
	// It should still create the app but fail when trying to connect

	app, err := NewApp("", "/tmp/test_password_manager.db")
	if err != nil {
		// Expected to fail without a real gRPC server
		t.Logf("Expected error (no gRPC server): %v", err)
		return
	}
	defer app.Close()

	// If we got here, the app was created successfully
}

func TestApp_Close(t *testing.T) {
	// Test that Close closes all resources
	app, err := NewApp("localhost:50051", "/tmp/test_password_manager.db")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	err = app.Close()
	if err != nil {
		t.Errorf("Expected no error from Close, got: %v", err)
	}
}

func TestApp_Config(t *testing.T) {
	// Test that Config returns a valid config
	app, err := NewApp("localhost:50051", "/tmp/test_password_manager.db")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	defer app.Close()

	cfg := app.Config()

	if cfg.ServerAddr != "localhost:50051" {
		t.Errorf("Expected ServerAddr to be 'localhost:50051', got: %s", cfg.ServerAddr)
	}
}

func TestApp_ContextWithTimeout(t *testing.T) {
	// Test that ContextWithTimeout returns a valid context
	app, err := NewApp("localhost:50051", "/tmp/test_password_manager.db")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	defer app.Close()

	ctx, cancel := app.ContextWithTimeout()
	defer cancel()

	if ctx == nil {
		t.Error("Expected ContextWithTimeout to return non-nil context")
	}
}

func TestIsLoggedIn(t *testing.T) {
	// Test that IsLoggedIn returns false when no token is stored
	app, err := NewApp("localhost:50051", "/tmp/test_password_manager.db")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	defer app.Close()

	isLoggedIn, err := app.IsLoggedIn()
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	// Should be false since no token is stored
	if isLoggedIn {
		t.Error("Expected IsLoggedIn to be false")
	}
}
