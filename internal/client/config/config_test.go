package config

import (
	"os"
	"testing"
	"time"
)

func TestNewConfig_DefaultValues(t *testing.T) {
	// Test that NewConfig returns a config with default values
	cfg := NewConfig("localhost:50051", "/tmp/test.db")

	if cfg.ServerAddr != "localhost:50051" {
		t.Errorf("Expected ServerAddr to be 'localhost:50051', got: %s", cfg.ServerAddr)
	}

	if cfg.DBPath != "/tmp/test.db" {
		t.Errorf("Expected DBPath to be '/tmp/test.db', got: %s", cfg.DBPath)
	}

	if cfg.Timeout != defaultTimeout {
		t.Errorf("Expected Timeout to be %v, got: %v", defaultTimeout, cfg.Timeout)
	}
}

func TestNewConfig_WithTimeout(t *testing.T) {
	// Test that NewConfig respects the timeout from env var
	os.Setenv("PM_TIMEOUT", "30s")
	defer os.Unsetenv("PM_TIMEOUT")

	cfg := NewConfig("localhost:50051", "/tmp/test.db")

	expectedTimeout := 30 * time.Second
	if cfg.Timeout != expectedTimeout {
		t.Errorf("Expected Timeout to be %v, got: %v", expectedTimeout, cfg.Timeout)
	}
}

func TestNewConfig_WithInvalidTimeout(t *testing.T) {
	// Test that NewConfig falls back to default when env var is invalid
	os.Setenv("PM_TIMEOUT", "invalid")
	defer os.Unsetenv("PM_TIMEOUT")

	cfg := NewConfig("localhost:50051", "/tmp/test.db")

	if cfg.Timeout != defaultTimeout {
		t.Errorf("Expected Timeout to be %v (default), got: %v", defaultTimeout, cfg.Timeout)
	}
}

func TestNewConfig_EmptyServerAddr(t *testing.T) {
	// Test that NewConfig works with empty server address
	cfg := NewConfig("", "/tmp/test.db")

	if cfg.ServerAddr != "" {
		t.Errorf("Expected ServerAddr to be empty, got: %s", cfg.ServerAddr)
	}

	if cfg.DBPath != "/tmp/test.db" {
		t.Errorf("Expected DBPath to be '/tmp/test.db', got: %s", cfg.DBPath)
	}
}

func TestNewConfig_EmptyDBPath(t *testing.T) {
	// Test that NewConfig works with empty DB path
	cfg := NewConfig("localhost:50051", "")

	if cfg.ServerAddr != "localhost:50051" {
		t.Errorf("Expected ServerAddr to be 'localhost:50051', got: %s", cfg.ServerAddr)
	}

	if cfg.DBPath != "" {
		t.Errorf("Expected DBPath to be empty, got: %s", cfg.DBPath)
	}
}

func TestNewConfig_WithAllOptions(t *testing.T) {
	// Test that NewConfig works with all options specified
	os.Setenv("PM_TIMEOUT", "1m30s")
	defer os.Unsetenv("PM_TIMEOUT")

	cfg := NewConfig("grpc.example.com:443", "/var/lib/password_manager/client.db")

	if cfg.ServerAddr != "grpc.example.com:443" {
		t.Errorf("Expected ServerAddr to be 'grpc.example.com:443', got: %s", cfg.ServerAddr)
	}

	if cfg.DBPath != "/var/lib/password_manager/client.db" {
		t.Errorf("Expected DBPath to be '/var/lib/password_manager/client.db', got: %s", cfg.DBPath)
	}

	expectedTimeout := 90 * time.Second
	if cfg.Timeout != expectedTimeout {
		t.Errorf("Expected Timeout to be %v, got: %v", expectedTimeout, cfg.Timeout)
	}
}

func TestNewConfig_WithZeroTimeout(t *testing.T) {
	// Test that NewConfig works with zero timeout
	os.Setenv("PM_TIMEOUT", "0s")
	defer os.Unsetenv("PM_TIMEOUT")

	cfg := NewConfig("localhost:50051", "/tmp/test.db")

	if cfg.Timeout != 0 {
		t.Errorf("Expected Timeout to be 0, got: %v", cfg.Timeout)
	}
}

func TestNewConfig_WithNegativeTimeout(t *testing.T) {
	// Test that NewConfig accepts negative timeout values (Go's time.ParseDuration allows this)
	os.Setenv("PM_TIMEOUT", "-1s")
	defer os.Unsetenv("PM_TIMEOUT")

	cfg := NewConfig("localhost:50051", "/tmp/test.db")

	// Go's time.ParseDuration accepts negative values, so the timeout will be -1s
	expectedTimeout := -1 * time.Second
	if cfg.Timeout != expectedTimeout {
		t.Errorf("Expected Timeout to be %v, got: %v", expectedTimeout, cfg.Timeout)
	}
}
