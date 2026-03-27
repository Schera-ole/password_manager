package config

import (
	"os"
	"time"
)

const (
	defaultTimeout = 10 * time.Second
)

type Config struct {
	ServerAddr string        // grpc-server address
	DBPath     string        // path to db (with db name)
	Timeout    time.Duration // request timeout
}

// NewConfig creates a new Config with timeout from env var or default
func NewConfig(serverAddr, dbPath string) Config {
	cfg := Config{
		ServerAddr: serverAddr,
		DBPath:     dbPath,
		Timeout:    defaultTimeout,
	}

	// Override timeout from environment variable if set
	if envTimeout := os.Getenv("PM_TIMEOUT"); envTimeout != "" {
		if t, err := time.ParseDuration(envTimeout); err == nil {
			cfg.Timeout = t
		}
	}

	return cfg
}
