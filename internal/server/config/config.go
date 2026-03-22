// Package config provides configuration management for the password manager server.
package config

import (
	"flag"
	"fmt"
	"os"
	"time"
)

// ServerConfig holds the configuration settings for the password manager server.
type ServerConfig struct {
	// DatabaseDSN is the data source name for connecting to the PostgreSQL database.
	DatabaseDSN string

	// GRPCServerAddress - grpc server will start on it
	GRPCServerAddress string

	// Database connection pool settings
	// MaxOpenConns - maximum number of open connections to the database
	// Default: 10
	MaxOpenConns int

	// MaxIdleConns - maximum number of idle connections to the database
	// Default: 5
	MaxIdleConns int

	// ConnMaxLifetime - maximum amount of time a connection may be reused
	// Default: 5 minutes
	ConnMaxLifetime time.Duration

	// JWTSecrets - secrets for JWT token signing
	// JWT_ACCESS_SECRET - secret for access tokens (base64 encoded)
	JWTAccessSecret string
}

// NewServerConfig creates a new ServerConfig with default values and parses
func NewServerConfig() (*ServerConfig, error) {
	config := &ServerConfig{
		DatabaseDSN:       "postgres://schera:schera@127.0.0.1:5432/pm",
		GRPCServerAddress: "127.0.0.1:50051",
		MaxOpenConns:      10,
		MaxIdleConns:      5,
		ConnMaxLifetime:   5 * time.Minute,
	}

	databaseDSN := flag.String("d", config.DatabaseDSN, "database dsn")
	grpcServerAddress := flag.String("g", config.GRPCServerAddress, "grpc server address")
	maxOpenConns := flag.Int("max_open_conns", config.MaxOpenConns, "maximum number of open connections to the database")
	maxIdleConns := flag.Int("max_idle_conns", config.MaxIdleConns, "maximum number of idle connections to the database")
	connMaxLifetime := flag.Duration("conn_max_lifetime", config.ConnMaxLifetime, "maximum amount of time a connection may be reused")
	jwtAccessSecret := flag.String("jwt_access_secret", "", "JWT access token secret (base64 encoded)")

	flag.Parse()

	envVars := map[string]*string{
		"GRPC_SERVER_ADDRESS": grpcServerAddress,
		"DATABASE_DSN":        databaseDSN,
		"JWT_ACCESS_SECRET":   jwtAccessSecret,
	}

	for envVar, flag := range envVars {
		if envValue := os.Getenv(envVar); envValue != "" {
			*flag = envValue
		}
	}

	// Read environment variables for connection pool settings
	if envValue := os.Getenv("MAX_OPEN_CONNS"); envValue != "" {
		*maxOpenConns = parseEnvInt(envValue, *maxOpenConns)
	}
	if envValue := os.Getenv("MAX_IDLE_CONNS"); envValue != "" {
		*maxIdleConns = parseEnvInt(envValue, *maxIdleConns)
	}
	if envValue := os.Getenv("CONN_MAX_LIFETIME"); envValue != "" {
		if duration, err := time.ParseDuration(envValue); err == nil {
			*connMaxLifetime = duration
		}
	}

	config.DatabaseDSN = *databaseDSN
	config.GRPCServerAddress = *grpcServerAddress
	config.MaxOpenConns = *maxOpenConns
	config.MaxIdleConns = *maxIdleConns
	config.ConnMaxLifetime = *connMaxLifetime
	config.JWTAccessSecret = *jwtAccessSecret

	return config, nil
}

// parseEnvInt parses a string to int, returning default if parsing fails
func parseEnvInt(value string, defaultValue int) int {
	var result int
	_, err := fmt.Sscanf(value, "%d", &result)
	if err != nil {
		return defaultValue
	}
	return result
}
