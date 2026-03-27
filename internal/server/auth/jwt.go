package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	AccessTokenExpiration = 15 * time.Minute
)

// TokenClaims represents the JWT token claims
type TokenClaims struct {
	UserID   string `json:"user_id"`
	Email    string `json:"email"`
	DeviceID string `json:"device_id,omitempty"`
	Role     string `json:"role,omitempty"`
	jwt.RegisteredClaims
}

// TokenManager handles JWT token generation and validation
type TokenManager interface {
	GenerateAccessToken(userID, email, deviceID string) (string, error)
	ValidateToken(tokenString string) (*TokenClaims, error)
	ExtractDeviceID(tokenString string) (string, error)
}

// JWTTokenManager implements TokenManager using JWT
type JWTTokenManager struct {
	accessTokenSecret []byte
	accessTokenExp    time.Duration
	mu                sync.RWMutex
}

// NewJWTTokenManagerWithSecrets creates a new JWT token manager with the provided secrets
func NewJWTTokenManagerWithSecrets(accessTokenSecret []byte) *JWTTokenManager {
	return &JWTTokenManager{
		accessTokenSecret: accessTokenSecret,
		accessTokenExp:    AccessTokenExpiration,
	}
}

// NewJWTTokenManagerFromConfig creates a new JWT token manager with secrets from config
// Secrets are loaded from base64-encoded strings in config
func NewJWTTokenManagerFromConfig(jwtAccessSecret string) (*JWTTokenManager, error) {
	var accessTokenSecret []byte
	var err error

	if jwtAccessSecret != "" {
		accessTokenSecret, err = Base64DecodeSecret(jwtAccessSecret)
		if err != nil {
			return nil, fmt.Errorf("decode access secret: %w", err)
		}
		if len(accessTokenSecret) != 32 {
			return nil, fmt.Errorf("access secret must be 32 bytes (got %d)", len(accessTokenSecret))
		}
	} else {
		// Generate random secret if not provided
		accessTokenSecret = make([]byte, 32)
		if _, err := rand.Read(accessTokenSecret); err != nil {
			return nil, fmt.Errorf("generate access secret: %w", err)
		}
	}

	return NewJWTTokenManagerWithSecrets(accessTokenSecret), nil
}

// GenerateAccessToken creates a new access token with specific device ID
func (tm *JWTTokenManager) GenerateAccessToken(userID, email, deviceID string) (string, error) {
	claims := &TokenClaims{
		UserID:   userID,
		Email:    email,
		DeviceID: deviceID,
		Role:     "user",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(tm.accessTokenExp)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "password-manager",
			Subject:   userID,
			ID:        uuid.New().String(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(tm.accessTokenSecret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// ValidateToken validates a token and returns its claims
func (tm *JWTTokenManager) ValidateToken(tokenString string) (*TokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return tm.accessTokenSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*TokenClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, jwt.ErrSignatureInvalid
}

// ExtractDeviceID extracts device ID from access token
func (tm *JWTTokenManager) ExtractDeviceID(tokenString string) (string, error) {
	claims, err := tm.ValidateToken(tokenString)
	if err != nil {
		return "", err
	}
	return claims.DeviceID, nil
}

// Base64EncodeSecret encodes a secret key as base64 for storage/transmission
func Base64EncodeSecret(secret []byte) string {
	return base64.StdEncoding.EncodeToString(secret)
}

// Base64DecodeSecret decodes a base64-encoded secret key
func Base64DecodeSecret(encoded string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(encoded)
}
