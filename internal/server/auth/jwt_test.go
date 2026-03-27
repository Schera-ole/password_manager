package auth

import (
	"testing"
	"time"
)

func TestJWTTokenManager_GenerateAccessToken(t *testing.T) {
	tm := NewJWTTokenManagerForTesting()

	token, err := tm.GenerateAccessToken("user123", "test@example.com", "device456")
	if err != nil {
		t.Fatalf("GenerateAccessToken failed: %v", err)
	}

	if token == "" {
		t.Error("Expected non-empty token")
	}
}

func TestJWTTokenManager_ValidateToken(t *testing.T) {
	tm := NewJWTTokenManagerForTesting()

	// Generate a token
	token, err := tm.GenerateAccessToken("user123", "test@example.com", "device456")
	if err != nil {
		t.Fatalf("GenerateAccessToken failed: %v", err)
	}

	// Validate the token
	claims, err := tm.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken failed: %v", err)
	}

	if claims.Email != "test@example.com" {
		t.Errorf("Expected email 'test@example.com', got '%s'", claims.Email)
	}

	if claims.DeviceID != "device456" {
		t.Errorf("Expected device_id 'device456', got '%s'", claims.DeviceID)
	}

	if claims.ExpiresAt.Time.Sub(time.Now()) > AccessTokenExpiration {
		t.Error("Token expiration is too long")
	}
}

func TestJWTTokenManager_ValidateInvalidToken(t *testing.T) {
	tm := NewJWTTokenManagerForTesting()

	_, err := tm.ValidateToken("invalid.token.here")
	if err == nil {
		t.Error("Expected error for invalid token")
	}
}

func TestJWTTokenManager_ValidateExpiredToken(t *testing.T) {
	tm := &JWTTokenManager{
		accessTokenSecret: make([]byte, 32),
		accessTokenExp:    1 * time.Second,
	}

	// Generate a token with 1 second expiration
	token, err := tm.GenerateAccessToken("user123", "test@example.com", "device456")
	if err != nil {
		t.Fatalf("GenerateAccessToken failed: %v", err)
	}

	// Wait for token to expire
	time.Sleep(2 * time.Second)

	// Try to validate expired token
	_, err = tm.ValidateToken(token)
	if err == nil {
		t.Error("Expected error for expired token")
	}
}

func TestJWTTokenManager_ExtractDeviceID(t *testing.T) {
	tm := NewJWTTokenManagerForTesting()

	// Generate a token
	token, err := tm.GenerateAccessToken("user123", "test@example.com", "device456")
	if err != nil {
		t.Fatalf("GenerateAccessToken failed: %v", err)
	}

	// Extract device ID
	deviceID, err := tm.ExtractDeviceID(token)
	if err != nil {
		t.Fatalf("ExtractDeviceID failed: %v", err)
	}

	if deviceID != "device456" {
		t.Errorf("Expected device_id 'device456', got '%s'", deviceID)
	}
}

func TestValidateTokenWithManager(t *testing.T) {
	// Test the ValidateTokenWithManagerForTesting function
	tm := NewJWTTokenManagerForTesting()
	token, err := tm.GenerateAccessToken("user123", "test@example.com", "device456")
	if err != nil {
		t.Fatalf("GenerateAccessToken failed: %v", err)
	}

	// ValidateTokenWithManagerForTesting uses the provided token manager
	claims, err := ValidateTokenWithManagerForTesting(tm, token)
	if err != nil {
		t.Fatalf("ValidateTokenWithManagerForTesting failed: %v", err)
	}

	if claims.Email != "test@example.com" {
		t.Errorf("Expected email 'test@example.com', got '%s'", claims.Email)
	}
}
