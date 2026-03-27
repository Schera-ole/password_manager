package auth

import (
	"crypto/rand"
)

// NewJWTTokenManagerForTesting creates a new JWT token manager with random secrets
// This is for testing purposes only - use NewJWTTokenManagerFromConfig for production
func NewJWTTokenManagerForTesting() *JWTTokenManager {
	accessTokenSecret := make([]byte, 32)

	if _, err := rand.Read(accessTokenSecret); err != nil {
		panic(err)
	}

	return &JWTTokenManager{
		accessTokenSecret: accessTokenSecret,
		accessTokenExp:    AccessTokenExpiration,
	}
}

// NewJWTTokenManagerWithSecretsForTesting creates a new JWT token manager with the provided secrets
// This is for testing purposes only - use NewJWTTokenManagerFromConfig for production
func NewJWTTokenManagerWithSecretsForTesting(accessTokenSecret []byte) *JWTTokenManager {
	return &JWTTokenManager{
		accessTokenSecret: accessTokenSecret,
		accessTokenExp:    AccessTokenExpiration,
	}
}

// ValidateTokenWithManagerForTesting validates a token and returns its claims using the provided token manager.
// This is for testing purposes only.
func ValidateTokenWithManagerForTesting(tokenMgr TokenManager, tokenString string) (*TokenClaims, error) {
	return tokenMgr.ValidateToken(tokenString)
}
