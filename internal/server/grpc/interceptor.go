package grpc

import (
	"context"

	"github.com/Schera-ole/password_manager/internal/server/auth"
	"github.com/Schera-ole/password_manager/internal/server/repository"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// contextKey is a private type for context keys to avoid collisions
type contextKey string

func (c contextKey) String() string {
	return "password-manager-context-key-" + string(c)
}

var (
	// contextKeyUserID is the key used to store user ID in context
	contextKeyUserID = contextKey("user_id")
	// contextKeyEmail is the key used to store email in context
	contextKeyEmail = contextKey("email")
)

// UserIDFromContext retrieves user ID from context
func UserIDFromContext(ctx context.Context) (string, bool) {
	userID, ok := ctx.Value(contextKeyUserID).(string)
	return userID, ok
}

// EmailFromContext retrieves email from context
func EmailFromContext(ctx context.Context) (string, bool) {
	email, ok := ctx.Value(contextKeyEmail).(string)
	return email, ok
}

// JWTInterceptor is a gRPC unary interceptor that validates the JWT token from client.
// It expects the token in the "authorization" metadata header.
// It skips validation for public endpoints (Register, Login), because for them user doesn't send jwt token.
func JWTInterceptor(tokenMgr auth.TokenManager, repo repository.Repository) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// Skip JWT validation for public endpoints
		if isPublicEndpoint(info.FullMethod) {
			return handler(ctx, req)
		}

		// Extract metadata from context
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing metadata")
		}

		// Get authorization header
		authHeaders := md["authorization"]
		if len(authHeaders) == 0 {
			return nil, status.Error(codes.Unauthenticated, "missing authorization header")
		}

		token := authHeaders[0]
		if token == "" {
			return nil, status.Error(codes.Unauthenticated, "empty authorization header")
		}

		// Remove "Bearer " prefix if present
		if len(token) > 7 && token[:7] == "Bearer " {
			token = token[7:]
		}

		// Validate JWT token
		claims, err := tokenMgr.ValidateToken(token)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "invalid token")
		}

		// Validate token against database (check if it's revoked or expired)
		deviceID := claims.DeviceID
		if deviceID == "" {
			return nil, status.Error(codes.Unauthenticated, "missing device ID in token")
		}

		// Check user id just in case
		userID := claims.UserID
		if userID == "" {
			return nil, status.Error(codes.Unauthenticated, "missing user ID in token")
		}

		dbToken, err := repo.GetAccessToken(ctx, deviceID)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "token not found or revoked")
		}

		// Verify the token matches the one in database
		if dbToken != token {
			return nil, status.Error(codes.Unauthenticated, "invalid token")
		}

		// Add user info to context
		ctx = context.WithValue(ctx, contextKeyUserID, userID)
		ctx = context.WithValue(ctx, contextKeyEmail, claims.Email)

		return handler(ctx, req)
	}
}

// isPublicEndpoint checks if the endpoint is public (no authentication required)
func isPublicEndpoint(fullMethod string) bool {
	// Public endpoints: /auth.AuthService/Register, /auth.AuthService/Login
	return fullMethod == "/auth.AuthService/Register" || fullMethod == "/auth.AuthService/Login"
}
