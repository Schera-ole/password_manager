package grpc

import (
	"context"
	"testing"
	"time"

	"github.com/Schera-ole/password_manager/internal/server/auth"
	"github.com/Schera-ole/password_manager/internal/server/errors"
	model "github.com/Schera-ole/password_manager/internal/shared/models"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// mockTokenManager is a mock implementation of the TokenManager interface
type mockTokenManager struct {
	validTokens   map[string]*auth.TokenClaims
	invalidTokens map[string]bool
}

func newMockTokenManager() *mockTokenManager {
	return &mockTokenManager{
		validTokens:   make(map[string]*auth.TokenClaims),
		invalidTokens: make(map[string]bool),
	}
}

func (m *mockTokenManager) GenerateAccessToken(userID, email, deviceID string) (string, error) {
	// Not implemented for testing
	return "", nil
}

func (m *mockTokenManager) ValidateToken(tokenString string) (*auth.TokenClaims, error) {
	if m.invalidTokens[tokenString] {
		return nil, errors.ErrQueryExecution
	}
	if claims, ok := m.validTokens[tokenString]; ok {
		return claims, nil
	}
	return nil, errors.ErrQueryExecution
}

func (m *mockTokenManager) ExtractDeviceID(tokenString string) (string, error) {
	if claims, ok := m.validTokens[tokenString]; ok {
		return claims.DeviceID, nil
	}
	return "", errors.ErrQueryExecution
}

// mockRepository is a mock implementation of the Repository interface
type mockRepository struct {
	accessTokens map[string]string // deviceID -> token
	tokenRevoked map[string]bool   // deviceID -> revoked
}

func newMockRepository() *mockRepository {
	return &mockRepository{
		accessTokens: make(map[string]string),
		tokenRevoked: make(map[string]bool),
	}
}

func (m *mockRepository) SetEntry(ctx context.Context, entry model.Entry) error {
	return nil
}

func (m *mockRepository) GetEntry(ctx context.Context, entryID string) (model.Entry, error) {
	return model.Entry{}, nil
}

func (m *mockRepository) GetEntries(ctx context.Context, entryIDs []string) (map[string]model.Entry, error) {
	return make(map[string]model.Entry), nil
}

func (m *mockRepository) DeleteEntry(ctx context.Context, entryID string) error {
	return nil
}

func (m *mockRepository) ListEntries(ctx context.Context, userID string, tags []string) ([]model.Entry, error) {
	return nil, nil
}

func (m *mockRepository) GetSyncLog(ctx context.Context, userID string, since time.Time, limit int) ([]model.SyncLog, error) {
	return nil, nil
}

func (m *mockRepository) AddSyncLog(ctx context.Context, log model.SyncLog) error {
	return nil
}

func (m *mockRepository) Ping(ctx context.Context) error {
	return nil
}

func (m *mockRepository) Close() error {
	return nil
}

func (m *mockRepository) GetUserByEmail(ctx context.Context, email string) (model.User, error) {
	return model.User{}, nil
}

func (m *mockRepository) CreateUser(ctx context.Context, user model.User) error {
	return nil
}

func (m *mockRepository) StoreAccessToken(ctx context.Context, userID, deviceID, accessToken string, expiresAt time.Time) error {
	m.accessTokens[deviceID] = accessToken
	m.tokenRevoked[deviceID] = false
	return nil
}

func (m *mockRepository) GetAccessToken(ctx context.Context, deviceID string) (string, error) {
	if revoked, ok := m.tokenRevoked[deviceID]; ok && revoked {
		return "", errors.ErrQueryExecution
	}
	if token, ok := m.accessTokens[deviceID]; ok {
		return token, nil
	}
	return "", errors.ErrQueryExecution
}

func (m *mockRepository) RevokeAccessToken(ctx context.Context, deviceID string) error {
	m.tokenRevoked[deviceID] = true
	return nil
}

func (m *mockRepository) RevokeAllAccessTokens(ctx context.Context, userID string) error {
	for deviceID := range m.accessTokens {
		m.tokenRevoked[deviceID] = true
	}
	return nil
}

func (m *mockRepository) GetActiveAccessToken(ctx context.Context, userID, deviceID string) (string, error) {
	return m.GetAccessToken(ctx, deviceID)
}

func (m *mockRepository) GetActiveAccessTokens(ctx context.Context, userID string) ([]string, error) {
	var tokens []string
	for deviceID, revoked := range m.tokenRevoked {
		if !revoked {
			if token, ok := m.accessTokens[deviceID]; ok {
				tokens = append(tokens, token)
			}
		}
	}
	return tokens, nil
}

func TestJWTInterceptor_PublicEndpoint_Register(t *testing.T) {
	mockTokenMgr := newMockTokenManager()
	mockRepo := newMockRepository()

	interceptor := JWTInterceptor(mockTokenMgr, mockRepo)

	ctx := context.Background()
	req := struct{}{}
	info := &grpc.UnaryServerInfo{
		FullMethod: "/auth.AuthService/Register",
	}

	handlerCalled := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		return struct{}{}, nil
	}

	_, err := interceptor(ctx, req, info, handler)

	if err != nil {
		t.Fatalf("Expected no error for public endpoint, got: %v", err)
	}

	if !handlerCalled {
		t.Error("Expected handler to be called for public endpoint")
	}
}

func TestJWTInterceptor_PublicEndpoint_Login(t *testing.T) {
	mockTokenMgr := newMockTokenManager()
	mockRepo := newMockRepository()

	interceptor := JWTInterceptor(mockTokenMgr, mockRepo)

	ctx := context.Background()
	req := struct{}{}
	info := &grpc.UnaryServerInfo{
		FullMethod: "/auth.AuthService/Login",
	}

	handlerCalled := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		return struct{}{}, nil
	}

	_, err := interceptor(ctx, req, info, handler)

	if err != nil {
		t.Fatalf("Expected no error for public endpoint, got: %v", err)
	}

	if !handlerCalled {
		t.Error("Expected handler to be called for public endpoint")
	}
}

func TestJWTInterceptor_PrivateEndpoint_NoMetadata(t *testing.T) {
	mockTokenMgr := newMockTokenManager()
	mockRepo := newMockRepository()

	interceptor := JWTInterceptor(mockTokenMgr, mockRepo)

	ctx := context.Background()
	req := struct{}{}
	info := &grpc.UnaryServerInfo{
		FullMethod: "/pm.PasswordManagerService/ListEntries",
	}

	handlerCalled := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		return struct{}{}, nil
	}

	_, err := interceptor(ctx, req, info, handler)

	if err == nil {
		t.Error("Expected error for missing metadata")
	}

	if handlerCalled {
		t.Error("Expected handler not to be called for private endpoint without metadata")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Error("Expected gRPC status error")
	}

	if st.Code() != codes.Unauthenticated {
		t.Errorf("Expected Unauthenticated code, got %v", st.Code())
	}
}

func TestJWTInterceptor_PrivateEndpoint_MissingAuthorizationHeader(t *testing.T) {
	mockTokenMgr := newMockTokenManager()
	mockRepo := newMockRepository()

	interceptor := JWTInterceptor(mockTokenMgr, mockRepo)

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", ""))
	req := struct{}{}
	info := &grpc.UnaryServerInfo{
		FullMethod: "/pm.PasswordManagerService/ListEntries",
	}

	handlerCalled := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		return struct{}{}, nil
	}

	_, err := interceptor(ctx, req, info, handler)

	if err == nil {
		t.Error("Expected error for missing authorization header")
	}

	if handlerCalled {
		t.Error("Expected handler not to be called for private endpoint without authorization header")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Error("Expected gRPC status error")
	}

	if st.Code() != codes.Unauthenticated {
		t.Errorf("Expected Unauthenticated code, got %v", st.Code())
	}
}

func TestJWTInterceptor_PrivateEndpoint_EmptyAuthorizationHeader(t *testing.T) {
	mockTokenMgr := newMockTokenManager()
	mockRepo := newMockRepository()

	interceptor := JWTInterceptor(mockTokenMgr, mockRepo)

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", ""))
	req := struct{}{}
	info := &grpc.UnaryServerInfo{
		FullMethod: "/pm.PasswordManagerService/ListEntries",
	}

	handlerCalled := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		return struct{}{}, nil
	}

	_, err := interceptor(ctx, req, info, handler)

	if err == nil {
		t.Error("Expected error for empty authorization header")
	}

	if handlerCalled {
		t.Error("Expected handler not to be called for private endpoint with empty authorization header")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Error("Expected gRPC status error")
	}

	if st.Code() != codes.Unauthenticated {
		t.Errorf("Expected Unauthenticated code, got %v", st.Code())
	}
}

func TestJWTInterceptor_PrivateEndpoint_InvalidToken(t *testing.T) {
	mockTokenMgr := newMockTokenManager()
	mockRepo := newMockRepository()

	// Add an invalid token
	mockTokenMgr.invalidTokens["invalid-token"] = true

	interceptor := JWTInterceptor(mockTokenMgr, mockRepo)

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer invalid-token"))
	req := struct{}{}
	info := &grpc.UnaryServerInfo{
		FullMethod: "/pm.PasswordManagerService/ListEntries",
	}

	handlerCalled := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		return struct{}{}, nil
	}

	_, err := interceptor(ctx, req, info, handler)

	if err == nil {
		t.Error("Expected error for invalid token")
	}

	if handlerCalled {
		t.Error("Expected handler not to be called for private endpoint with invalid token")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Error("Expected gRPC status error")
	}

	if st.Code() != codes.Unauthenticated {
		t.Errorf("Expected Unauthenticated code, got %v", st.Code())
	}
}

func TestJWTInterceptor_PrivateEndpoint_TokenNotFoundInDB(t *testing.T) {
	mockTokenMgr := newMockTokenManager()
	mockRepo := newMockRepository()

	// Add a valid token to the mock token manager
	claims := &auth.TokenClaims{
		UserID:   "user1@example.com",
		Email:    "user1@example.com",
		DeviceID: "device1",
	}
	mockTokenMgr.validTokens["valid-token"] = claims

	// Token not in repository
	interceptor := JWTInterceptor(mockTokenMgr, mockRepo)

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer valid-token"))
	req := struct{}{}
	info := &grpc.UnaryServerInfo{
		FullMethod: "/pm.PasswordManagerService/ListEntries",
	}

	handlerCalled := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		return struct{}{}, nil
	}

	_, err := interceptor(ctx, req, info, handler)

	if err == nil {
		t.Error("Expected error for token not found in database")
	}

	if handlerCalled {
		t.Error("Expected handler not to be called for private endpoint with token not in database")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Error("Expected gRPC status error")
	}

	if st.Code() != codes.Unauthenticated {
		t.Errorf("Expected Unauthenticated code, got %v", st.Code())
	}
}

func TestJWTInterceptor_PrivateEndpoint_TokenRevoked(t *testing.T) {
	mockTokenMgr := newMockTokenManager()
	mockRepo := newMockRepository()

	// Add a valid token to the mock token manager
	claims := &auth.TokenClaims{
		UserID:   "user1@example.com",
		Email:    "user1@example.com",
		DeviceID: "device1",
	}
	mockTokenMgr.validTokens["revoked-token"] = claims

	// Add token to repository but mark as revoked
	mockRepo.accessTokens["device1"] = "revoked-token"
	mockRepo.tokenRevoked["device1"] = true

	interceptor := JWTInterceptor(mockTokenMgr, mockRepo)

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer revoked-token"))
	req := struct{}{}
	info := &grpc.UnaryServerInfo{
		FullMethod: "/pm.PasswordManagerService/ListEntries",
	}

	handlerCalled := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		return struct{}{}, nil
	}

	_, err := interceptor(ctx, req, info, handler)

	if err == nil {
		t.Error("Expected error for revoked token")
	}

	if handlerCalled {
		t.Error("Expected handler not to be called for private endpoint with revoked token")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Error("Expected gRPC status error")
	}

	if st.Code() != codes.Unauthenticated {
		t.Errorf("Expected Unauthenticated code, got %v", st.Code())
	}
}

func TestJWTInterceptor_PrivateEndpoint_MissingDeviceID(t *testing.T) {
	mockTokenMgr := newMockTokenManager()
	mockRepo := newMockRepository()

	// Add a valid token without device ID
	claims := &auth.TokenClaims{
		UserID: "user1@example.com",
		Email:  "user1@example.com",
		// DeviceID is empty
	}
	mockTokenMgr.validTokens["token-no-device"] = claims

	// Add token to repository
	mockRepo.accessTokens[""] = "token-no-device"

	interceptor := JWTInterceptor(mockTokenMgr, mockRepo)

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer token-no-device"))
	req := struct{}{}
	info := &grpc.UnaryServerInfo{
		FullMethod: "/pm.PasswordManagerService/ListEntries",
	}

	handlerCalled := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		return struct{}{}, nil
	}

	_, err := interceptor(ctx, req, info, handler)

	if err == nil {
		t.Error("Expected error for missing device ID in token")
	}

	if handlerCalled {
		t.Error("Expected handler not to be called for private endpoint with missing device ID")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Error("Expected gRPC status error")
	}

	if st.Code() != codes.Unauthenticated {
		t.Errorf("Expected Unauthenticated code, got %v", st.Code())
	}
}

func TestJWTInterceptor_PrivateEndpoint_MissingUserID(t *testing.T) {
	mockTokenMgr := newMockTokenManager()
	mockRepo := newMockRepository()

	// Add a valid token without user ID
	claims := &auth.TokenClaims{
		Email:    "user1@example.com",
		DeviceID: "device1",
		// UserID is empty
	}
	mockTokenMgr.validTokens["token-no-user"] = claims

	// Add token to repository
	mockRepo.accessTokens["device1"] = "token-no-user"

	interceptor := JWTInterceptor(mockTokenMgr, mockRepo)

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer token-no-user"))
	req := struct{}{}
	info := &grpc.UnaryServerInfo{
		FullMethod: "/pm.PasswordManagerService/ListEntries",
	}

	handlerCalled := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		return struct{}{}, nil
	}

	_, err := interceptor(ctx, req, info, handler)

	if err == nil {
		t.Error("Expected error for missing user ID in token")
	}

	if handlerCalled {
		t.Error("Expected handler not to be called for private endpoint with missing user ID")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Error("Expected gRPC status error")
	}

	if st.Code() != codes.Unauthenticated {
		t.Errorf("Expected Unauthenticated code, got %v", st.Code())
	}
}

func TestJWTInterceptor_PrivateEndpoint_TokenMismatch(t *testing.T) {
	mockTokenMgr := newMockTokenManager()
	mockRepo := newMockRepository()

	// Add a valid token to the mock token manager
	claims := &auth.TokenClaims{
		UserID:   "user1@example.com",
		Email:    "user1@example.com",
		DeviceID: "device1",
	}
	mockTokenMgr.validTokens["token1"] = claims

	// Add different token to repository
	mockRepo.accessTokens["device1"] = "token2"

	interceptor := JWTInterceptor(mockTokenMgr, mockRepo)

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer token1"))
	req := struct{}{}
	info := &grpc.UnaryServerInfo{
		FullMethod: "/pm.PasswordManagerService/ListEntries",
	}

	handlerCalled := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		return struct{}{}, nil
	}

	_, err := interceptor(ctx, req, info, handler)

	if err == nil {
		t.Error("Expected error for token mismatch")
	}

	if handlerCalled {
		t.Error("Expected handler not to be called for private endpoint with token mismatch")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Error("Expected gRPC status error")
	}

	if st.Code() != codes.Unauthenticated {
		t.Errorf("Expected Unauthenticated code, got %v", st.Code())
	}
}

func TestJWTInterceptor_PrivateEndpoint_ValidToken(t *testing.T) {
	mockTokenMgr := newMockTokenManager()
	mockRepo := newMockRepository()

	// Add a valid token to the mock token manager
	claims := &auth.TokenClaims{
		UserID:   "user1@example.com",
		Email:    "user1@example.com",
		DeviceID: "device1",
	}
	mockTokenMgr.validTokens["valid-token"] = claims

	// Add token to repository
	mockRepo.accessTokens["device1"] = "valid-token"

	interceptor := JWTInterceptor(mockTokenMgr, mockRepo)

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer valid-token"))
	req := struct{}{}
	info := &grpc.UnaryServerInfo{
		FullMethod: "/pm.PasswordManagerService/ListEntries",
	}

	handlerCalled := false
	var handlerCtx context.Context
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		handlerCtx = ctx
		return struct{}{}, nil
	}

	resp, err := interceptor(ctx, req, info, handler)

	if err != nil {
		t.Fatalf("Expected no error for valid token, got: %v", err)
	}

	if !handlerCalled {
		t.Error("Expected handler to be called for private endpoint with valid token")
	}

	// Check that user_id was added to context
	userID, ok := UserIDFromContext(handlerCtx)
	if !ok {
		t.Error("Expected user_id to be in context")
	} else if userID != "user1@example.com" {
		t.Errorf("Expected user_id 'user1@example.com', got '%v'", userID)
	}

	// Check that email was added to context
	email, ok := EmailFromContext(handlerCtx)
	if !ok {
		t.Error("Expected email to be in context")
	} else if email != "user1@example.com" {
		t.Errorf("Expected email 'user1@example.com', got '%v'", email)
	}

	if resp == nil {
		t.Error("Expected non-nil response")
	}
}

func TestJWTInterceptor_PrivateEndpoint_ValidToken_WithCustomClaims(t *testing.T) {
	mockTokenMgr := newMockTokenManager()
	mockRepo := newMockRepository()

	// Add a valid token with custom claims
	claims := &auth.TokenClaims{
		UserID:   "user2@example.com",
		Email:    "user2@example.com",
		DeviceID: "device2",
		Role:     "admin",
	}
	mockTokenMgr.validTokens["valid-token-2"] = claims

	// Add token to repository
	mockRepo.accessTokens["device2"] = "valid-token-2"

	interceptor := JWTInterceptor(mockTokenMgr, mockRepo)

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer valid-token-2"))
	req := struct{}{}
	info := &grpc.UnaryServerInfo{
		FullMethod: "/pm.PasswordManagerService/GetEntry",
	}

	handlerCalled := false
	var handlerCtx context.Context
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		handlerCtx = ctx
		return struct{}{}, nil
	}

	_, err := interceptor(ctx, req, info, handler)

	if err != nil {
		t.Fatalf("Expected no error for valid token, got: %v", err)
	}

	if !handlerCalled {
		t.Error("Expected handler to be called for private endpoint with valid token")
	}

	// Check that user_id was added to context
	userID, ok := UserIDFromContext(handlerCtx)
	if !ok {
		t.Error("Expected user_id to be in context")
	} else if userID != "user2@example.com" {
		t.Errorf("Expected user_id 'user2@example.com', got '%v'", userID)
	}

	// Check that email was added to context
	email, ok := EmailFromContext(handlerCtx)
	if !ok {
		t.Error("Expected email to be in context")
	} else if email != "user2@example.com" {
		t.Errorf("Expected email 'user2@example.com', got '%v'", email)
	}
}

func TestJWTInterceptor_NonAuthMethod(t *testing.T) {
	mockTokenMgr := newMockTokenManager()
	mockRepo := newMockRepository()

	interceptor := JWTInterceptor(mockTokenMgr, mockRepo)

	ctx := context.Background()
	req := struct{}{}
	info := &grpc.UnaryServerInfo{
		FullMethod: "/pm.PasswordManagerService/ListEntries",
	}

	handlerCalled := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		return struct{}{}, nil
	}

	_, err := interceptor(ctx, req, info, handler)

	if err == nil {
		t.Error("Expected error for non-auth method without metadata")
	}

	if handlerCalled {
		t.Error("Expected handler not to be called for non-auth method without metadata")
	}
}

func TestJWTInterceptor_NonAuthMethod_WithMetadata(t *testing.T) {
	mockTokenMgr := newMockTokenManager()
	mockRepo := newMockRepository()

	interceptor := JWTInterceptor(mockTokenMgr, mockRepo)

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer valid-token"))
	req := struct{}{}
	info := &grpc.UnaryServerInfo{
		FullMethod: "/pm.PasswordManagerService/ListEntries",
	}

	handlerCalled := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		return struct{}{}, nil
	}

	_, err := interceptor(ctx, req, info, handler)

	if err == nil {
		t.Error("Expected error for non-auth method with invalid token")
	}

	if handlerCalled {
		t.Error("Expected handler not to be called for non-auth method with invalid token")
	}
}

func TestJWTInterceptor_NonAuthMethod_WithValidToken(t *testing.T) {
	mockTokenMgr := newMockTokenManager()
	mockRepo := newMockRepository()

	// Add a valid token
	claims := &auth.TokenClaims{
		UserID:   "user1@example.com",
		Email:    "user1@example.com",
		DeviceID: "device1",
	}
	mockTokenMgr.validTokens["valid-token"] = claims
	mockRepo.accessTokens["device1"] = "valid-token"

	interceptor := JWTInterceptor(mockTokenMgr, mockRepo)

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer valid-token"))
	req := struct{}{}
	info := &grpc.UnaryServerInfo{
		FullMethod: "/pm.PasswordManagerService/ListEntries",
	}

	handlerCalled := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		handlerCalled = true
		return struct{}{}, nil
	}

	_, err := interceptor(ctx, req, info, handler)

	if err != nil {
		t.Fatalf("Expected no error for valid token, got: %v", err)
	}

	if !handlerCalled {
		t.Error("Expected handler to be called for non-auth method with valid token")
	}
}

func TestIsPublicEndpoint(t *testing.T) {
	tests := []struct {
		method   string
		expected bool
	}{
		{"/auth.AuthService/Register", true},
		{"/auth.AuthService/Login", true},
		{"/auth.AuthService/Logout", false},
		{"/pm.PasswordManagerService/ListEntries", false},
		{"/pm.PasswordManagerService/GetEntry", false},
		{"/pm.PasswordManagerService/CreateEntry", false},
		{"/pm.PasswordManagerService/UpdateEntry", false},
		{"/pm.PasswordManagerService/DeleteEntry", false},
		{"/pm.PasswordManagerService/Sync", false},
		{"/unknown.Service/UnknownMethod", false},
		{"/auth.AuthService/", false},
		{"/auth.AuthService/Register/Extra", false},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			result := isPublicEndpoint(tt.method)
			if result != tt.expected {
				t.Errorf("isPublicEndpoint(%q) = %v, want %v", tt.method, result, tt.expected)
			}
		})
	}
}
