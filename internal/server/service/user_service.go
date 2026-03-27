package service

import (
	"context"
	"net/mail"
	"time"

	"github.com/Schera-ole/password_manager/internal/server/auth"
	"github.com/Schera-ole/password_manager/internal/server/repository"
	model "github.com/Schera-ole/password_manager/internal/shared/models"
	authpb "github.com/Schera-ole/password_manager/internal/shared/pb/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// UserService provides methods for user authentication.
type UserService struct {
	repository repository.Repository
	tokenMgr   auth.TokenManager
}

// NewUserService creates a new UserService with the specified repository.
func NewUserService(repo repository.Repository, tokenMgr auth.TokenManager) *UserService {
	return &UserService{
		repository: repo,
		tokenMgr:   tokenMgr,
	}
}

// Register creates a new user in the system.
// The password_hash from client is in format: base64(salt)$base64(hash)
func (us *UserService) Register(ctx context.Context, req *authpb.RegisterRequest) (*authpb.RegisterResponse, error) {
	// Validate email
	email := req.GetEmail()
	if email == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}
	if _, err := mail.ParseAddress(email); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid email format")
	}

	// Validate password hash format
	passwordHash := req.GetPasswordHash()
	if passwordHash == "" {
		return nil, status.Error(codes.InvalidArgument, "password hash is required")
	}

	// Generate enc_salt for client-side encryption
	encSalt, err := auth.GenerateSalt()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate enc_salt: %v", err)
	}

	// Store the password hash as received from client
	user := model.User{
		Email:        email,
		PasswordHash: passwordHash,
		EncSalt:      auth.Base64EncodeSecret(encSalt),
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := us.repository.CreateUser(ctx, user); err != nil {

		return nil, status.Errorf(codes.Internal, "failed to create user: %v", err)
	}

	return &authpb.RegisterResponse{}, nil
}

// Login authenticates a user and returns access token.
func (us *UserService) Login(ctx context.Context, req *authpb.LoginRequest) (*authpb.LoginResponse, error) {
	email := req.GetEmail()
	password := req.GetPassword()

	if email == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}
	if password == "" {
		return nil, status.Error(codes.InvalidArgument, "password is required")
	}

	// Get user from database
	user, err := us.repository.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, status.Error(codes.NotFound, "invalid credentials")
	}

	// Verify password. The stored hash is in format: base64(salt)$base64(hash)
	// The client sends the password in plain text, server verify by hashing the password with the stored salt
	isValid, err := auth.VerifyPassword(user.PasswordHash, password)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid credentials")
	}
	if !isValid {
		return nil, status.Error(codes.Unauthenticated, "invalid credentials")
	}

	// Generate JWT access token with device ID (using email as user identifier)
	deviceID := req.GetDeviceId()
	accessToken, err := us.tokenMgr.GenerateAccessToken(user.Email, user.Email, deviceID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate access token: %v", err)
	}

	// Store access token in database
	expiresAt := time.Now().Add(auth.AccessTokenExpiration)
	if err := us.repository.StoreAccessToken(ctx, user.Email, deviceID, accessToken, expiresAt); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to store access token: %v", err)
	}

	builder := authpb.LoginResponse_builder{
		AccessToken: accessToken,
		EncSalt:     user.EncSalt,
	}
	return builder.Build(), nil
}

// Logout revokes the access token for the specified device.
func (us *UserService) Logout(ctx context.Context, req *authpb.LogoutRequest) (*authpb.LogoutResponse, error) {
	deviceID := req.GetDeviceId()
	if deviceID == "" {
		return nil, status.Error(codes.InvalidArgument, "device_id is required for logout")
	}

	if err := us.repository.RevokeAccessToken(ctx, deviceID); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to revoke access token: %v", err)
	}

	return &authpb.LogoutResponse{}, nil
}
