package grpc

import (
	"context"
	"fmt"

	"github.com/Schera-ole/password_manager/internal/client/crypto"
	"github.com/Schera-ole/password_manager/internal/client/encryption"
	"github.com/Schera-ole/password_manager/internal/client/store"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// Context key for password
type passwordContextKey struct{}

// WithPassword adds password to context for interceptor
func WithPassword(ctx context.Context, password string) context.Context {
	return context.WithValue(ctx, passwordContextKey{}, password)
}

// GetPassword retrieves password from context
func GetPassword(ctx context.Context) (string, bool) {
	pwd, ok := ctx.Value(passwordContextKey{}).(string)
	return pwd, ok
}

// GetPasswordOrError retrieves password from context or returns an error
func GetPasswordOrError(ctx context.Context) (string, error) {
	pwd, ok := ctx.Value(passwordContextKey{}).(string)
	if !ok {
		return "", fmt.Errorf("password not found in context")
	}
	return pwd, nil
}

// UnaryInterceptor is a gRPC unary client interceptor that JWT tokens to outgoing requests
func UnaryInterceptor(store store.Store, encryptor *encryption.Service) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply interface{},
		cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {

		// Get password from context
		password, ok := GetPassword(ctx)
		if !ok {
			// No password in context, proceed without token
			return invoker(ctx, method, req, reply, cc, opts...)
		}

		// Load encrypted access token from store
		encryptedToken, err := store.LoadEncryptedToken("access_token")
		if err != nil {
			return fmt.Errorf("load access_token: %w", err)
		}
		if encryptedToken == nil || len(encryptedToken) < crypto.NonceSize {
			// No token stored, proceed without token
			return invoker(ctx, method, req, reply, cc, opts...)
		}

		// Load static_salt from store
		staticSalt, err := store.LoadStaticSalt()
		if err != nil {
			return fmt.Errorf("load static_salt: %w", err)
		}
		defer crypto.ZeroMemory(staticSalt)

		// Decrypt enc_salt_enc using password and static_salt
		encSaltEnc, err := store.LoadEncSaltEnc()
		if err != nil {
			return fmt.Errorf("load enc_salt_enc: %w", err)
		}
		if len(encSaltEnc) < crypto.NonceSize {
			return fmt.Errorf("enc_salt_enc not found or invalid")
		}

		encSalt, err := encryptor.DecryptEncSalt(encSaltEnc, password, staticSalt)
		if err != nil {
			return fmt.Errorf("decrypt enc_salt: %w", err)
		}
		defer crypto.ZeroMemory(encSalt)

		// Derive encKey from password and enc_salt
		encKey, err := encryptor.DeriveEncKey(password, encSalt)
		if err != nil {
			return fmt.Errorf("derive encKey: %w", err)
		}
		defer crypto.ZeroMemory(encKey)

		// Decrypt token with encKey
		decryptedToken, err := encryptor.DecryptEntry(encKey, encryptedToken)
		if err != nil {
			return fmt.Errorf("decrypt access_token: %w", err)
		}
		defer crypto.ZeroMemory(decryptedToken)

		// Add authorization header to metadata
		md := metadata.Pairs("authorization", "Bearer "+string(decryptedToken))
		ctx = metadata.NewOutgoingContext(ctx, md)

		// Proceed with the gRPC call
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}
