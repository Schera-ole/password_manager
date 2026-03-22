package grpc

import (
	authpb "github.com/Schera-ole/password_manager/internal/shared/pb/auth"
	pmpb "github.com/Schera-ole/password_manager/internal/shared/pb/pm"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/Schera-ole/password_manager/internal/client/encryption"
	"github.com/Schera-ole/password_manager/internal/client/store"
)

// Client wraps gRPC connections for password manager services
type Client struct {
	conn      *grpc.ClientConn
	auth      authpb.AuthServiceClient
	pm        pmpb.PasswordManagerServiceClient
	store     store.Store
	encryptor *encryption.Service
}

// NewClient creates a new gRPC client connection with JWT interceptor
func NewClient(serverAddr string, store store.Store) (*Client, error) {
	encryptor := encryption.NewService()
	conn, err := grpc.NewClient(
		serverAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithUnaryInterceptor(UnaryInterceptor(store, encryptor)),
	)
	if err != nil {
		return nil, err
	}
	authClient := authpb.NewAuthServiceClient(conn)
	pmClient := pmpb.NewPasswordManagerServiceClient(conn)
	return &Client{
		conn:      conn,
		auth:      authClient,
		pm:        pmClient,
		store:     store,
		encryptor: encryptor,
	}, nil
}

// Close closes the gRPC connection
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *Client) GetAuth() authpb.AuthServiceClient {
	return c.auth
}

func (c *Client) GetPM() pmpb.PasswordManagerServiceClient {
	return c.pm
}

func (c *Client) GetConn() *grpc.ClientConn {
	return c.conn
}

func (c *Client) GetStore() store.Store {
	return c.store
}
