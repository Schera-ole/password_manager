package grpc

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	authpb "github.com/Schera-ole/password_manager/internal/shared/pb/auth"
	pmpb "github.com/Schera-ole/password_manager/internal/shared/pb/pm"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/Schera-ole/password_manager/internal/client/encryption"
	"github.com/Schera-ole/password_manager/internal/client/store"
)

// isTestMode returns true if running in test mode
func isTestMode() bool {
	return os.Getenv("PM_TEST_MODE") == "true"
}

// getCredentials returns the appropriate gRPC dial options based on mode
func getCredentials(serverAddr string, store store.Store) (grpc.DialOption, error) {
	if isTestMode() {
		return grpc.WithTransportCredentials(insecure.NewCredentials()), nil
	}
	return getTLSCredentialsWithCertPinning(serverAddr, store)
}

// Client wraps gRPC connections for password manager services
type Client struct {
	conn      *grpc.ClientConn
	auth      authpb.AuthServiceClient
	pm        pmpb.PasswordManagerServiceClient
	store     store.Store
	encryptor *encryption.Service
}

// NewClient creates a new gRPC client connection with JWT interceptor and TLS
func NewClient(serverAddr string, store store.Store) (*Client, error) {
	encryptor := encryption.NewService()

	creds, err := getCredentials(serverAddr, store)
	if err != nil {
		return nil, fmt.Errorf("get credentials: %w", err)
	}

	conn, err := grpc.NewClient(
		serverAddr,
		creds,
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

// getTLSCredentialsWithCertPinning returns TLS credentials with certificate pinning
func getTLSCredentialsWithCertPinning(serverAddr string, store store.Store) (grpc.DialOption, error) {
	// Create a temporary connection to get the server's certificate
	conn, err := tls.Dial("tcp", serverAddr, &tls.Config{
		InsecureSkipVerify: true, // verify the cert manually
	})
	if err != nil {
		return nil, fmt.Errorf("dial to get cert: %w", err)
	}
	defer conn.Close()

	// Get the server's certificate
	cert := conn.ConnectionState().PeerCertificates[0]
	certDER := cert.Raw

	// Calculate SHA256 hash of the certificate
	hash := sha256.Sum256(certDER)
	certHash := fmt.Sprintf("%x", hash)

	// Check if we have a stored hash for this server
	storedHash, err := store.LoadServerCertHash(serverAddr)
	if err != nil && err.Error() != "cert hash not found" {
		return nil, fmt.Errorf("load cert hash: %w", err)
	}

	if storedHash != "" {
		// Verify the certificate matches the stored hash
		if storedHash != certHash {
			return nil, fmt.Errorf("server certificate changed! expected: %s, got: %s", storedHash, certHash)
		}
	} else {
		// First connection - store the certificate hash
		if err := store.SaveServerCertHash(serverAddr, certHash); err != nil {
			return nil, fmt.Errorf("save cert hash: %w", err)
		}
	}

	// Create a custom TLS config that verifies the certificate
	creds := credentials.NewTLS(&tls.Config{
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no certificates received from server")
			}

			// Calculate hash of the first certificate
			hash := sha256.Sum256(rawCerts[0])
			actualHash := fmt.Sprintf("%x", hash)

			// Load stored hash
			storedHash, err := store.LoadServerCertHash(serverAddr)
			if err != nil {
				return fmt.Errorf("no stored certificate hash for server %s", serverAddr)
			}

			if actualHash != storedHash {
				return fmt.Errorf("server certificate hash mismatch: expected %s, got %s", storedHash, actualHash)
			}

			return nil
		},
	})

	return grpc.WithTransportCredentials(creds), nil
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
