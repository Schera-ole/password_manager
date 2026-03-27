// Package tls provides utilities for generating and loading TLS certificates
// for the password manager server.
package tls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

const (
	defaultCertDir = ".password_manager/certs/server"
	certFileName   = "cert.pem"
	keyFileName    = "key.pem"
)

// generateCertDirPath returns the full path to the certificate directory
func generateCertDirPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		// Fallback to current directory if home cannot be determined
		return "./certs"
	}
	return filepath.Join(home, defaultCertDir)
}

// GenerateSelfSignedCert generates a self-signed certificate and saves it to files
func GenerateSelfSignedCert() (string, string, error) {
	certDir := generateCertDirPath()

	// Create directory if it doesn't exist
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return "", "", fmt.Errorf("create cert directory: %w", err)
	}

	certPath := filepath.Join(certDir, certFileName)
	keyPath := filepath.Join(certDir, keyFileName)

	// Generate RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("generate private key: %w", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Password Manager"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "127.0.0.1", "::1"},
	}

	// Self-sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return "", "", fmt.Errorf("create certificate: %w", err)
	}

	// Encode certificate to PEM
	certFile, err := os.Create(certPath)
	if err != nil {
		return "", "", fmt.Errorf("create cert file: %w", err)
	}
	defer certFile.Close()

	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return "", "", fmt.Errorf("encode cert to PEM: %w", err)
	}

	// Encode private key to PEM
	keyFile, err := os.Create(keyPath)
	if err != nil {
		return "", "", fmt.Errorf("create key file: %w", err)
	}
	defer keyFile.Close()

	privateKeyPEM, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", "", fmt.Errorf("marshal private key: %w", err)
	}

	if err := pem.Encode(keyFile, &pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyPEM}); err != nil {
		return "", "", fmt.Errorf("encode key to PEM: %w", err)
	}

	// Set file permissions to 600 (owner read/write only)
	if err := os.Chmod(certPath, 0600); err != nil {
		return "", "", fmt.Errorf("set cert permissions: %w", err)
	}
	if err := os.Chmod(keyPath, 0600); err != nil {
		return "", "", fmt.Errorf("set key permissions: %w", err)
	}

	return certPath, keyPath, nil
}

// LoadTLSCert loads a TLS certificate from files
func LoadTLSCert(certPath, keyPath string) (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load TLS cert: %w", err)
	}
	return &cert, nil
}

// LoadTLSCertFromDefaultDir loads TLS certificate from default directory
func LoadTLSCertFromDefaultDir() (*tls.Certificate, error) {
	certDir := generateCertDirPath()
	certPath := filepath.Join(certDir, certFileName)
	keyPath := filepath.Join(certDir, keyFileName)
	return LoadTLSCert(certPath, keyPath)
}

// GetCertFingerprint returns the SHA256 fingerprint of a certificate
func GetCertFingerprint(cert *tls.Certificate) (string, error) {
	certDER := cert.Certificate[0]
	// Calculate SHA256 hash
	hash := sha256.Sum256(certDER)
	return fmt.Sprintf("%x", hash), nil
}
