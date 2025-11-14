package reitunnel

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// TLSConfig provides helper functions for creating TLS configurations
// with common settings for Reitunnel server and client components.

// NewServerTLSConfig creates a TLS configuration for the server with the given
// certificate and key files. It optionally enables client certificate authentication.
func NewServerTLSConfig(certFile, keyFile string, clientAuth bool, clientCAFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate: %w", err)
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	if clientAuth {
		if clientCAFile == "" {
			return nil, fmt.Errorf("client CA file is required when client authentication is enabled")
		}

		// Load client CA certificate
		caCert, err := os.ReadFile(clientCAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read client CA file: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse client CA certificate")
		}

		config.ClientCAs = caCertPool
		config.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return config, nil
}

// NewClientTLSConfig creates a TLS configuration for the client.
// It optionally loads a client certificate for mutual TLS authentication.
// If insecureSkipVerify is true, the client will not verify the server's certificate.
func NewClientTLSConfig(certFile, keyFile string, serverCAFile string, insecureSkipVerify bool) (*tls.Config, error) {
	config := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: insecureSkipVerify,
	}

	// Load client certificate if provided (for mutual TLS)
	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		config.Certificates = []tls.Certificate{cert}
	}

	// Load server CA certificate if provided
	if serverCAFile != "" {
		caCert, err := os.ReadFile(serverCAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read server CA file: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse server CA certificate")
		}

		config.RootCAs = caCertPool
	}

	return config, nil
}

// GetClientCertificate extracts the client certificate from a TLS connection state.
// This can be used in hooks to implement certificate-based authentication.
func GetClientCertificate(state *tls.ConnectionState) (*x509.Certificate, error) {
	if state == nil {
		return nil, fmt.Errorf("connection state is nil")
	}

	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no client certificate provided")
	}

	return state.PeerCertificates[0], nil
}

// VerifyClientCertificate verifies that the client certificate is valid
// and matches the expected common name or organization.
func VerifyClientCertificate(cert *x509.Certificate, expectedCN string, expectedOrg string) error {
	if cert == nil {
		return fmt.Errorf("certificate is nil")
	}

	if expectedCN != "" && cert.Subject.CommonName != expectedCN {
		return fmt.Errorf("certificate CN mismatch: expected %s, got %s", expectedCN, cert.Subject.CommonName)
	}

	if expectedOrg != "" {
		found := false
		for _, org := range cert.Subject.Organization {
			if org == expectedOrg {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("certificate organization mismatch: expected %s", expectedOrg)
		}
	}

	return nil
}
