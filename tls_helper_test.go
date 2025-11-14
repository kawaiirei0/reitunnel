package reitunnel

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"
)

// generateTestCertificate generates a self-signed certificate for testing
func generateTestCertificate(cn string, isCA bool) (*x509.Certificate, *rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	if isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}

	return cert, priv, nil
}

// saveCertAndKey saves a certificate and private key to PEM files
func saveCertAndKey(certFile, keyFile string, cert *x509.Certificate, key *rsa.PrivateKey) error {
	// Save certificate
	certOut, err := os.Create(certFile)
	if err != nil {
		return err
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
		return err
	}

	// Save private key
	keyOut, err := os.Create(keyFile)
	if err != nil {
		return err
	}
	defer keyOut.Close()

	privBytes := x509.MarshalPKCS1PrivateKey(key)
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}); err != nil {
		return err
	}

	return nil
}

func TestNewServerTLSConfig(t *testing.T) {
	// Generate test certificates
	serverCert, serverKey, err := generateTestCertificate("localhost", false)
	if err != nil {
		t.Fatalf("Failed to generate server certificate: %v", err)
	}

	// Save to temporary files
	serverCertFile := "test-server-cert.pem"
	serverKeyFile := "test-server-key.pem"
	defer os.Remove(serverCertFile)
	defer os.Remove(serverKeyFile)

	if err := saveCertAndKey(serverCertFile, serverKeyFile, serverCert, serverKey); err != nil {
		t.Fatalf("Failed to save server certificate: %v", err)
	}

	// Test without client authentication
	tlsConfig, err := NewServerTLSConfig(serverCertFile, serverKeyFile, false, "")
	if err != nil {
		t.Fatalf("Failed to create server TLS config: %v", err)
	}

	if tlsConfig == nil {
		t.Fatal("TLS config is nil")
	}

	if len(tlsConfig.Certificates) != 1 {
		t.Errorf("Expected 1 certificate, got %d", len(tlsConfig.Certificates))
	}

	if tlsConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("Expected MinVersion TLS 1.2, got %d", tlsConfig.MinVersion)
	}

	if tlsConfig.ClientAuth != tls.NoClientCert {
		t.Errorf("Expected NoClientCert, got %d", tlsConfig.ClientAuth)
	}
}

func TestNewServerTLSConfigWithClientAuth(t *testing.T) {
	// Generate test certificates
	serverCert, serverKey, err := generateTestCertificate("localhost", false)
	if err != nil {
		t.Fatalf("Failed to generate server certificate: %v", err)
	}

	caCert, caKey, err := generateTestCertificate("CA", true)
	if err != nil {
		t.Fatalf("Failed to generate CA certificate: %v", err)
	}

	// Save to temporary files
	serverCertFile := "test-server-cert-auth.pem"
	serverKeyFile := "test-server-key-auth.pem"
	caFile := "test-ca.pem"
	defer os.Remove(serverCertFile)
	defer os.Remove(serverKeyFile)
	defer os.Remove(caFile)

	if err := saveCertAndKey(serverCertFile, serverKeyFile, serverCert, serverKey); err != nil {
		t.Fatalf("Failed to save server certificate: %v", err)
	}

	if err := saveCertAndKey(caFile, "test-ca-key.pem", caCert, caKey); err != nil {
		t.Fatalf("Failed to save CA certificate: %v", err)
	}
	defer os.Remove("test-ca-key.pem")

	// Test with client authentication
	tlsConfig, err := NewServerTLSConfig(serverCertFile, serverKeyFile, true, caFile)
	if err != nil {
		t.Fatalf("Failed to create server TLS config with client auth: %v", err)
	}

	if tlsConfig.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("Expected RequireAndVerifyClientCert, got %d", tlsConfig.ClientAuth)
	}

	if tlsConfig.ClientCAs == nil {
		t.Error("ClientCAs should not be nil")
	}
}

func TestNewClientTLSConfig(t *testing.T) {
	// Generate test certificates
	clientCert, clientKey, err := generateTestCertificate("client.example.com", false)
	if err != nil {
		t.Fatalf("Failed to generate client certificate: %v", err)
	}

	serverCACert, serverCAKey, err := generateTestCertificate("Server CA", true)
	if err != nil {
		t.Fatalf("Failed to generate server CA certificate: %v", err)
	}

	// Save to temporary files
	clientCertFile := "test-client-cert.pem"
	clientKeyFile := "test-client-key.pem"
	serverCAFile := "test-server-ca.pem"
	defer os.Remove(clientCertFile)
	defer os.Remove(clientKeyFile)
	defer os.Remove(serverCAFile)

	if err := saveCertAndKey(clientCertFile, clientKeyFile, clientCert, clientKey); err != nil {
		t.Fatalf("Failed to save client certificate: %v", err)
	}

	if err := saveCertAndKey(serverCAFile, "test-server-ca-key.pem", serverCACert, serverCAKey); err != nil {
		t.Fatalf("Failed to save server CA certificate: %v", err)
	}
	defer os.Remove("test-server-ca-key.pem")

	// Test with client certificate
	tlsConfig, err := NewClientTLSConfig(clientCertFile, clientKeyFile, serverCAFile, false)
	if err != nil {
		t.Fatalf("Failed to create client TLS config: %v", err)
	}

	if tlsConfig == nil {
		t.Fatal("TLS config is nil")
	}

	if len(tlsConfig.Certificates) != 1 {
		t.Errorf("Expected 1 certificate, got %d", len(tlsConfig.Certificates))
	}

	if tlsConfig.RootCAs == nil {
		t.Error("RootCAs should not be nil")
	}

	if tlsConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be false")
	}

	if tlsConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("Expected MinVersion TLS 1.2, got %d", tlsConfig.MinVersion)
	}
}

func TestNewClientTLSConfigWithoutCert(t *testing.T) {
	// Test without client certificate (server verification only)
	tlsConfig, err := NewClientTLSConfig("", "", "", false)
	if err != nil {
		t.Fatalf("Failed to create client TLS config: %v", err)
	}

	if len(tlsConfig.Certificates) != 0 {
		t.Errorf("Expected 0 certificates, got %d", len(tlsConfig.Certificates))
	}

	if tlsConfig.RootCAs != nil {
		t.Error("RootCAs should be nil when no CA file is provided")
	}
}

func TestVerifyClientCertificate(t *testing.T) {
	// Generate test certificate
	cert, _, err := generateTestCertificate("client.example.com", false)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	// Test CN verification
	err = VerifyClientCertificate(cert, "client.example.com", "")
	if err != nil {
		t.Errorf("CN verification failed: %v", err)
	}

	// Test CN mismatch
	err = VerifyClientCertificate(cert, "wrong.example.com", "")
	if err == nil {
		t.Error("Expected CN mismatch error")
	}

	// Test organization verification
	err = VerifyClientCertificate(cert, "", "Test Org")
	if err != nil {
		t.Errorf("Organization verification failed: %v", err)
	}

	// Test organization mismatch
	err = VerifyClientCertificate(cert, "", "Wrong Org")
	if err == nil {
		t.Error("Expected organization mismatch error")
	}

	// Test both CN and organization
	err = VerifyClientCertificate(cert, "client.example.com", "Test Org")
	if err != nil {
		t.Errorf("Combined verification failed: %v", err)
	}
}

func TestGetClientCertificate(t *testing.T) {
	// Generate test certificate
	cert, _, err := generateTestCertificate("client.example.com", false)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	// Create connection state with certificate
	state := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}

	// Test getting certificate
	extractedCert, err := GetClientCertificate(state)
	if err != nil {
		t.Errorf("Failed to get client certificate: %v", err)
	}

	if extractedCert == nil {
		t.Fatal("Extracted certificate is nil")
	}

	if extractedCert.Subject.CommonName != "client.example.com" {
		t.Errorf("Expected CN 'client.example.com', got '%s'", extractedCert.Subject.CommonName)
	}

	// Test with nil state
	_, err = GetClientCertificate(nil)
	if err == nil {
		t.Error("Expected error for nil connection state")
	}

	// Test with no certificates
	emptyState := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{},
	}
	_, err = GetClientCertificate(emptyState)
	if err == nil {
		t.Error("Expected error for empty peer certificates")
	}
}
