package main

import (
	"context"
	"crypto/tls"
	"log"
	"os"
	"time"

	"github.com/kawaiirei0/reitunnel"
	"github.com/kawaiirei0/reitunnel/client"
	"github.com/kawaiirei0/reitunnel/config"
	"github.com/kawaiirei0/reitunnel/hooks"
	"github.com/kawaiirei0/reitunnel/server"
)

// This example demonstrates how to use TLS with Reitunnel, including:
// 1. Server with TLS enabled
// 2. Client certificate authentication
// 3. Mutual TLS (mTLS) setup

func main() {
	// Example 1: Server with TLS and client certificate authentication
	runServerWithTLS()

	// Example 2: Client with TLS and client certificate
	runClientWithTLS()
}

// runServerWithTLS demonstrates setting up a server with TLS and client certificate authentication.
func runServerWithTLS() {
	logger := log.New(os.Stdout, "[server] ", log.LstdFlags)

	// Create TLS configuration for the server
	// In production, use proper certificate files
	tlsConfig, err := reitunnel.NewServerTLSConfig(
		"server-cert.pem", // Server certificate
		"server-key.pem",  // Server private key
		true,              // Enable client certificate authentication
		"client-ca.pem",   // Client CA certificate for verification
	)
	if err != nil {
		log.Fatalf("Failed to create server TLS config: %v", err)
	}

	// Create hooks
	loggerHook := hooks.NewStdLoggerHook(logger, 0) // 0 = log all events
	certAuthHook := hooks.NewCertAuthHook("client.example.com", "Example Org")

	// Create hook manager and register hooks
	hm := reitunnel.NewHookManager()
	hm.Register(certAuthHook) // Authenticate first
	hm.Register(loggerHook)   // Then log

	// Create server configuration
	cfg := config.ServerConfig{
		Addr:      ":7000",
		Transport: "tcp",
		TLS:       tlsConfig,
		MaxConns:  100,
		Timeout:   30 * time.Second,
	}

	// Create and run server
	srv := server.NewServer(cfg, server.WithHookManager(hm))

	logger.Println("Starting TLS server on :7000")
	if err := srv.Run(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

// runClientWithTLS demonstrates setting up a client with TLS and client certificate.
func runClientWithTLS() {
	// Create TLS configuration for the client
	// In production, use proper certificate files
	tlsConfig, err := reitunnel.NewClientTLSConfig(
		"client-cert.pem", // Client certificate (for mutual TLS)
		"client-key.pem",  // Client private key
		"server-ca.pem",   // Server CA certificate for verification
		false,             // Don't skip server certificate verification
	)
	if err != nil {
		log.Fatalf("Failed to create client TLS config: %v", err)
	}

	// Create client configuration
	cfg := config.ClientConfig{
		ServerAddr: "localhost:7000",
		Transport:  "tcp",
		TLS:        tlsConfig,
		Reconnect:  true,
		Timeout:    30 * time.Second,
	}

	// Create client
	c := client.NewClient(cfg)

	// Connect to server
	if err := c.Connect(); err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}

	log.Println("Connected to server with TLS")

	// Create a tunnel
	tunnel, err := c.CreateTunnel("localhost:8080", "0.0.0.0:80")
	if err != nil {
		log.Fatalf("Failed to create tunnel: %v", err)
	}

	log.Printf("Tunnel created: %s", tunnel.ID)

	// Keep running
	select {}
}

// Example 3: Simple TLS setup without client certificate authentication
func runSimpleTLS() {
	// Server side - TLS without client certificate authentication
	serverTLSConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Load certificates manually
		Certificates: []tls.Certificate{
			// Load your certificate here
		},
	}

	serverCfg := config.ServerConfig{
		Addr:      ":7000",
		Transport: "tcp",
		TLS:       serverTLSConfig,
	}

	srv := server.NewServer(serverCfg)
	go srv.Run()

	// Client side - TLS with server verification
	clientTLSConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Optionally set RootCAs to verify server certificate
		InsecureSkipVerify: false, // Set to true only for testing
	}

	clientCfg := config.ClientConfig{
		ServerAddr: "localhost:7000",
		Transport:  "tcp",
		TLS:        clientTLSConfig,
	}

	c := client.NewClient(clientCfg)
	if err := c.Connect(); err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}

	log.Println("Connected with simple TLS")
}

// Example 4: WebSocket with TLS
func runWebSocketWithTLS() {
	// Server side - WebSocket with TLS
	tlsConfig, err := reitunnel.NewServerTLSConfig(
		"server-cert.pem",
		"server-key.pem",
		false, // No client certificate authentication
		"",
	)
	if err != nil {
		log.Fatalf("Failed to create TLS config: %v", err)
	}

	serverCfg := config.ServerConfig{
		Addr:      ":7000",
		Transport: "websocket",
		TLS:       tlsConfig,
	}

	srv := server.NewServer(serverCfg)
	go srv.Run()

	// Client side - WebSocket with TLS
	clientTLSConfig, err := reitunnel.NewClientTLSConfig(
		"", // No client certificate
		"",
		"server-ca.pem",
		false,
	)
	if err != nil {
		log.Fatalf("Failed to create client TLS config: %v", err)
	}

	clientCfg := config.ClientConfig{
		ServerAddr: "localhost:7000",
		Transport:  "websocket",
		TLS:        clientTLSConfig,
	}

	c := client.NewClient(clientCfg)
	if err := c.Connect(); err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}

	log.Println("Connected with WebSocket over TLS")
}

// Example 5: Custom certificate validation
func runCustomCertValidation() {
	// Create a custom certificate validation hook
	customValidator := func(cert interface{}) error {
		// Implement custom validation logic here
		// For example, check certificate serial number, extensions, etc.
		log.Println("Performing custom certificate validation")
		return nil
	}

	certAuthHook := hooks.NewCertAuthHookWithValidator(customValidator)

	hm := reitunnel.NewHookManager()
	hm.Register(certAuthHook)

	tlsConfig, _ := reitunnel.NewServerTLSConfig(
		"server-cert.pem",
		"server-key.pem",
		true,
		"client-ca.pem",
	)

	cfg := config.ServerConfig{
		Addr:      ":7000",
		Transport: "tcp",
		TLS:       tlsConfig,
	}

	srv := server.NewServer(cfg, server.WithHookManager(hm))
	srv.Run()
}

// Example 6: Graceful shutdown with TLS
func runGracefulShutdownWithTLS() {
	tlsConfig, _ := reitunnel.NewServerTLSConfig(
		"server-cert.pem",
		"server-key.pem",
		false,
		"",
	)

	cfg := config.ServerConfig{
		Addr:      ":7000",
		Transport: "tcp",
		TLS:       tlsConfig,
	}

	srv := server.NewServer(cfg)

	// Run server in goroutine
	go func() {
		if err := srv.Run(); err != nil {
			log.Printf("Server error: %v", err)
		}
	}()

	// Wait for some time
	time.Sleep(10 * time.Second)

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("Shutdown error: %v", err)
	}

	log.Println("Server shut down gracefully")
}
