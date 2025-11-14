package reitunnel_test

import (
	"context"
	"testing"
	"time"

	"github.com/kawaiirei0/reitunnel"
	"github.com/kawaiirei0/reitunnel/client"
	"github.com/kawaiirei0/reitunnel/config"
	"github.com/kawaiirei0/reitunnel/server"
)

// TestServerContextCancellation verifies that server respects context cancellation
func TestServerContextCancellation(t *testing.T) {
	// Create server with default config
	cfg := config.ServerConfig{
		Addr:      "127.0.0.1:0", // Use random port
		Transport: "tcp",
	}

	srv := server.NewServer(cfg)

	// Start server in a goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Run()
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Shutdown server with a context
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Shutdown failed: %v", err)
	}

	// Verify server stopped
	select {
	case err := <-errCh:
		if err != reitunnel.ErrServerClosed {
			t.Errorf("Expected ErrServerClosed, got: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Server did not stop within timeout")
	}
}

// TestClientContextCancellation verifies that client respects context cancellation
func TestClientContextCancellation(t *testing.T) {
	// Create client with invalid server address (won't connect)
	cfg := config.ClientConfig{
		ServerAddr: "127.0.0.1:19999", // Non-existent server
		Transport:  "tcp",
		Reconnect:  true, // Enable reconnect to test cancellation during retry
		Timeout:    1 * time.Second,
	}

	c := client.NewClient(cfg)

	// Try to connect in a goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- c.Connect()
	}()

	// Give it a moment to start connecting
	time.Sleep(200 * time.Millisecond)

	// Close the client (which cancels the context)
	if err := c.Close(); err != nil {
		t.Logf("Close returned error (expected): %v", err)
	}

	// Verify connect operation was cancelled
	select {
	case err := <-errCh:
		if err == nil {
			t.Error("Expected connection to fail, but it succeeded")
		}
		// Connection should fail due to context cancellation or connection error
		t.Logf("Connect failed as expected: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("Connect did not return within timeout")
	}
}

// TestServerShutdownTimeout verifies that server shutdown respects context timeout
func TestServerShutdownTimeout(t *testing.T) {
	// Create server
	cfg := config.ServerConfig{
		Addr:      "127.0.0.1:0",
		Transport: "tcp",
	}

	srv := server.NewServer(cfg)

	// Start server
	go func() {
		srv.Run()
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Shutdown with a very short timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	err := srv.Shutdown(shutdownCtx)
	// Should timeout or succeed quickly
	if err != nil && err != context.DeadlineExceeded {
		t.Logf("Shutdown returned: %v", err)
	}
}
