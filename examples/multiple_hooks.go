package main

import (
	"log"
	"os"
	"time"

	"github.com/kawaiirei0/reitunnel"
	"github.com/kawaiirei0/reitunnel/config"
	"github.com/kawaiirei0/reitunnel/hooks"
	"github.com/kawaiirei0/reitunnel/server"
)

// This example demonstrates using multiple hooks together.
// It shows how to:
// 1. Register multiple hooks in a specific order
// 2. Combine authentication, logging, and metrics
// 3. Configure hook execution strategies

func main() {
	logger := log.New(os.Stdout, "[reitunnel] ", log.LstdFlags)

	// Create authentication hook
	// This validates client connections
	clientValidator := func(clientID string) error {
		// Simple validation: reject empty client IDs
		if clientID == "" {
			logger.Printf("Rejected connection: empty client ID")
			return reitunnel.ErrAuthFailed
		}
		// In production, you might check against a database or API
		logger.Printf("Authenticated client: %s", clientID)
		return nil
	}

	tunnelValidator := func(tunnelID string, meta map[string]string) error {
		// Validate tunnel permissions
		// In production, check if client has permission for this tunnel
		logger.Printf("Authorized tunnel: %s", tunnelID)
		return nil
	}

	authHook := hooks.NewAuthHook(clientValidator, tunnelValidator)

	// Create logger hook
	// This logs all lifecycle events
	loggerHook := hooks.NewStdLoggerHook(logger, 0) // 0 = log all events

	// Create metrics hook
	// This collects statistics about connections and data transfer
	metricsHook := hooks.NewMetricsHook()

	// Create hook manager
	hm := reitunnel.NewHookManager()

	// Set execution strategy
	// StopOnError: if any hook returns an error, stop execution
	// This is important for authentication - if auth fails, we don't want to proceed
	hm.SetStrategy(reitunnel.StopOnError)

	// Register hooks in order
	// Order matters! Auth should run first to reject unauthorized connections
	hm.Register(authHook)    // 1. Authenticate first
	hm.Register(loggerHook)  // 2. Log events
	hm.Register(metricsHook) // 3. Collect metrics

	// Create server configuration
	cfg := config.ServerConfig{
		Addr:      ":7000",
		Transport: "tcp",
		MaxConns:  100,
		Timeout:   30 * time.Second,
	}

	// Create server with hook manager
	srv := server.NewServer(cfg, server.WithHookManager(hm))

	// Start a goroutine to periodically print metrics
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			metrics := metricsHook.GetMetrics()
			logger.Printf("=== Metrics ===")
			logger.Printf("Active connections: %d", metrics.ActiveConnections)
			logger.Printf("Total connections: %d", metrics.TotalConnections)
			logger.Printf("Active tunnels: %d", metrics.ActiveTunnels)
			logger.Printf("Total tunnels: %d", metrics.TotalTunnels)
			logger.Printf("Bytes sent: %d", metrics.BytesSent)
			logger.Printf("Bytes received: %d", metrics.BytesReceived)
			logger.Printf("===============")
		}
	}()

	// Start the server
	logger.Println("Starting server with multiple hooks on :7000")
	logger.Println("Hooks enabled: Auth, Logger, Metrics")
	if err := srv.Run(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
