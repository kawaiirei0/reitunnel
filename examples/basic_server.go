package main

import (
	"log"
	"os"

	"github.com/kawaiirei0/reitunnel"
	"github.com/kawaiirei0/reitunnel/config"
	"github.com/kawaiirei0/reitunnel/hooks"
	"github.com/kawaiirei0/reitunnel/server"
)

// This example demonstrates a basic server setup with minimal configuration.
// It shows how to:
// 1. Create a simple server with default settings
// 2. Add basic logging
// 3. Start the server

func main() {
	// Create a logger for output
	logger := log.New(os.Stdout, "[reitunnel] ", log.LstdFlags)

	// Create a logger hook to see what's happening
	loggerHook := hooks.NewStdLoggerHook(logger, 0) // 0 = log all events

	// Create hook manager and register the logger hook
	hm := reitunnel.NewHookManager()
	hm.Register(loggerHook)

	// Create server configuration
	cfg := config.ServerConfig{
		Addr:      ":7000",
		Transport: "tcp",
		MaxConns:  100,
	}

	// Create server with hook manager
	srv := server.NewServer(cfg, server.WithHookManager(hm))

	// Start the server
	logger.Println("Starting server on :7000")
	if err := srv.Run(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
