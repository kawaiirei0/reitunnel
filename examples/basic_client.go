package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/kawaiirei0/reitunnel/client"
	"github.com/kawaiirei0/reitunnel/config"
)

// This example demonstrates a basic client setup.
// It shows how to:
// 1. Connect to a server
// 2. Create a tunnel
// 3. Handle graceful shutdown

func main() {
	// Create client configuration
	cfg := config.ClientConfig{
		ServerAddr: "localhost:7000",
		Transport:  "tcp",
		Reconnect:  true, // Automatically reconnect if connection is lost
	}

	// Create client
	c := client.NewClient(cfg)

	// Connect to server
	log.Println("Connecting to server at localhost:7000...")
	if err := c.Connect(); err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	log.Println("Connected to server")

	// Create a tunnel: forward local port 8080 to remote port 80
	// This means traffic to the server's port 80 will be forwarded to localhost:8080
	log.Println("Creating tunnel: localhost:8080 -> remote:80")
	tunnel, err := c.CreateTunnel("localhost:8080", "0.0.0.0:80")
	if err != nil {
		log.Fatalf("Failed to create tunnel: %v", err)
	}

	log.Printf("Tunnel created successfully: %s", tunnel.ID)
	log.Println("Tunnel is active. Press Ctrl+C to stop.")

	// Wait for interrupt signal for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	// Clean up
	log.Println("Shutting down...")
	if err := c.Close(); err != nil {
		log.Printf("Error closing client: %v", err)
	}
	log.Println("Client closed")
}
