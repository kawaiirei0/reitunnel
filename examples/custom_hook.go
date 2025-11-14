package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/kawaiirei0/reitunnel"
	"github.com/kawaiirei0/reitunnel/config"
	"github.com/kawaiirei0/reitunnel/server"
)

// This example demonstrates how to create a custom hook.
// It shows how to:
// 1. Implement the Hook interface
// 2. Use NoopHook as a base for convenience
// 3. Track custom metrics and events
// 4. Implement rate limiting

// AuditHook is a custom hook that logs all events to an audit trail
type AuditHook struct {
	reitunnel.NoopHook // Embed NoopHook to get default implementations
	logger             *log.Logger
	events             []AuditEvent
	mu                 sync.Mutex
}

// AuditEvent represents a single audit log entry
type AuditEvent struct {
	Timestamp time.Time
	EventType string
	ClientID  string
	TunnelID  string
	Details   string
}

// NewAuditHook creates a new audit hook
func NewAuditHook(logger *log.Logger) *AuditHook {
	return &AuditHook{
		logger: logger,
		events: make([]AuditEvent, 0),
	}
}

// logEvent adds an event to the audit trail
func (h *AuditHook) logEvent(eventType, clientID, tunnelID, details string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	event := AuditEvent{
		Timestamp: time.Now(),
		EventType: eventType,
		ClientID:  clientID,
		TunnelID:  tunnelID,
		Details:   details,
	}

	h.events = append(h.events, event)
	h.logger.Printf("[AUDIT] %s | Client: %s | Tunnel: %s | %s",
		eventType, clientID, tunnelID, details)
}

// GetAuditTrail returns all audit events
func (h *AuditHook) GetAuditTrail() []AuditEvent {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Return a copy to prevent external modification
	trail := make([]AuditEvent, len(h.events))
	copy(trail, h.events)
	return trail
}

// Override Hook methods to implement custom behavior

func (h *AuditHook) OnServerStart(ctx context.Context) error {
	h.logEvent("SERVER_START", "", "", "Server started")
	return nil
}

func (h *AuditHook) OnServerStop(ctx context.Context) error {
	h.logEvent("SERVER_STOP", "", "", "Server stopped")
	return nil
}

func (h *AuditHook) OnClientConnect(ctx context.Context, clientID string) error {
	h.logEvent("CLIENT_CONNECT", clientID, "", "Client connected")
	return nil
}

func (h *AuditHook) OnClientDisconnect(ctx context.Context, clientID string, reason error) error {
	details := "Normal disconnect"
	if reason != nil {
		details = fmt.Sprintf("Disconnect reason: %v", reason)
	}
	h.logEvent("CLIENT_DISCONNECT", clientID, "", details)
	return nil
}

func (h *AuditHook) OnTunnelOpen(ctx context.Context, tunnelID string, meta map[string]string) error {
	details := fmt.Sprintf("Tunnel opened: %v", meta)
	clientID := meta["client_id"]
	h.logEvent("TUNNEL_OPEN", clientID, tunnelID, details)
	return nil
}

func (h *AuditHook) OnTunnelClose(ctx context.Context, tunnelID string) error {
	h.logEvent("TUNNEL_CLOSE", "", tunnelID, "Tunnel closed")
	return nil
}

func (h *AuditHook) OnError(ctx context.Context, err error, meta map[string]string) error {
	details := fmt.Sprintf("Error: %v | Meta: %v", err, meta)
	clientID := meta["client_id"]
	tunnelID := meta["tunnel_id"]
	h.logEvent("ERROR", clientID, tunnelID, details)
	return nil
}

// RateLimitHook is a custom hook that implements rate limiting
type RateLimitHook struct {
	reitunnel.NoopHook
	logger       *log.Logger
	connections  map[string]*connectionInfo
	mu           sync.Mutex
	maxPerMinute int
}

type connectionInfo struct {
	count     int
	resetTime time.Time
}

// NewRateLimitHook creates a new rate limiting hook
func NewRateLimitHook(logger *log.Logger, maxPerMinute int) *RateLimitHook {
	return &RateLimitHook{
		logger:       logger,
		connections:  make(map[string]*connectionInfo),
		maxPerMinute: maxPerMinute,
	}
}

func (h *RateLimitHook) OnClientConnect(ctx context.Context, clientID string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	now := time.Now()

	// Get or create connection info
	info, exists := h.connections[clientID]
	if !exists || now.After(info.resetTime) {
		// Create new entry or reset if time window expired
		h.connections[clientID] = &connectionInfo{
			count:     1,
			resetTime: now.Add(time.Minute),
		}
		return nil
	}

	// Check rate limit
	if info.count >= h.maxPerMinute {
		h.logger.Printf("[RATE_LIMIT] Client %s exceeded rate limit (%d connections/min)",
			clientID, h.maxPerMinute)
		return fmt.Errorf("rate limit exceeded: max %d connections per minute", h.maxPerMinute)
	}

	// Increment counter
	info.count++
	return nil
}

func main() {
	logger := log.New(os.Stdout, "[reitunnel] ", log.LstdFlags)

	// Create custom hooks
	auditHook := NewAuditHook(logger)
	rateLimitHook := NewRateLimitHook(logger, 10) // Max 10 connections per minute per client

	// Create hook manager and register custom hooks
	hm := reitunnel.NewHookManager()
	hm.SetStrategy(reitunnel.StopOnError)

	// Register hooks in order
	hm.Register(rateLimitHook) // Check rate limit first
	hm.Register(auditHook)     // Then audit

	// Create server configuration
	cfg := config.ServerConfig{
		Addr:      ":7000",
		Transport: "tcp",
		MaxConns:  100,
		Timeout:   30 * time.Second,
	}

	// Create server with custom hooks
	srv := server.NewServer(cfg, server.WithHookManager(hm))

	// Start a goroutine to periodically print audit summary
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			trail := auditHook.GetAuditTrail()
			logger.Printf("=== Audit Summary ===")
			logger.Printf("Total events: %d", len(trail))

			// Count events by type
			eventCounts := make(map[string]int)
			for _, event := range trail {
				eventCounts[event.EventType]++
			}

			for eventType, count := range eventCounts {
				logger.Printf("  %s: %d", eventType, count)
			}
			logger.Printf("====================")
		}
	}()

	// Start the server
	logger.Println("Starting server with custom hooks on :7000")
	logger.Println("Custom hooks enabled: Audit, Rate Limiting")
	if err := srv.Run(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
