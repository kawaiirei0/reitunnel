package hooks

import (
	"context"
	"log"
	"sync/atomic"

	"github.com/kawaiirei0/reitunnel"
)

// Package hooks provides default Hook implementations for Reitunnel,
// including Logger Hook, Metrics Hook, and Auth Hook.

// StdLoggerHook is a Hook implementation that logs all lifecycle events
// using the standard Go log.Logger. It embeds NoopHook and overrides
// specific methods to provide logging functionality.
type StdLoggerHook struct {
	reitunnel.NoopHook
	logger *log.Logger

	// Sampling counters for high-frequency events
	dataSentCount     atomic.Int64
	dataReceivedCount atomic.Int64
	sampleRate        int64 // Log every Nth data event (0 = log all)
}

// NewStdLoggerHook creates a new StdLoggerHook with the provided logger.
// If sampleRate is 0, all data events are logged. Otherwise, only every
// Nth data event is logged to reduce overhead.
func NewStdLoggerHook(logger *log.Logger, sampleRate int64) *StdLoggerHook {
	return &StdLoggerHook{
		logger:     logger,
		sampleRate: sampleRate,
	}
}

// OnServerStart logs when the server starts
func (h *StdLoggerHook) OnServerStart(ctx context.Context) error {
	h.logger.Println("Server started")
	return nil
}

// OnServerStop logs when the server stops
func (h *StdLoggerHook) OnServerStop(ctx context.Context) error {
	h.logger.Println("Server stopped")
	return nil
}

// OnClientConnect logs when a client connects
func (h *StdLoggerHook) OnClientConnect(ctx context.Context, clientID string) error {
	h.logger.Printf("Client connected: %s", clientID)
	return nil
}

// OnClientDisconnect logs when a client disconnects
func (h *StdLoggerHook) OnClientDisconnect(ctx context.Context, clientID string, reason error) error {
	if reason != nil {
		h.logger.Printf("Client disconnected: %s (reason: %v)", clientID, reason)
	} else {
		h.logger.Printf("Client disconnected: %s", clientID)
	}
	return nil
}

// OnTunnelOpen logs when a tunnel is opened
func (h *StdLoggerHook) OnTunnelOpen(ctx context.Context, tunnelID string, meta map[string]string) error {
	if len(meta) > 0 {
		h.logger.Printf("Tunnel opened: %s (meta: %v)", tunnelID, meta)
	} else {
		h.logger.Printf("Tunnel opened: %s", tunnelID)
	}
	return nil
}

// OnTunnelClose logs when a tunnel is closed
func (h *StdLoggerHook) OnTunnelClose(ctx context.Context, tunnelID string) error {
	h.logger.Printf("Tunnel closed: %s", tunnelID)
	return nil
}

// OnDataSent logs data sent events with sampling to reduce overhead.
// If sampleRate is set, only every Nth event is logged.
func (h *StdLoggerHook) OnDataSent(ctx context.Context, tunnelID string, bytes int64) error {
	count := h.dataSentCount.Add(1)

	// Log all events if sampleRate is 0, otherwise sample
	if h.sampleRate == 0 || count%h.sampleRate == 0 {
		h.logger.Printf("Data sent on tunnel %s: %d bytes (total events: %d)", tunnelID, bytes, count)
	}
	return nil
}

// OnDataReceived logs data received events with sampling to reduce overhead.
// If sampleRate is set, only every Nth event is logged.
func (h *StdLoggerHook) OnDataReceived(ctx context.Context, tunnelID string, bytes int64) error {
	count := h.dataReceivedCount.Add(1)

	// Log all events if sampleRate is 0, otherwise sample
	if h.sampleRate == 0 || count%h.sampleRate == 0 {
		h.logger.Printf("Data received on tunnel %s: %d bytes (total events: %d)", tunnelID, bytes, count)
	}
	return nil
}

// OnError logs error events
func (h *StdLoggerHook) OnError(ctx context.Context, err error, meta map[string]string) error {
	if len(meta) > 0 {
		h.logger.Printf("Error occurred: %v (meta: %v)", err, meta)
	} else {
		h.logger.Printf("Error occurred: %v", err)
	}
	return nil
}

// Metrics represents the current metrics collected by MetricsHook
type Metrics struct {
	// ActiveConnections is the current number of active client connections
	ActiveConnections int64
	// TotalConnections is the total number of client connections since start
	TotalConnections int64
	// ActiveTunnels is the current number of active tunnels
	ActiveTunnels int64
	// TotalTunnels is the total number of tunnels created since start
	TotalTunnels int64
	// BytesSent is the total number of bytes sent through all tunnels
	BytesSent int64
	// BytesReceived is the total number of bytes received through all tunnels
	BytesReceived int64
}

// MetricsHook is a Hook implementation that collects metrics about
// connections, tunnels, and data transfer. It uses atomic operations
// for thread-safe counter updates.
type MetricsHook struct {
	reitunnel.NoopHook

	// Connection metrics
	activeConnections atomic.Int64
	totalConnections  atomic.Int64

	// Tunnel metrics
	activeTunnels atomic.Int64
	totalTunnels  atomic.Int64

	// Data transfer metrics
	bytesSent     atomic.Int64
	bytesReceived atomic.Int64
}

// NewMetricsHook creates a new MetricsHook with all counters initialized to zero
func NewMetricsHook() *MetricsHook {
	return &MetricsHook{}
}

// OnClientConnect increments the active and total connection counters
func (h *MetricsHook) OnClientConnect(ctx context.Context, clientID string) error {
	h.activeConnections.Add(1)
	h.totalConnections.Add(1)
	return nil
}

// OnClientDisconnect decrements the active connection counter
func (h *MetricsHook) OnClientDisconnect(ctx context.Context, clientID string, reason error) error {
	h.activeConnections.Add(-1)
	return nil
}

// OnTunnelOpen increments the active and total tunnel counters
func (h *MetricsHook) OnTunnelOpen(ctx context.Context, tunnelID string, meta map[string]string) error {
	h.activeTunnels.Add(1)
	h.totalTunnels.Add(1)
	return nil
}

// OnTunnelClose decrements the active tunnel counter
func (h *MetricsHook) OnTunnelClose(ctx context.Context, tunnelID string) error {
	h.activeTunnels.Add(-1)
	return nil
}

// OnDataSent increments the bytes sent counter
func (h *MetricsHook) OnDataSent(ctx context.Context, tunnelID string, bytes int64) error {
	h.bytesSent.Add(bytes)
	return nil
}

// OnDataReceived increments the bytes received counter
func (h *MetricsHook) OnDataReceived(ctx context.Context, tunnelID string, bytes int64) error {
	h.bytesReceived.Add(bytes)
	return nil
}

// GetMetrics returns a snapshot of the current metrics.
// The returned Metrics struct contains the current values of all counters.
func (h *MetricsHook) GetMetrics() Metrics {
	return Metrics{
		ActiveConnections: h.activeConnections.Load(),
		TotalConnections:  h.totalConnections.Load(),
		ActiveTunnels:     h.activeTunnels.Load(),
		TotalTunnels:      h.totalTunnels.Load(),
		BytesSent:         h.bytesSent.Load(),
		BytesReceived:     h.bytesReceived.Load(),
	}
}

// ClientValidator is a function type that validates a client ID.
// It should return nil if the client is authorized, or an error if not.
type ClientValidator func(clientID string) error

// TunnelValidator is a function type that validates tunnel permissions.
// It receives the tunnel ID and metadata, and should return nil if authorized.
type TunnelValidator func(tunnelID string, meta map[string]string) error

// AuthHook is a Hook implementation that provides authentication and
// authorization for client connections and tunnel creation. It uses
// validator functions to determine whether to allow or reject operations.
type AuthHook struct {
	reitunnel.NoopHook
	clientValidator ClientValidator
	tunnelValidator TunnelValidator
}

// NewAuthHook creates a new AuthHook with the provided validator functions.
// If clientValidator is nil, all client connections are allowed.
// If tunnelValidator is nil, all tunnel creations are allowed.
func NewAuthHook(clientValidator ClientValidator, tunnelValidator TunnelValidator) *AuthHook {
	return &AuthHook{
		clientValidator: clientValidator,
		tunnelValidator: tunnelValidator,
	}
}

// OnClientConnect validates the client ID using the configured validator.
// If the validator returns an error, the client connection is rejected.
func (h *AuthHook) OnClientConnect(ctx context.Context, clientID string) error {
	if h.clientValidator != nil {
		return h.clientValidator(clientID)
	}
	return nil
}

// OnTunnelOpen validates tunnel permissions using the configured validator.
// If the validator returns an error, the tunnel creation is rejected.
func (h *AuthHook) OnTunnelOpen(ctx context.Context, tunnelID string, meta map[string]string) error {
	if h.tunnelValidator != nil {
		return h.tunnelValidator(tunnelID, meta)
	}
	return nil
}
