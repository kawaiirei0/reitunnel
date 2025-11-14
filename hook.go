package reitunnel

import "context"

// Hook defines the interface for handling lifecycle and data transfer events
// in the Reitunnel system. All methods receive a context for cancellation support.
type Hook interface {
	// OnServerStart is invoked when the Server Component starts
	OnServerStart(ctx context.Context) error

	// OnServerStop is invoked when the Server Component stops
	OnServerStop(ctx context.Context) error

	// OnClientConnect is invoked when a client connects to the server
	OnClientConnect(ctx context.Context, clientID string) error

	// OnClientDisconnect is invoked when a client disconnects from the server
	OnClientDisconnect(ctx context.Context, clientID string, reason error) error

	// OnTunnelOpen is invoked when a Tunnel Session is opened
	OnTunnelOpen(ctx context.Context, tunnelID string, meta map[string]string) error

	// OnTunnelClose is invoked when a Tunnel Session is closed
	OnTunnelClose(ctx context.Context, tunnelID string) error

	// OnDataSent is invoked when data is sent through a Tunnel Session
	OnDataSent(ctx context.Context, tunnelID string, bytes int64) error

	// OnDataReceived is invoked when data is received through a Tunnel Session
	OnDataReceived(ctx context.Context, tunnelID string, bytes int64) error

	// OnError is invoked when an error occurs in the Reitunnel System
	OnError(ctx context.Context, err error, meta map[string]string) error
}

// NoopHook provides a default implementation of the Hook interface with empty method bodies.
// Users can embed NoopHook in their custom hooks to only implement the methods they need.
type NoopHook struct{}

// OnServerStart implements Hook.OnServerStart
func (NoopHook) OnServerStart(ctx context.Context) error { return nil }

// OnServerStop implements Hook.OnServerStop
func (NoopHook) OnServerStop(ctx context.Context) error { return nil }

// OnClientConnect implements Hook.OnClientConnect
func (NoopHook) OnClientConnect(ctx context.Context, clientID string) error { return nil }

// OnClientDisconnect implements Hook.OnClientDisconnect
func (NoopHook) OnClientDisconnect(ctx context.Context, clientID string, reason error) error {
	return nil
}

// OnTunnelOpen implements Hook.OnTunnelOpen
func (NoopHook) OnTunnelOpen(ctx context.Context, tunnelID string, meta map[string]string) error {
	return nil
}

// OnTunnelClose implements Hook.OnTunnelClose
func (NoopHook) OnTunnelClose(ctx context.Context, tunnelID string) error { return nil }

// OnDataSent implements Hook.OnDataSent
func (NoopHook) OnDataSent(ctx context.Context, tunnelID string, bytes int64) error { return nil }

// OnDataReceived implements Hook.OnDataReceived
func (NoopHook) OnDataReceived(ctx context.Context, tunnelID string, bytes int64) error { return nil }

// OnError implements Hook.OnError
func (NoopHook) OnError(ctx context.Context, err error, meta map[string]string) error { return nil }
