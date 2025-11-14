package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"

	"github.com/kawaiirei0/reitunnel"
	"github.com/kawaiirei0/reitunnel/config"
	"github.com/kawaiirei0/reitunnel/protocol"
	"github.com/kawaiirei0/reitunnel/transport"
	"github.com/kawaiirei0/reitunnel/tunnel"
)

// Package server provides the Server Component implementation for Reitunnel.
// The server accepts client connections and manages tunnel sessions.

// ClientInfo holds information about a connected client.
type ClientInfo struct {
	ID         string
	Conn       net.Conn
	RemoteAddr string
}

// Server is the main server component that accepts client connections
// and manages tunnel sessions. It is safe for concurrent use.
type Server struct {
	config      config.ServerConfig
	hookManager *reitunnel.HookManager
	tunnelMgr   *tunnel.Manager
	transport   transport.Transport
	listener    net.Listener
	clients     map[string]*ClientInfo
	router      *protocol.Router
	mu          sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
}

// Option is a function that configures a Server.
type Option func(*Server)

// WithHookManager sets the HookManager for the server.
func WithHookManager(hm *reitunnel.HookManager) Option {
	return func(s *Server) {
		s.hookManager = hm
	}
}

// WithTransport sets the Transport for the server.
func WithTransport(t transport.Transport) Option {
	return func(s *Server) {
		s.transport = t
	}
}

// WithTLS sets the TLS configuration for the server.
func WithTLS(tlsConfig *tls.Config) Option {
	return func(s *Server) {
		s.config.TLS = tlsConfig
	}
}

// NewServer creates a new Server instance with the given configuration and options.
// If no HookManager is provided, a default one is created.
// If no Transport is provided, TCP transport is used by default.
func NewServer(cfg config.ServerConfig, opts ...Option) *Server {
	ctx, cancel := context.WithCancel(context.Background())

	s := &Server{
		config:      cfg,
		hookManager: reitunnel.NewHookManager(),
		tunnelMgr:   tunnel.NewManager(),
		transport:   transport.NewTCPTransport(),
		clients:     make(map[string]*ClientInfo),
		router:      protocol.NewRouter(),
		ctx:         ctx,
		cancel:      cancel,
	}

	// Apply options
	for _, opt := range opts {
		opt(s)
	}

	// Override transport based on config if not explicitly set
	if cfg.Transport == "websocket" && s.transport.Name() == "tcp" {
		s.transport = transport.NewWebSocketTransport()
	}

	// Register message handlers
	s.setupMessageHandlers()

	return s
}

// Run starts the server and begins accepting client connections.
// It invokes OnServerStart hook before accepting connections and creates
// a goroutine for each client connection. This method blocks until the
// server is shut down or an error occurs.
func (s *Server) Run() error {
	// Set up listener with TLS if configured
	var listener net.Listener
	var err error

	if s.config.TLS != nil && s.config.Transport == "tcp" {
		// Create TLS listener for TCP
		baseListener, err := s.transport.Listen(s.config.Addr)
		if err != nil {
			return fmt.Errorf("failed to create listener: %w", err)
		}
		listener = tls.NewListener(baseListener, s.config.TLS)
	} else if s.config.TLS != nil && s.config.Transport == "websocket" {
		// For WebSocket with TLS, we need to configure the HTTP server
		// This is handled by creating a TLS-enabled wsListener
		baseListener, err := s.transport.Listen(s.config.Addr)
		if err != nil {
			return fmt.Errorf("failed to create listener: %w", err)
		}
		// Wrap the base listener with TLS
		listener = tls.NewListener(baseListener, s.config.TLS)
	} else {
		listener, err = s.transport.Listen(s.config.Addr)
		if err != nil {
			return fmt.Errorf("failed to create listener: %w", err)
		}
	}

	s.listener = listener

	// Invoke OnServerStart hook
	if err := s.hookManager.ExecuteServerStart(s.ctx); err != nil {
		// Clean up listener on hook failure
		listener.Close()
		hookErr := reitunnel.NewServerError("start", err).WithMeta("hook", "OnServerStart")
		// Trigger OnError hook for the failure
		meta := reitunnel.ErrorMetadata(hookErr)
		if meta == nil {
			meta = make(map[string]string)
		}
		s.hookManager.ExecuteError(s.ctx, hookErr, meta)
		return hookErr
	}

	// Accept loop
	for {
		// Check context before accepting
		select {
		case <-s.ctx.Done():
			// Server is shutting down
			return reitunnel.ErrServerClosed
		default:
		}

		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				// Server is shutting down
				return reitunnel.ErrServerClosed
			default:
				// For other errors, log and return
				acceptErr := reitunnel.NewServerError("accept", err)
				meta := reitunnel.ErrorMetadata(acceptErr)
				if meta == nil {
					meta = make(map[string]string)
				}
				s.hookManager.ExecuteError(s.ctx, acceptErr, meta)
				return acceptErr
			}
		}

		// Check max connections limit
		if s.config.MaxConns > 0 {
			s.mu.RLock()
			clientCount := len(s.clients)
			s.mu.RUnlock()

			if clientCount >= s.config.MaxConns {
				conn.Close()
				// Trigger OnError hook for max connections reached
				maxConnErr := reitunnel.NewServerError("accept", reitunnel.ErrMaxConnectionsReached)
				meta := map[string]string{
					"current_connections": fmt.Sprintf("%d", clientCount),
					"max_connections":     fmt.Sprintf("%d", s.config.MaxConns),
				}
				s.hookManager.ExecuteError(s.ctx, maxConnErr, meta)
				continue
			}
		}

		// Handle client connection in a new goroutine
		s.wg.Add(1)
		go s.handleClient(conn)
	}
}

// handleClient handles a single client connection.
// It invokes OnClientConnect hook after connection is established,
// handles authentication errors, and maintains the client map.
// It invokes OnClientDisconnect when the connection closes.
func (s *Server) handleClient(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	// Generate client ID from remote address
	clientID := conn.RemoteAddr().String()

	// Create client info
	clientInfo := &ClientInfo{
		ID:         clientID,
		Conn:       conn,
		RemoteAddr: conn.RemoteAddr().String(),
	}

	// Add client to map
	s.mu.Lock()
	s.clients[clientID] = clientInfo
	s.mu.Unlock()

	// Invoke OnClientConnect hook
	if err := s.hookManager.ExecuteClientConnect(s.ctx, clientID); err != nil {
		// Authentication or other hook error - reject connection
		s.mu.Lock()
		delete(s.clients, clientID)
		s.mu.Unlock()

		// Wrap error and invoke OnError hook
		clientErr := reitunnel.NewClientError(clientID, "connect", err)
		meta := reitunnel.ErrorMetadata(clientErr)
		if meta == nil {
			meta = make(map[string]string)
		}
		meta["hook"] = "OnClientConnect"
		s.hookManager.ExecuteError(s.ctx, clientErr, meta)

		return
	}

	// Handle client communication using the protocol router
	var disconnectReason error

	// Create a context for this client
	clientCtx, clientCancel := context.WithCancel(s.ctx)
	defer clientCancel()

	// Handle messages from the client
	if err := s.router.Handle(clientCtx, conn); err != nil {
		disconnectReason = err
	}

	// Remove client from map
	s.mu.Lock()
	delete(s.clients, clientID)
	s.mu.Unlock()

	// Invoke OnClientDisconnect hook
	s.hookManager.ExecuteClientDisconnect(s.ctx, clientID, disconnectReason)
}

// Shutdown gracefully shuts down the server.
// It stops accepting new connections, closes all active client connections
// and tunnels, invokes OnServerStop hook, and waits for all goroutines
// to complete or until the context is cancelled.
func (s *Server) Shutdown(ctx context.Context) error {
	// Cancel internal context to signal shutdown
	s.cancel()

	// Stop accepting new connections
	if s.listener != nil {
		if err := s.listener.Close(); err != nil {
			// Log error but continue shutdown
			shutdownErr := reitunnel.NewServerError("shutdown", err).WithMeta("component", "listener")
			meta := reitunnel.ErrorMetadata(shutdownErr)
			if meta == nil {
				meta = make(map[string]string)
			}
			s.hookManager.ExecuteError(s.ctx, shutdownErr, meta)
		}
	}

	// Close all active client connections
	s.mu.Lock()
	for clientID, clientInfo := range s.clients {
		if clientInfo.Conn != nil {
			clientInfo.Conn.Close()
		}
		delete(s.clients, clientID)
	}
	s.mu.Unlock()

	// Close all active tunnels
	tunnels := s.tunnelMgr.List()
	for _, t := range tunnels {
		if t.Conn != nil {
			t.Conn.Close()
		}
		s.tunnelMgr.Remove(t.ID)
	}

	// Wait for all goroutines to complete or timeout
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All goroutines completed successfully
	case <-ctx.Done():
		// Timeout or cancellation - force shutdown
		return ctx.Err()
	}

	// Invoke OnServerStop hook
	// Use background context since server context is cancelled
	stopCtx := context.Background()
	if err := s.hookManager.ExecuteServerStop(stopCtx); err != nil {
		stopErr := reitunnel.NewServerError("stop", err).WithMeta("hook", "OnServerStop")
		meta := reitunnel.ErrorMetadata(stopErr)
		if meta == nil {
			meta = make(map[string]string)
		}
		s.hookManager.ExecuteError(stopCtx, stopErr, meta)
		return stopErr
	}

	return nil
}

// setupMessageHandlers registers handlers for all message types.
func (s *Server) setupMessageHandlers() {
	s.router.Register(protocol.MsgTypeHandshake, s.handleHandshake)
	s.router.Register(protocol.MsgTypeTunnelOpen, s.handleTunnelOpen)
	s.router.Register(protocol.MsgTypeTunnelClose, s.handleTunnelClose)
	s.router.Register(protocol.MsgTypeData, s.handleData)
	s.router.Register(protocol.MsgTypeError, s.handleError)
}

// handleHandshake handles handshake messages from clients.
func (s *Server) handleHandshake(ctx context.Context, msg *protocol.Message) error {
	// For now, just acknowledge the handshake
	// In a full implementation, this would handle version negotiation, authentication, etc.
	return nil
}

// handleTunnelOpen handles tunnel open requests from clients.
func (s *Server) handleTunnelOpen(ctx context.Context, msg *protocol.Message) error {
	tunnelID := msg.TunnelID

	// Parse tunnel metadata from payload (simplified - in production would use proper encoding)
	meta := map[string]string{
		"tunnel_id": tunnelID,
	}

	// Invoke OnTunnelOpen hook for authorization
	if err := s.hookManager.ExecuteTunnelOpen(ctx, tunnelID, meta); err != nil {
		// Hook rejected the tunnel - send error response
		tunnelErr := reitunnel.NewTunnelError(tunnelID, "open", err)
		errMeta := reitunnel.ErrorMetadata(tunnelErr)
		if errMeta == nil {
			errMeta = make(map[string]string)
		}
		errMeta["hook"] = "OnTunnelOpen"
		s.hookManager.ExecuteError(ctx, tunnelErr, errMeta)
		// Note: In a full implementation, we would send this back to the client
		_ = protocol.NewErrorMessage(tunnelID, []byte(err.Error()))
		return tunnelErr
	}

	// Create tunnel in tunnel manager
	// Note: localAddr and remoteAddr would be parsed from the payload in production
	tun, err := s.tunnelMgr.Create(tunnelID, "", "", meta)
	if err != nil {
		tunnelErr := reitunnel.NewTunnelError(tunnelID, "create", err)
		errMeta := reitunnel.ErrorMetadata(tunnelErr)
		if errMeta == nil {
			errMeta = make(map[string]string)
		}
		s.hookManager.ExecuteError(ctx, tunnelErr, errMeta)
		return tunnelErr
	}

	// Store tunnel reference
	_ = tun

	return nil
}

// handleTunnelClose handles tunnel close requests from clients.
func (s *Server) handleTunnelClose(ctx context.Context, msg *protocol.Message) error {
	tunnelID := msg.TunnelID

	// Get tunnel from manager
	tun, ok := s.tunnelMgr.Get(tunnelID)
	if !ok {
		tunnelErr := reitunnel.NewTunnelError(tunnelID, "close", reitunnel.ErrTunnelNotFound)
		errMeta := reitunnel.ErrorMetadata(tunnelErr)
		if errMeta == nil {
			errMeta = make(map[string]string)
		}
		s.hookManager.ExecuteError(ctx, tunnelErr, errMeta)
		return tunnelErr
	}

	// Invoke OnTunnelClose hook
	s.hookManager.ExecuteTunnelClose(ctx, tunnelID)

	// Close tunnel connection if exists
	if tun.Conn != nil {
		tun.Conn.Close()
	}

	// Remove tunnel from manager
	s.tunnelMgr.Remove(tunnelID)

	return nil
}

// handleData handles data messages for tunnels.
func (s *Server) handleData(ctx context.Context, msg *protocol.Message) error {
	tunnelID := msg.TunnelID

	// Get tunnel from manager
	tun, ok := s.tunnelMgr.Get(tunnelID)
	if !ok {
		tunnelErr := reitunnel.NewTunnelError(tunnelID, "data", reitunnel.ErrTunnelNotFound)
		errMeta := reitunnel.ErrorMetadata(tunnelErr)
		if errMeta == nil {
			errMeta = make(map[string]string)
		}
		s.hookManager.ExecuteError(ctx, tunnelErr, errMeta)
		return tunnelErr
	}

	// Write data to tunnel connection
	if tun.Conn != nil {
		n, err := tun.Conn.Write(msg.Payload)
		if err != nil {
			tunnelErr := reitunnel.NewTunnelError(tunnelID, "write", err)
			errMeta := reitunnel.ErrorMetadata(tunnelErr)
			if errMeta == nil {
				errMeta = make(map[string]string)
			}
			s.hookManager.ExecuteError(ctx, tunnelErr, errMeta)
			return tunnelErr
		}

		// Update statistics
		tun.AddBytesRecv(int64(n))

		// Invoke OnDataReceived hook
		if err := s.hookManager.ExecuteDataReceived(ctx, tunnelID, int64(n)); err != nil {
			hookErr := reitunnel.NewHookError("", "OnDataReceived", err).
				WithMeta("tunnel_id", tunnelID)
			errMeta := reitunnel.ErrorMetadata(hookErr)
			if errMeta == nil {
				errMeta = make(map[string]string)
			}
			s.hookManager.ExecuteError(ctx, hookErr, errMeta)
		}
	}

	return nil
}

// handleError handles error messages from clients.
func (s *Server) handleError(ctx context.Context, msg *protocol.Message) error {
	// Log the error through the hook system
	err := fmt.Errorf("client error: %s", string(msg.Payload))
	var wrappedErr error
	if msg.TunnelID != "" {
		wrappedErr = reitunnel.NewTunnelError(msg.TunnelID, "remote_error", err).
			WithMeta("source", "client")
	} else {
		wrappedErr = reitunnel.NewClientError("", "remote_error", err).
			WithMeta("source", "client")
	}
	meta := reitunnel.ErrorMetadata(wrappedErr)
	if meta == nil {
		meta = make(map[string]string)
	}
	s.hookManager.ExecuteError(ctx, wrappedErr, meta)
	return nil
}
