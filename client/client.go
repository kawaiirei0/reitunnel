package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/kawaiirei0/reitunnel"
	"github.com/kawaiirei0/reitunnel/config"
	"github.com/kawaiirei0/reitunnel/protocol"
	"github.com/kawaiirei0/reitunnel/transport"
	"github.com/kawaiirei0/reitunnel/tunnel"
)

// Package client provides the Client Component implementation for Reitunnel.
// The client connects to the server and establishes tunnel sessions.

// Client is the main client component that connects to the server
// and establishes tunnel sessions. It is safe for concurrent use.
type Client struct {
	config      config.ClientConfig
	hookManager *reitunnel.HookManager
	tunnelMgr   *tunnel.Manager
	transport   transport.Transport
	conn        net.Conn
	tunnels     map[string]*tunnel.Tunnel
	router      *protocol.Router
	mu          sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
}

// Option is a function that configures a Client.
type Option func(*Client)

// WithHookManager sets the HookManager for the client.
func WithHookManager(hm *reitunnel.HookManager) Option {
	return func(c *Client) {
		c.hookManager = hm
	}
}

// WithTransport sets the Transport for the client.
func WithTransport(t transport.Transport) Option {
	return func(c *Client) {
		c.transport = t
	}
}

// WithTLS sets the TLS configuration for the client.
func WithTLS(tlsConfig *tls.Config) Option {
	return func(c *Client) {
		c.config.TLS = tlsConfig
	}
}

// NewClient creates a new Client instance with the given configuration and options.
// If no HookManager is provided, a default one is created.
// If no Transport is provided, TCP transport is used by default.
func NewClient(cfg config.ClientConfig, opts ...Option) *Client {
	ctx, cancel := context.WithCancel(context.Background())

	c := &Client{
		config:      cfg,
		hookManager: reitunnel.NewHookManager(),
		tunnelMgr:   tunnel.NewManager(),
		transport:   transport.NewTCPTransport(),
		tunnels:     make(map[string]*tunnel.Tunnel),
		router:      protocol.NewRouter(),
		ctx:         ctx,
		cancel:      cancel,
	}

	// Apply options
	for _, opt := range opts {
		opt(c)
	}

	// Override transport based on config if not explicitly set
	if cfg.Transport == "websocket" && c.transport.Name() == "tcp" {
		c.transport = transport.NewWebSocketTransport()
	}

	// Register message handlers
	c.setupMessageHandlers()

	return c
}

// Connect establishes a connection to the server using the configured transport.
// It handles connection errors and implements retry logic if Reconnect is enabled.
// The connection state is maintained for the lifetime of the client.
func (c *Client) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if already connected
	if c.conn != nil {
		return reitunnel.ErrAlreadyConnected
	}

	var conn net.Conn
	var err error

	// Attempt to connect with retry logic if enabled
	maxRetries := 1
	if c.config.Reconnect {
		maxRetries = 3 // Retry up to 3 times
	}

	for attempt := 0; attempt < maxRetries; attempt++ {
		// Check if context is cancelled before attempting connection
		select {
		case <-c.ctx.Done():
			return c.ctx.Err()
		default:
		}

		// Apply timeout if configured
		if c.config.Timeout > 0 {
			// For dial operations, we need to use a context with timeout
			dialCtx, dialCancel := context.WithTimeout(c.ctx, c.config.Timeout)

			// Check if context is already cancelled
			select {
			case <-dialCtx.Done():
				dialCancel()
				return dialCtx.Err()
			default:
			}
			dialCancel()
		}

		// Dial the server (with TLS support for WebSocket)
		if c.config.TLS != nil && c.config.Transport == "websocket" {
			// Use TLS-aware dial for WebSocket
			if wsTransport, ok := c.transport.(*transport.WebSocketTransport); ok {
				conn, err = wsTransport.DialWithTLS(c.config.ServerAddr, c.config.TLS)
			} else {
				conn, err = c.transport.Dial(c.config.ServerAddr)
			}
		} else {
			conn, err = c.transport.Dial(c.config.ServerAddr)
		}

		if err == nil {
			break // Connection successful
		}

		// If reconnect is disabled or this is the last attempt, return error
		if !c.config.Reconnect || attempt == maxRetries-1 {
			connErr := reitunnel.NewClientError("", "connect", err).
				WithMeta("server_addr", c.config.ServerAddr)
			meta := reitunnel.ErrorMetadata(connErr)
			if meta == nil {
				meta = make(map[string]string)
			}
			c.hookManager.ExecuteError(c.ctx, connErr, meta)
			return connErr
		}

		// Wait before retrying (exponential backoff)
		// Check context cancellation during retry delay
		retryDelay := time.Duration(attempt+1) * time.Second
		select {
		case <-time.After(retryDelay):
			// Continue to next attempt
		case <-c.ctx.Done():
			return c.ctx.Err()
		}
	}

	// Wrap connection with TLS if configured (only for TCP, WebSocket handles TLS internally)
	if c.config.TLS != nil && c.config.Transport == "tcp" {
		tlsConn := tls.Client(conn, c.config.TLS)
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			tlsErr := reitunnel.NewClientError("", "tls_handshake", err).
				WithMeta("server_addr", c.config.ServerAddr)
			meta := reitunnel.ErrorMetadata(tlsErr)
			if meta == nil {
				meta = make(map[string]string)
			}
			c.hookManager.ExecuteError(c.ctx, tlsErr, meta)
			return tlsErr
		}
		conn = tlsConn
	}

	// Store the connection
	c.conn = conn

	// Start message handler goroutine to process incoming messages from server
	c.wg.Add(1)
	go c.handleServerMessages()

	return nil
}

// isConnected checks if the client is currently connected to the server.
// This method should be called with the mutex held.
func (c *Client) isConnected() bool {
	return c.conn != nil
}

// CreateTunnel creates a new tunnel session between local and remote addresses.
// It sends a tunnel open message to the server, invokes OnTunnelOpen hook,
// handles tunnel authorization errors from hooks, and creates goroutines for
// bidirectional data transfer. The tunnel map is maintained with thread-safe access.
func (c *Client) CreateTunnel(localAddr, remoteAddr string) (*tunnel.Tunnel, error) {
	// Check if context is cancelled before creating tunnel
	select {
	case <-c.ctx.Done():
		return nil, c.ctx.Err()
	default:
	}

	c.mu.Lock()

	// Check if connected
	if !c.isConnected() {
		c.mu.Unlock()
		return nil, reitunnel.ErrNotConnected
	}
	c.mu.Unlock()

	// Generate unique tunnel ID
	tunnelID := fmt.Sprintf("tunnel-%d", time.Now().UnixNano())

	// Create metadata for the tunnel
	meta := map[string]string{
		"local_addr":  localAddr,
		"remote_addr": remoteAddr,
	}

	// Invoke OnTunnelOpen hook for authorization
	if err := c.hookManager.ExecuteTunnelOpen(c.ctx, tunnelID, meta); err != nil {
		// Hook rejected the tunnel (authorization failed)
		tunnelErr := reitunnel.NewTunnelError(tunnelID, "open", err).
			WithMeta("local_addr", localAddr).
			WithMeta("remote_addr", remoteAddr)
		hookErr := reitunnel.ErrorMetadata(tunnelErr)
		if hookErr == nil {
			hookErr = make(map[string]string)
		}
		hookErr["hook"] = "OnTunnelOpen"
		c.hookManager.ExecuteError(c.ctx, tunnelErr, hookErr)
		return nil, tunnelErr
	}

	// Connect to local address
	localConn, err := net.Dial("tcp", localAddr)
	if err != nil {
		tunnelErr := reitunnel.NewTunnelError(tunnelID, "dial", err).
			WithMeta("local_addr", localAddr).
			WithMeta("remote_addr", remoteAddr)
		errMeta := reitunnel.ErrorMetadata(tunnelErr)
		if errMeta == nil {
			errMeta = make(map[string]string)
		}
		c.hookManager.ExecuteError(c.ctx, tunnelErr, errMeta)
		return nil, tunnelErr
	}

	// Create tunnel in tunnel manager
	tun, err := c.tunnelMgr.Create(tunnelID, localAddr, remoteAddr, meta)
	if err != nil {
		localConn.Close()
		tunnelErr := reitunnel.NewTunnelError(tunnelID, "create", err).
			WithMeta("local_addr", localAddr).
			WithMeta("remote_addr", remoteAddr)
		errMeta := reitunnel.ErrorMetadata(tunnelErr)
		if errMeta == nil {
			errMeta = make(map[string]string)
		}
		c.hookManager.ExecuteError(c.ctx, tunnelErr, errMeta)
		return nil, tunnelErr
	}

	// Store local connection in tunnel
	tun.Conn = localConn

	// Add tunnel to client's tunnel map
	c.mu.Lock()
	c.tunnels[tunnelID] = tun
	c.mu.Unlock()

	// Send tunnel open message to server
	openMsg := protocol.NewTunnelOpenMessage(tunnelID, []byte(fmt.Sprintf("%s->%s", localAddr, remoteAddr)))
	if err := c.sendMessage(openMsg); err != nil {
		// Failed to send message - cleanup
		c.closeTunnel(tun)
		tunnelErr := reitunnel.NewTunnelError(tunnelID, "send_open", err).
			WithMeta("local_addr", localAddr).
			WithMeta("remote_addr", remoteAddr)
		errMeta := reitunnel.ErrorMetadata(tunnelErr)
		if errMeta == nil {
			errMeta = make(map[string]string)
		}
		c.hookManager.ExecuteError(c.ctx, tunnelErr, errMeta)
		return nil, tunnelErr
	}

	// Start bidirectional data transfer goroutines
	c.wg.Add(2)
	go c.handleTunnelRead(tun)
	go c.handleTunnelWrite(tun)

	return tun, nil
}

// handleTunnelRead handles reading data from the local connection and sending it
// to the remote server. This implements the local to remote data flow.
// It invokes OnDataSent hook, updates tunnel statistics atomically, and handles
// connection errors by invoking OnTunnelClose.
func (c *Client) handleTunnelRead(tun *tunnel.Tunnel) {
	defer c.wg.Done()
	defer c.closeTunnel(tun)

	buf := make([]byte, 32*1024) // 32KB buffer

	for {
		// Check context cancellation before each read
		select {
		case <-c.ctx.Done():
			// Context cancelled - clean shutdown
			return
		default:
		}

		// Set read deadline to allow periodic context checking
		// Use a short deadline (1 second) to ensure responsiveness to cancellation
		deadline := time.Now().Add(1 * time.Second)
		if c.config.Timeout > 0 && c.config.Timeout < 1*time.Second {
			// Use configured timeout if it's shorter
			deadline = time.Now().Add(c.config.Timeout)
		}
		tun.Conn.SetReadDeadline(deadline)

		// Read from local connection
		n, err := tun.Conn.Read(buf)
		if err != nil {
			// Check if it's a timeout error and context is still valid
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Check if context is cancelled
				select {
				case <-c.ctx.Done():
					// Context cancelled during read
					return
				default:
					// Just a read timeout, continue reading
					continue
				}
			}

			// Other connection error - trigger cleanup
			tunnelErr := reitunnel.NewTunnelError(tun.ID, "read", err).
				WithMeta("direction", "local_to_remote")
			errMeta := reitunnel.ErrorMetadata(tunnelErr)
			if errMeta == nil {
				errMeta = make(map[string]string)
			}
			c.hookManager.ExecuteError(c.ctx, tunnelErr, errMeta)
			return
		}

		if n > 0 {
			// Check context before sending
			select {
			case <-c.ctx.Done():
				return
			default:
			}

			// Send data to server using protocol message
			dataMsg := protocol.NewDataMessage(tun.ID, buf[:n])
			if err := c.sendMessage(dataMsg); err != nil {
				tunnelErr := reitunnel.NewTunnelError(tun.ID, "send", err).
					WithMeta("direction", "local_to_remote")
				errMeta := reitunnel.ErrorMetadata(tunnelErr)
				if errMeta == nil {
					errMeta = make(map[string]string)
				}
				c.hookManager.ExecuteError(c.ctx, tunnelErr, errMeta)
				return
			}

			// Update tunnel statistics atomically
			tun.AddBytesSent(int64(n))

			// Invoke OnDataSent hook
			if err := c.hookManager.ExecuteDataSent(c.ctx, tun.ID, int64(n)); err != nil {
				// Hook error - log but continue
				hookErr := reitunnel.NewHookError("", "OnDataSent", err).
					WithMeta("tunnel_id", tun.ID)
				errMeta := reitunnel.ErrorMetadata(hookErr)
				if errMeta == nil {
					errMeta = make(map[string]string)
				}
				c.hookManager.ExecuteError(c.ctx, hookErr, errMeta)
			}
		}
	}
}

// handleTunnelWrite handles reading data from the remote server and writing it
// to the local connection. This implements the remote to local data flow.
// It invokes OnDataReceived hook, updates tunnel statistics atomically, and handles
// connection errors by invoking OnTunnelClose.
// Note: This goroutine is no longer needed as data from server is handled by
// the message router in handleServerMessages. Keeping it for now for compatibility.
func (c *Client) handleTunnelWrite(tun *tunnel.Tunnel) {
	defer c.wg.Done()
	// This is now handled by the message router
	// Data messages from server are routed to handleData which writes to the tunnel
}

// closeTunnel closes a tunnel and performs cleanup.
// It invokes OnTunnelClose hook, closes the local connection,
// removes the tunnel from the manager and client's tunnel map.
func (c *Client) closeTunnel(tun *tunnel.Tunnel) {
	// Invoke OnTunnelClose hook
	c.hookManager.ExecuteTunnelClose(c.ctx, tun.ID)

	// Close local connection
	if tun.Conn != nil {
		tun.Conn.Close()
	}

	// Remove from tunnel manager
	c.tunnelMgr.Remove(tun.ID)

	// Remove from client's tunnel map
	c.mu.Lock()
	delete(c.tunnels, tun.ID)
	c.mu.Unlock()
}

// Close closes the client connection and cleans up all resources.
// It closes all active tunnels, closes the connection to the server,
// and performs cleanup. This method is safe to call multiple times.
func (c *Client) Close() error {
	// Cancel context to signal all goroutines to stop
	c.cancel()

	c.mu.Lock()
	defer c.mu.Unlock()

	// Close all active tunnels
	for tunnelID, tun := range c.tunnels {
		// Send tunnel close message
		closeMsg := protocol.NewTunnelCloseMessage(tunnelID, nil)
		c.sendMessage(closeMsg) // Ignore error as we're closing anyway

		// Invoke OnTunnelClose hook
		c.hookManager.ExecuteTunnelClose(c.ctx, tunnelID)

		// Close local connection
		if tun.Conn != nil {
			tun.Conn.Close()
		}

		// Remove from tunnel manager
		c.tunnelMgr.Remove(tunnelID)

		// Remove from map
		delete(c.tunnels, tunnelID)
	}

	// Close connection to server
	if c.conn != nil {
		if err := c.conn.Close(); err != nil {
			clientErr := reitunnel.NewClientError("", "close", err)
			errMeta := reitunnel.ErrorMetadata(clientErr)
			if errMeta == nil {
				errMeta = make(map[string]string)
			}
			c.hookManager.ExecuteError(context.Background(), clientErr, errMeta)
			c.conn = nil
			// Wait for goroutines
			c.wg.Wait()
			return clientErr
		}
		c.conn = nil
	}

	// Wait for all goroutines to finish
	c.wg.Wait()

	return nil
}

// setupMessageHandlers registers handlers for all message types.
func (c *Client) setupMessageHandlers() {
	c.router.Register(protocol.MsgTypeHandshake, c.handleHandshake)
	c.router.Register(protocol.MsgTypeTunnelOpen, c.handleTunnelOpenResponse)
	c.router.Register(protocol.MsgTypeTunnelClose, c.handleTunnelCloseResponse)
	c.router.Register(protocol.MsgTypeData, c.handleData)
	c.router.Register(protocol.MsgTypeError, c.handleError)
}

// handleServerMessages continuously reads and routes messages from the server.
func (c *Client) handleServerMessages() {
	defer c.wg.Done()

	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()

	if conn == nil {
		return
	}

	// Handle messages until error or context cancellation
	if err := c.router.Handle(c.ctx, conn); err != nil {
		clientErr := reitunnel.NewClientError("", "handle_messages", err)
		errMeta := reitunnel.ErrorMetadata(clientErr)
		if errMeta == nil {
			errMeta = make(map[string]string)
		}
		c.hookManager.ExecuteError(c.ctx, clientErr, errMeta)
	}
}

// sendMessage sends a protocol message to the server.
// This method is thread-safe.
func (c *Client) sendMessage(msg *protocol.Message) error {
	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()

	if conn == nil {
		return reitunnel.ErrNotConnected
	}

	// Encode message to buffer first to avoid partial writes
	var buf bytes.Buffer
	if err := msg.Encode(&buf); err != nil {
		return fmt.Errorf("failed to encode message: %w", err)
	}

	// Write to connection
	if _, err := conn.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}

	return nil
}

// handleHandshake handles handshake messages from the server.
func (c *Client) handleHandshake(ctx context.Context, msg *protocol.Message) error {
	// For now, just acknowledge the handshake
	// In a full implementation, this would handle version negotiation, etc.
	return nil
}

// handleTunnelOpenResponse handles tunnel open response messages from the server.
func (c *Client) handleTunnelOpenResponse(ctx context.Context, msg *protocol.Message) error {
	// Server acknowledged tunnel open
	// In a full implementation, this would handle any server-side tunnel setup
	return nil
}

// handleTunnelCloseResponse handles tunnel close response messages from the server.
func (c *Client) handleTunnelCloseResponse(ctx context.Context, msg *protocol.Message) error {
	tunnelID := msg.TunnelID

	c.mu.RLock()
	tun, ok := c.tunnels[tunnelID]
	c.mu.RUnlock()

	if ok {
		c.closeTunnel(tun)
	}

	return nil
}

// handleData handles data messages from the server.
func (c *Client) handleData(ctx context.Context, msg *protocol.Message) error {
	tunnelID := msg.TunnelID

	// Get tunnel from map
	c.mu.RLock()
	tun, ok := c.tunnels[tunnelID]
	c.mu.RUnlock()

	if !ok {
		tunnelErr := reitunnel.NewTunnelError(tunnelID, "data", reitunnel.ErrTunnelNotFound)
		errMeta := reitunnel.ErrorMetadata(tunnelErr)
		if errMeta == nil {
			errMeta = make(map[string]string)
		}
		c.hookManager.ExecuteError(ctx, tunnelErr, errMeta)
		return tunnelErr
	}

	// Write data to local connection
	if tun.Conn != nil {
		n, err := tun.Conn.Write(msg.Payload)
		if err != nil {
			tunnelErr := reitunnel.NewTunnelError(tunnelID, "write", err).
				WithMeta("direction", "remote_to_local")
			errMeta := reitunnel.ErrorMetadata(tunnelErr)
			if errMeta == nil {
				errMeta = make(map[string]string)
			}
			c.hookManager.ExecuteError(ctx, tunnelErr, errMeta)
			return tunnelErr
		}

		// Update tunnel statistics atomically
		tun.AddBytesRecv(int64(n))

		// Invoke OnDataReceived hook
		if err := c.hookManager.ExecuteDataReceived(ctx, tunnelID, int64(n)); err != nil {
			// Hook error - log but continue
			hookErr := reitunnel.NewHookError("", "OnDataReceived", err).
				WithMeta("tunnel_id", tunnelID)
			errMeta := reitunnel.ErrorMetadata(hookErr)
			if errMeta == nil {
				errMeta = make(map[string]string)
			}
			c.hookManager.ExecuteError(ctx, hookErr, errMeta)
		}
	}

	return nil
}

// handleError handles error messages from the server.
func (c *Client) handleError(ctx context.Context, msg *protocol.Message) error {
	// Log the error through the hook system
	err := fmt.Errorf("server error: %s", string(msg.Payload))
	var wrappedErr error
	if msg.TunnelID != "" {
		wrappedErr = reitunnel.NewTunnelError(msg.TunnelID, "remote_error", err).
			WithMeta("source", "server")
	} else {
		wrappedErr = reitunnel.NewClientError("", "remote_error", err).
			WithMeta("source", "server")
	}
	meta := reitunnel.ErrorMetadata(wrappedErr)
	if meta == nil {
		meta = make(map[string]string)
	}
	c.hookManager.ExecuteError(ctx, wrappedErr, meta)
	return nil
}
