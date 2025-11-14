package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Transport defines the interface for network transport protocols.
// It abstracts the underlying transport mechanism (TCP, WebSocket, etc.)
// to allow flexible protocol selection.
type Transport interface {
	// Listen starts listening on the given address and returns a net.Listener
	Listen(addr string) (net.Listener, error)

	// Dial connects to the given address and returns a net.Conn
	Dial(addr string) (net.Conn, error)

	// Name returns the name of the transport protocol
	Name() string
}

// TCPTransport implements the Transport interface using TCP protocol.
type TCPTransport struct{}

// NewTCPTransport creates a new TCP transport instance.
func NewTCPTransport() *TCPTransport {
	return &TCPTransport{}
}

// Listen starts a TCP listener on the given address.
func (t *TCPTransport) Listen(addr string) (net.Listener, error) {
	return net.Listen("tcp", addr)
}

// Dial establishes a TCP connection to the given address.
func (t *TCPTransport) Dial(addr string) (net.Conn, error) {
	return net.Dial("tcp", addr)
}

// Name returns the transport protocol name.
func (t *TCPTransport) Name() string {
	return "tcp"
}

// WebSocketTransport implements the Transport interface using WebSocket protocol.
type WebSocketTransport struct {
	upgrader websocket.Upgrader
}

// NewWebSocketTransport creates a new WebSocket transport instance.
func NewWebSocketTransport() *WebSocketTransport {
	return &WebSocketTransport{
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins by default
			},
		},
	}
}

// Listen starts a WebSocket server on the given address.
// It returns a custom listener that wraps HTTP server functionality.
func (t *WebSocketTransport) Listen(addr string) (net.Listener, error) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &wsListener{
		listener: listener,
		upgrader: &t.upgrader,
		connCh:   make(chan net.Conn),
		errCh:    make(chan error, 1),
	}, nil
}

// Dial establishes a WebSocket connection to the given address.
// For TLS connections, use DialWithTLS instead or configure the dialer externally.
func (t *WebSocketTransport) Dial(addr string) (net.Conn, error) {
	// Construct WebSocket URL
	wsURL := "ws://" + addr

	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		return nil, err
	}

	return &wsConn{Conn: conn}, nil
}

// DialWithTLS establishes a secure WebSocket connection to the given address using TLS.
func (t *WebSocketTransport) DialWithTLS(addr string, tlsConfig *tls.Config) (net.Conn, error) {
	// Construct secure WebSocket URL
	wsURL := "wss://" + addr

	dialer := *websocket.DefaultDialer
	dialer.TLSClientConfig = tlsConfig

	conn, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		return nil, err
	}

	return &wsConn{Conn: conn}, nil
}

// Name returns the transport protocol name.
func (t *WebSocketTransport) Name() string {
	return "websocket"
}

// wsListener wraps a TCP listener to accept WebSocket connections.
type wsListener struct {
	listener net.Listener
	upgrader *websocket.Upgrader
	connCh   chan net.Conn
	errCh    chan error
	once     sync.Once
	server   *http.Server
}

// Accept waits for and returns the next WebSocket connection.
func (l *wsListener) Accept() (net.Conn, error) {
	l.once.Do(func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/", l.handleWebSocket)

		l.server = &http.Server{Handler: mux}

		go func() {
			if err := l.server.Serve(l.listener); err != nil && err != http.ErrServerClosed {
				l.errCh <- err
			}
		}()
	})

	select {
	case conn := <-l.connCh:
		return conn, nil
	case err := <-l.errCh:
		return nil, err
	}
}

// handleWebSocket upgrades HTTP connections to WebSocket.
func (l *wsListener) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := l.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	l.connCh <- &wsConn{Conn: conn}
}

// Close closes the WebSocket listener.
func (l *wsListener) Close() error {
	if l.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		l.server.Shutdown(ctx)
	}
	return l.listener.Close()
}

// Addr returns the listener's network address.
func (l *wsListener) Addr() net.Addr {
	return l.listener.Addr()
}

// wsConn wraps a WebSocket connection to implement net.Conn interface.
type wsConn struct {
	*websocket.Conn
	reader io.Reader
}

// Read reads data from the WebSocket connection.
func (c *wsConn) Read(b []byte) (int, error) {
	if c.reader == nil {
		messageType, reader, err := c.Conn.NextReader()
		if err != nil {
			return 0, err
		}
		if messageType != websocket.BinaryMessage {
			return 0, fmt.Errorf("expected binary message, got %d", messageType)
		}
		c.reader = reader
	}

	n, err := c.reader.Read(b)
	if err == io.EOF {
		c.reader = nil
		if n == 0 {
			// Try to get next message
			return c.Read(b)
		}
	}
	return n, err
}

// Write writes data to the WebSocket connection.
func (c *wsConn) Write(b []byte) (int, error) {
	err := c.Conn.WriteMessage(websocket.BinaryMessage, b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

// Close closes the WebSocket connection.
func (c *wsConn) Close() error {
	return c.Conn.Close()
}

// LocalAddr returns the local network address.
func (c *wsConn) LocalAddr() net.Addr {
	return c.Conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (c *wsConn) RemoteAddr() net.Addr {
	return c.Conn.RemoteAddr()
}

// SetDeadline sets the read and write deadlines.
func (c *wsConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

// SetReadDeadline sets the deadline for future Read calls.
func (c *wsConn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the deadline for future Write calls.
func (c *wsConn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}
