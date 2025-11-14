# API Reference

This document provides a quick reference for the Reitunnel API. For complete documentation, see the [GoDoc](https://pkg.go.dev/github.com/kawaiirei0/reitunnel).

## Core Packages

### reitunnel

The main package provides the Hook interface and HookManager.

```go
import "github.com/kawaiirei0/reitunnel"
```

#### Hook Interface

```go
type Hook interface {
    OnServerStart(ctx context.Context) error
    OnServerStop(ctx context.Context) error
    OnClientConnect(ctx context.Context, clientID string) error
    OnClientDisconnect(ctx context.Context, clientID string, reason error) error
    OnTunnelOpen(ctx context.Context, tunnelID string, meta map[string]string) error
    OnTunnelClose(ctx context.Context, tunnelID string) error
    OnDataSent(ctx context.Context, tunnelID string, bytes int64) error
    OnDataReceived(ctx context.Context, tunnelID string, bytes int64) error
    OnError(ctx context.Context, err error, meta map[string]string) error
}
```

#### NoopHook

Base implementation with empty methods for convenient composition:

```go
type NoopHook struct{}
```

Embed in your custom hooks to only implement needed methods:

```go
type MyHook struct {
    reitunnel.NoopHook
    // your fields
}

func (h *MyHook) OnClientConnect(ctx context.Context, clientID string) error {
    // your implementation
    return nil
}
```

#### HookManager

Manages hook registration and execution:

```go
func NewHookManager() *HookManager
func (hm *HookManager) Register(hook Hook)
func (hm *HookManager) SetStrategy(strategy ExecutionStrategy)
func (hm *HookManager) ExecuteServerStart(ctx context.Context) error
func (hm *HookManager) ExecuteServerStop(ctx context.Context) error
func (hm *HookManager) ExecuteClientConnect(ctx context.Context, clientID string) error
func (hm *HookManager) ExecuteClientDisconnect(ctx context.Context, clientID string, reason error) error
func (hm *HookManager) ExecuteTunnelOpen(ctx context.Context, tunnelID string, meta map[string]string) error
func (hm *HookManager) ExecuteTunnelClose(ctx context.Context, tunnelID string) error
func (hm *HookManager) ExecuteDataSent(ctx context.Context, tunnelID string, bytes int64) error
func (hm *HookManager) ExecuteDataReceived(ctx context.Context, tunnelID string, bytes int64) error
func (hm *HookManager) ExecuteError(ctx context.Context, err error, meta map[string]string) error
```

#### Execution Strategies

```go
const (
    StopOnError        ExecutionStrategy = iota // Stop on first error (default)
    CollectAndContinue                          // Collect all errors
)
```

#### Error Types

```go
var (
    ErrServerClosed          = errors.New("server closed")
    ErrClientDisconnected    = errors.New("client disconnected")
    ErrTunnelClosed          = errors.New("tunnel closed")
    ErrInvalidConfig         = errors.New("invalid configuration")
    ErrAuthFailed            = errors.New("authentication failed")
    ErrHookFailed            = errors.New("hook execution failed")
    ErrNotConnected          = errors.New("not connected")
    ErrAlreadyConnected      = errors.New("already connected")
    ErrTunnelNotFound        = errors.New("tunnel not found")
    ErrMaxConnectionsReached = errors.New("maximum connections reached")
    ErrTimeout               = errors.New("operation timed out")
    ErrInvalidMessage        = errors.New("invalid message")
)
```

#### Structured Errors

```go
type TunnelError struct {
    TunnelID string
    Op       string
    Err      error
    Meta     map[string]string
}

type ClientError struct {
    ClientID string
    Op       string
    Err      error
    Meta     map[string]string
}

type ServerError struct {
    Op   string
    Err  error
    Meta map[string]string
}

type HookError struct {
    HookName string
    Event    string
    Err      error
    Meta     map[string]string
}

func NewTunnelError(tunnelID, op string, err error) *TunnelError
func NewClientError(clientID, op string, err error) *ClientError
func NewServerError(op string, err error) *ServerError
func NewHookError(hookName, event string, err error) *HookError
func ErrorMetadata(err error) map[string]string
```

### server

Server component for accepting client connections:

```go
import "github.com/kawaiirei0/reitunnel/server"
```

#### Server

```go
type Server struct { /* ... */ }

func NewServer(cfg config.ServerConfig, opts ...Option) *Server
func (s *Server) Run() error
func (s *Server) Shutdown(ctx context.Context) error
```

#### Options

```go
func WithHookManager(hm *reitunnel.HookManager) Option
func WithTransport(t transport.Transport) Option
func WithTLS(tlsConfig *tls.Config) Option
```

#### Example

```go
srv := server.NewServer(
    config.ServerConfig{
        Addr:      ":7000",
        Transport: "tcp",
        MaxConns:  100,
    },
    server.WithHookManager(hm),
    server.WithTLS(tlsConfig),
)

if err := srv.Run(); err != nil {
    log.Fatal(err)
}
```

### client

Client component for connecting to server and creating tunnels:

```go
import "github.com/kawaiirei0/reitunnel/client"
```

#### Client

```go
type Client struct { /* ... */ }

func NewClient(cfg config.ClientConfig, opts ...Option) *Client
func (c *Client) Connect() error
func (c *Client) CreateTunnel(localAddr, remoteAddr string) (*tunnel.Tunnel, error)
func (c *Client) Close() error
```

#### Options

```go
func WithHookManager(hm *reitunnel.HookManager) Option
func WithTransport(t transport.Transport) Option
func WithTLS(tlsConfig *tls.Config) Option
```

#### Example

```go
c := client.NewClient(
    config.ClientConfig{
        ServerAddr: "localhost:7000",
        Transport:  "tcp",
        Reconnect:  true,
    },
    client.WithHookManager(hm),
)

if err := c.Connect(); err != nil {
    log.Fatal(err)
}

tunnel, err := c.CreateTunnel("localhost:8080", "0.0.0.0:80")
if err != nil {
    log.Fatal(err)
}
```

### config

Configuration structures:

```go
import "github.com/kawaiirei0/reitunnel/config"
```

#### ServerConfig

```go
type ServerConfig struct {
    Addr      string        // Listen address (e.g., ":7000")
    Transport string        // "tcp" or "websocket"
    TLS       *tls.Config   // Optional TLS configuration
    MaxConns  int           // Maximum concurrent connections (0 = unlimited)
    Timeout   time.Duration // Connection timeout
}

func (c *ServerConfig) Validate() error
```

#### ClientConfig

```go
type ClientConfig struct {
    ServerAddr string        // Server address to connect to
    Transport  string        // "tcp" or "websocket"
    TLS        *tls.Config   // Optional TLS configuration
    Reconnect  bool          // Enable automatic reconnection
    Timeout    time.Duration // Connection timeout
}

func (c *ClientConfig) Validate() error
```

### hooks

Default hook implementations:

```go
import "github.com/kawaiirei0/reitunnel/hooks"
```

#### StdLoggerHook

Logs all lifecycle events:

```go
func NewStdLoggerHook(logger *log.Logger, sampleRate int64) *StdLoggerHook
```

Parameters:
- `logger`: Standard Go logger for output
- `sampleRate`: Sample rate for data events (0 = log all, N = log every Nth)

#### MetricsHook

Collects metrics about connections, tunnels, and data transfer:

```go
type Metrics struct {
    ActiveConnections int64
    TotalConnections  int64
    ActiveTunnels     int64
    TotalTunnels      int64
    BytesSent         int64
    BytesReceived     int64
}

func NewMetricsHook() *MetricsHook
func (h *MetricsHook) GetMetrics() Metrics
```

#### AuthHook

Provides authentication and authorization:

```go
type ClientValidator func(clientID string) error
type TunnelValidator func(tunnelID string, meta map[string]string) error

func NewAuthHook(clientValidator ClientValidator, tunnelValidator TunnelValidator) *AuthHook
```

#### CertAuthHook

Certificate-based authentication:

```go
func NewCertAuthHook(requiredCN, requiredOrg string) *CertAuthHook
func NewCertAuthHookWithValidator(validator func(cert interface{}) error) *CertAuthHook
```

### tunnel

Tunnel session management:

```go
import "github.com/kawaiirei0/reitunnel/tunnel"
```

#### Tunnel

```go
type Tunnel struct {
    ID         string
    LocalAddr  string
    RemoteAddr string
    Conn       net.Conn
    Meta       map[string]string
    CreatedAt  time.Time
    BytesSent  int64
    BytesRecv  int64
}

func (t *Tunnel) AddBytesSent(bytes int64)
func (t *Tunnel) AddBytesRecv(bytes int64)
func (t *Tunnel) GetStats() (sent int64, recv int64)
```

#### Manager

```go
type Manager struct { /* ... */ }

func NewManager() *Manager
func (m *Manager) Create(id, localAddr, remoteAddr string, meta map[string]string) (*Tunnel, error)
func (m *Manager) Get(id string) (*Tunnel, bool)
func (m *Manager) Remove(id string)
func (m *Manager) List() []*Tunnel
```

### transport

Transport layer abstraction:

```go
import "github.com/kawaiirei0/reitunnel/transport"
```

#### Transport Interface

```go
type Transport interface {
    Listen(addr string) (net.Listener, error)
    Dial(addr string) (net.Conn, error)
    Name() string
}
```

#### Built-in Transports

```go
func NewTCPTransport() Transport
func NewWebSocketTransport() Transport
```

### protocol

Protocol message handling:

```go
import "github.com/kawaiirei0/reitunnel/protocol"
```

#### MessageType

```go
const (
    MsgTypeHandshake MessageType = iota
    MsgTypeTunnelOpen
    MsgTypeTunnelClose
    MsgTypeData
    MsgTypeError
)
```

#### Message

```go
type Message struct {
    Type     MessageType
    TunnelID string
    Payload  []byte
}

func (m *Message) Encode(w io.Writer) error
func Decode(r io.Reader) (*Message, error)
func (m *Message) Validate() error

func NewHandshakeMessage(payload []byte) *Message
func NewTunnelOpenMessage(tunnelID string, payload []byte) *Message
func NewTunnelCloseMessage(tunnelID string, payload []byte) *Message
func NewDataMessage(tunnelID string, data []byte) *Message
func NewErrorMessage(tunnelID string, errorMsg []byte) *Message
```

## Common Patterns

### Basic Server Setup

```go
hm := reitunnel.NewHookManager()
hm.Register(hooks.NewStdLoggerHook(logger, 100))
hm.Register(hooks.NewMetricsHook())

srv := server.NewServer(
    config.ServerConfig{
        Addr:     ":7000",
        MaxConns: 1000,
    },
    server.WithHookManager(hm),
)

go func() {
    if err := srv.Run(); err != nil {
        log.Printf("server error: %v", err)
    }
}()

// Graceful shutdown
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()
srv.Shutdown(ctx)
```

### Basic Client Setup

```go
c := client.NewClient(config.ClientConfig{
    ServerAddr: "localhost:7000",
    Reconnect:  true,
})

if err := c.Connect(); err != nil {
    log.Fatal(err)
}
defer c.Close()

tunnel, err := c.CreateTunnel("localhost:8080", "0.0.0.0:80")
if err != nil {
    log.Fatal(err)
}
```

### Custom Hook

```go
type MyHook struct {
    reitunnel.NoopHook
    db *sql.DB
}

func (h *MyHook) OnClientConnect(ctx context.Context, clientID string) error {
    _, err := h.db.Exec("INSERT INTO connections (client_id, timestamp) VALUES (?, ?)",
        clientID, time.Now())
    return err
}

// Register hook
hm := reitunnel.NewHookManager()
hm.Register(&MyHook{db: db})
```

### Error Handling

```go
if err := c.Connect(); err != nil {
    // Check for specific errors
    if errors.Is(err, reitunnel.ErrAuthFailed) {
        log.Println("Authentication failed")
    }
    
    // Extract metadata
    if meta := reitunnel.ErrorMetadata(err); meta != nil {
        log.Printf("Error context: %v", meta)
    }
    
    // Work with typed errors
    var clientErr *reitunnel.ClientError
    if errors.As(err, &clientErr) {
        log.Printf("Client error during %s: %v", clientErr.Op, clientErr.Err)
    }
}
```

### TLS Configuration

```go
// Server
tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{serverCert},
    ClientAuth:   tls.RequireAndVerifyClientCert,
    ClientCAs:    caCertPool,
    MinVersion:   tls.VersionTLS13,
}

srv := server.NewServer(cfg, server.WithTLS(tlsConfig))

// Client
clientTLSConfig := &tls.Config{
    Certificates: []tls.Certificate{clientCert},
    RootCAs:      caCertPool,
    ServerName:   "tunnel.example.com",
}

c := client.NewClient(cfg, client.WithTLS(clientTLSConfig))
```

## See Also

- [Hook Development Guide](HOOKS.md) - Comprehensive guide to creating custom hooks
- [Performance Best Practices](PERFORMANCE.md) - Optimization guidelines
- [Security Considerations](SECURITY.md) - Security best practices
- [Examples](../examples/) - Complete working examples
- [GoDoc](https://pkg.go.dev/github.com/kawaiirei0/reitunnel) - Full API documentation
