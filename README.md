# Reitunnel

[![Go Reference](https://pkg.go.dev/badge/github.com/kawaiirei0/reitunnel.svg)](https://pkg.go.dev/github.com/kawaiirei0/reitunnel)
[![Go Report Card](https://goreportcard.com/badge/github.com/kawaiirei0/reitunnel)](https://goreportcard.com/report/github.com/kawaiirei0/reitunnel)

Reitunnel is a general-purpose, embeddable Go tunneling library designed to be integrated into other services or applications. It provides stable tunnel communication with a rich lifecycle/event hook mechanism, following a hook-first architecture that supports logging, authentication, auditing, metrics, and other extensibility features with guaranteed concurrency safety.

## Features

- **Embeddable Library**: Designed as a library, not a standalone tool - integrate directly into your Go applications
- **Hook-First Architecture**: Extend functionality through a comprehensive hook system for all lifecycle events
- **Concurrent Safe**: All core components are safe for concurrent access from multiple goroutines
- **Multiple Transports**: Built-in support for TCP and WebSocket protocols with extensible transport interface
- **TLS Support**: Full TLS support including client certificate authentication
- **Flexible Error Handling**: Configurable error strategies (StopOnError, CollectAndContinue)
- **Default Hooks**: Includes Logger, Metrics, and Auth hooks out of the box
- **Graceful Shutdown**: Proper resource cleanup and connection management
- **Context-Based**: Uses Go's context for cancellation and timeout support

## Quick Start

### Installation

```bash
go get github.com/kawaiirei0/reitunnel
```

### Basic Server

```go
package main

import (
    "log"
    "os"
    
    "github.com/kawaiirei0/reitunnel"
    "github.com/kawaiirei0/reitunnel/config"
    "github.com/kawaiirei0/reitunnel/hooks"
    "github.com/kawaiirei0/reitunnel/server"
)

func main() {
    // Create logger hook
    logger := log.New(os.Stdout, "[reitunnel] ", log.LstdFlags)
    loggerHook := hooks.NewStdLoggerHook(logger, 0)
    
    // Create hook manager and register hooks
    hm := reitunnel.NewHookManager()
    hm.Register(loggerHook)
    
    // Create server configuration
    cfg := config.ServerConfig{
        Addr:      ":7000",
        Transport: "tcp",
        MaxConns:  100,
    }
    
    // Create and start server
    srv := server.NewServer(cfg, server.WithHookManager(hm))
    
    if err := srv.Run(); err != nil {
        log.Fatalf("server error: %v", err)
    }
}
```

### Basic Client

```go
package main

import (
    "log"
    
    "github.com/kawaiirei0/reitunnel/client"
    "github.com/kawaiirei0/reitunnel/config"
)

func main() {
    // Create client configuration
    cfg := config.ClientConfig{
        ServerAddr: "localhost:7000",
        Transport:  "tcp",
        Reconnect:  true,
    }
    
    // Create and connect client
    c := client.NewClient(cfg)
    
    if err := c.Connect(); err != nil {
        log.Fatalf("connect error: %v", err)
    }
    
    // Create tunnel: local port 8080 maps to remote port 80
    tunnel, err := c.CreateTunnel("localhost:8080", "0.0.0.0:80")
    if err != nil {
        log.Fatalf("create tunnel error: %v", err)
    }
    
    log.Printf("tunnel created: %s", tunnel.ID)
    
    // Keep running
    select {}
}
```

## Architecture

Reitunnel follows a hook-first architecture where all key events trigger hooks that can be used to extend functionality:

```
Application Code
    ├── Server Component
    │   ├── Hook Manager
    │   │   ├── Logger Hook
    │   │   ├── Metrics Hook
    │   │   ├── Auth Hook
    │   │   └── Custom Hooks
    │   ├── Tunnel Manager
    │   └── Transport Layer
    └── Client Component
        ├── Hook Manager
        ├── Tunnel Manager
        └── Transport Layer
```

## Core Concepts

### Hooks

Hooks are the primary extension mechanism in Reitunnel. The `Hook` interface defines methods for all lifecycle and data transfer events:

- `OnServerStart` / `OnServerStop` - Server lifecycle
- `OnClientConnect` / `OnClientDisconnect` - Client connections
- `OnTunnelOpen` / `OnTunnelClose` - Tunnel sessions
- `OnDataSent` / `OnDataReceived` - Data transfer
- `OnError` - Error handling

See [Hook Development Guide](docs/HOOKS.md) for detailed information on creating custom hooks.

### Hook Manager

The `HookManager` manages hook registration and execution with configurable error handling strategies:

- **StopOnError** (default): Halts execution when a hook returns an error
- **CollectAndContinue**: Collects errors but continues executing remaining hooks

### Transport Layer

Reitunnel supports multiple transport protocols through a unified interface:

- **TCP**: Standard TCP connections
- **WebSocket**: WebSocket connections for firewall-friendly tunneling
- **Custom**: Implement the `Transport` interface for custom protocols

### Configuration

Both server and client use configuration structs with validation:

```go
// Server configuration
type ServerConfig struct {
    Addr      string        // Listen address (e.g., ":7000")
    Transport string        // "tcp" or "websocket"
    TLS       *tls.Config   // Optional TLS configuration
    MaxConns  int           // Maximum concurrent connections (0 = unlimited)
    Timeout   time.Duration // Connection timeout
}

// Client configuration
type ClientConfig struct {
    ServerAddr string        // Server address to connect to
    Transport  string        // "tcp" or "websocket"
    TLS        *tls.Config   // Optional TLS configuration
    Reconnect  bool          // Enable automatic reconnection
    Timeout    time.Duration // Connection timeout
}
```

## Default Hooks

### Logger Hook

Logs all lifecycle events with optional sampling for high-frequency data events:

```go
logger := log.New(os.Stdout, "[reitunnel] ", log.LstdFlags)
// Sample rate: 0 = log all events, N = log every Nth event
loggerHook := hooks.NewStdLoggerHook(logger, 100)
```

### Metrics Hook

Collects metrics about connections, tunnels, and data transfer:

```go
metricsHook := hooks.NewMetricsHook()

// Get current metrics
metrics := metricsHook.GetMetrics()
fmt.Printf("Active connections: %d\n", metrics.ActiveConnections)
fmt.Printf("Bytes sent: %d\n", metrics.BytesSent)
```

### Auth Hook

Provides authentication and authorization for clients and tunnels:

```go
authHook := hooks.NewAuthHook(
    // Client validator
    func(clientID string) error {
        if !isValidClient(clientID) {
            return reitunnel.ErrAuthFailed
        }
        return nil
    },
    // Tunnel validator
    func(tunnelID string, meta map[string]string) error {
        if !isAllowedTunnel(meta) {
            return reitunnel.ErrAuthFailed
        }
        return nil
    },
)
```

## Advanced Usage

### Multiple Hooks

Register multiple hooks to compose functionality:

```go
hm := reitunnel.NewHookManager()
hm.Register(authHook)      // Authenticate first
hm.Register(loggerHook)    // Then log
hm.Register(metricsHook)   // Finally collect metrics
```

### TLS Configuration

Enable TLS for secure connections:

```go
// Server with TLS
tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{cert},
    ClientAuth:   tls.RequireAndVerifyClientCert,
    ClientCAs:    caCertPool,
}

srv := server.NewServer(config.ServerConfig{
    Addr: ":7000",
    TLS:  tlsConfig,
})

// Client with TLS
clientTLSConfig := &tls.Config{
    Certificates: []tls.Certificate{clientCert},
    RootCAs:      caCertPool,
}

c := client.NewClient(config.ClientConfig{
    ServerAddr: "localhost:7000",
    TLS:        clientTLSConfig,
})
```

### Graceful Shutdown

Properly shut down the server with context timeout:

```go
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

if err := srv.Shutdown(ctx); err != nil {
    log.Printf("shutdown error: %v", err)
}
```

### Custom Transport

Implement custom transport protocols:

```go
type CustomTransport struct{}

func (t *CustomTransport) Listen(addr string) (net.Listener, error) {
    // Custom listen implementation
}

func (t *CustomTransport) Dial(addr string) (net.Conn, error) {
    // Custom dial implementation
}

func (t *CustomTransport) Name() string {
    return "custom"
}

// Use custom transport
srv := server.NewServer(cfg, server.WithTransport(&CustomTransport{}))
```

## Error Handling

Reitunnel provides structured error types with context:

```go
// Check for specific errors
if errors.Is(err, reitunnel.ErrAuthFailed) {
    // Handle authentication failure
}

// Extract error metadata
if meta := reitunnel.ErrorMetadata(err); meta != nil {
    log.Printf("Error context: %v", meta)
}

// Work with typed errors
var tunnelErr *reitunnel.TunnelError
if errors.As(err, &tunnelErr) {
    log.Printf("Tunnel %s failed during %s", tunnelErr.TunnelID, tunnelErr.Op)
}
```

## Examples

See the [examples](examples/) directory for complete working examples:

- [basic_server.go](examples/basic_server.go) - Simple server setup
- [basic_client.go](examples/basic_client.go) - Simple client setup
- [multiple_hooks.go](examples/multiple_hooks.go) - Using multiple hooks together
- [custom_hook.go](examples/custom_hook.go) - Creating custom hooks
- [tls_example.go](examples/tls_example.go) - TLS configuration

## Documentation

- [Hook Development Guide](docs/HOOKS.md) - Comprehensive guide to creating custom hooks
- [API Reference](https://pkg.go.dev/github.com/kawaiirei0/reitunnel) - Complete API documentation
- [Performance Best Practices](docs/PERFORMANCE.md) - Optimization guidelines
- [Security Considerations](docs/SECURITY.md) - Security guidelines and best practices

## Performance Considerations

- Use sampling for high-frequency data events in hooks
- Configure appropriate buffer sizes for your use case
- Limit concurrent connections with `MaxConns` when needed
- Use connection pooling for tunnel creation
- Consider async processing for expensive hook operations

See [Performance Best Practices](docs/PERFORMANCE.md) for detailed optimization guidelines.

## Security

- Always use TLS in production environments
- Implement proper authentication through Auth hooks
- Validate all client inputs and tunnel parameters
- Use rate limiting to prevent abuse
- Keep certificates and keys secure
- Regularly update dependencies

See [Security Considerations](docs/SECURITY.md) for comprehensive security guidelines.

## Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

## License

[MIT License](LICENSE)

## Acknowledgments

Reitunnel is designed with inspiration from modern tunneling solutions while focusing on embeddability and extensibility through hooks.
