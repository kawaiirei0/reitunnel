# Reitunnel Examples

This directory contains examples demonstrating various features and use cases of the Reitunnel library.

## Examples Overview

### 1. Basic Server (`basic_server.go`)

A minimal server setup showing:
- Basic server configuration
- Adding a logger hook
- Starting the server

**Run:**
```bash
go run examples/basic_server.go
```

### 2. Basic Client (`basic_client.go`)

A minimal client setup showing:
- Connecting to a server
- Creating a tunnel
- Graceful shutdown handling

**Run:**
```bash
# Start the server first (in another terminal)
go run examples/basic_server.go

# Then run the client
go run examples/basic_client.go
```

### 3. Multiple Hooks (`multiple_hooks.go`)

Demonstrates using multiple hooks together:
- Authentication hook for access control
- Logger hook for event logging
- Metrics hook for statistics collection
- Hook execution order and strategies

**Run:**
```bash
go run examples/multiple_hooks.go
```

### 4. Custom Hook (`custom_hook.go`)

Shows how to create custom hooks:
- Implementing the Hook interface
- Using NoopHook as a base
- Creating an audit trail hook
- Implementing rate limiting hook

**Run:**
```bash
go run examples/custom_hook.go
```

### 5. TLS Example (`tls_example.go`)

Comprehensive TLS examples including:
- Server with TLS and client certificate authentication
- Client with TLS and mutual TLS (mTLS)
- WebSocket with TLS
- Custom certificate validation
- Graceful shutdown with TLS

**Run:**
```bash
# Note: Requires certificate files (see TLS_GUIDE.md for setup)
go run examples/tls_example.go
```

## Common Patterns

### Creating a Server

```go
import (
    "github.com/kawaiirei0/reitunnel/config"
    "github.com/kawaiirei0/reitunnel/server"
)

cfg := config.ServerConfig{
    Addr:      ":7000",
    Transport: "tcp",
    MaxConns:  100,
}

srv := server.NewServer(cfg)
srv.Run()
```

### Creating a Client

```go
import (
    "github.com/kawaiirei0/reitunnel/client"
    "github.com/kawaiirei0/reitunnel/config"
)

cfg := config.ClientConfig{
    ServerAddr: "localhost:7000",
    Transport:  "tcp",
    Reconnect:  true,
}

c := client.NewClient(cfg)
c.Connect()

// Create tunnel: local:8080 -> remote:80
tunnel, err := c.CreateTunnel("localhost:8080", "0.0.0.0:80")
```

### Using Hooks

```go
import (
    "github.com/kawaiirei0/reitunnel"
    "github.com/kawaiirei0/reitunnel/hooks"
)

// Create hook manager
hm := reitunnel.NewHookManager()

// Register hooks
hm.Register(hooks.NewAuthHook(validatorFunc))
hm.Register(hooks.NewStdLoggerHook(logger, 0))
hm.Register(hooks.NewMetricsHook())

// Use with server
srv := server.NewServer(cfg, server.WithHookManager(hm))
```

### Creating Custom Hooks

```go
import "github.com/kawaiirei0/reitunnel"

type MyCustomHook struct {
    reitunnel.NoopHook // Embed for default implementations
    // Your fields here
}

// Override only the methods you need
func (h *MyCustomHook) OnClientConnect(ctx context.Context, clientID string) error {
    // Your custom logic
    return nil
}
```

## Requirements Mapping

These examples satisfy the following requirements from the specification:

- **Requirement 1.1**: Expose core functionality through package-level APIs
- **Requirement 1.2**: Provide Server Component that can be instantiated programmatically
- **Requirement 1.3**: Provide Client Component that can be instantiated programmatically
- **Requirement 2.1**: Define Hook Interface with methods for lifecycle events

## Next Steps

1. Review the [main documentation](../README.md) for detailed API reference
2. Check [TLS_GUIDE.md](../TLS_GUIDE.md) for TLS setup instructions
3. Explore the source code in the respective packages for more details
4. Try modifying these examples to fit your use case

## Tips

- Always start the server before connecting clients
- Use hooks for cross-cutting concerns (logging, metrics, auth)
- Register hooks in the correct order (auth first, then logging/metrics)
- Use `StopOnError` strategy for critical hooks like authentication
- Enable reconnection in clients for production use
- Use TLS in production environments
- Implement graceful shutdown for clean resource cleanup
