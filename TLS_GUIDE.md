# TLS Support in Reitunnel

Reitunnel provides comprehensive TLS support for secure tunnel communication, including:

- Server-side TLS encryption
- Client-side TLS encryption
- Mutual TLS (mTLS) with client certificate authentication
- Support for both TCP and WebSocket transports
- Custom certificate validation

## Quick Start

### Server with TLS

```go
import (
    "github.com/kawaiirei0/reitunnel"
    "github.com/kawaiirei0/reitunnel/config"
    "github.com/kawaiirei0/reitunnel/server"
)

// Create TLS configuration
tlsConfig, err := reitunnel.NewServerTLSConfig(
    "server-cert.pem",  // Server certificate
    "server-key.pem",   // Server private key
    false,              // Disable client certificate authentication
    "",                 // No client CA needed
)
if err != nil {
    log.Fatal(err)
}

// Create server with TLS
cfg := config.ServerConfig{
    Addr:      ":7000",
    Transport: "tcp",
    TLS:       tlsConfig,
}

srv := server.NewServer(cfg)
srv.Run()
```

### Client with TLS

```go
import (
    "github.com/kawaiirei0/reitunnel"
    "github.com/kawaiirei0/reitunnel/client"
    "github.com/kawaiirei0/reitunnel/config"
)

// Create TLS configuration
tlsConfig, err := reitunnel.NewClientTLSConfig(
    "",              // No client certificate
    "",              // No client key
    "server-ca.pem", // Server CA for verification
    false,           // Don't skip verification
)
if err != nil {
    log.Fatal(err)
}

// Create client with TLS
cfg := config.ClientConfig{
    ServerAddr: "localhost:7000",
    Transport:  "tcp",
    TLS:        tlsConfig,
}

c := client.NewClient(cfg)
c.Connect()
```

## Mutual TLS (mTLS) with Client Certificate Authentication

### Server Configuration

```go
// Enable client certificate authentication
tlsConfig, err := reitunnel.NewServerTLSConfig(
    "server-cert.pem",
    "server-key.pem",
    true,            // Enable client certificate authentication
    "client-ca.pem", // Client CA certificate
)

// Create certificate authentication hook
certAuthHook := hooks.NewCertAuthHook(
    "client.example.com", // Required CN
    "Example Org",        // Required Organization
)

hm := reitunnel.NewHookManager()
hm.Register(certAuthHook)

cfg := config.ServerConfig{
    Addr:      ":7000",
    Transport: "tcp",
    TLS:       tlsConfig,
}

srv := server.NewServer(cfg, server.WithHookManager(hm))
srv.Run()
```

### Client Configuration

```go
// Provide client certificate for authentication
tlsConfig, err := reitunnel.NewClientTLSConfig(
    "client-cert.pem", // Client certificate
    "client-key.pem",  // Client private key
    "server-ca.pem",   // Server CA
    false,
)

cfg := config.ClientConfig{
    ServerAddr: "localhost:7000",
    Transport:  "tcp",
    TLS:        tlsConfig,
}

c := client.NewClient(cfg)
c.Connect()
```

## WebSocket with TLS

TLS works seamlessly with WebSocket transport:

```go
// Server
tlsConfig, _ := reitunnel.NewServerTLSConfig(
    "server-cert.pem",
    "server-key.pem",
    false,
    "",
)

cfg := config.ServerConfig{
    Addr:      ":7000",
    Transport: "websocket", // Use WebSocket
    TLS:       tlsConfig,
}

srv := server.NewServer(cfg)
srv.Run()

// Client
clientTLSConfig, _ := reitunnel.NewClientTLSConfig(
    "",
    "",
    "server-ca.pem",
    false,
)

cfg := config.ClientConfig{
    ServerAddr: "localhost:7000",
    Transport:  "websocket", // Use WebSocket
    TLS:        clientTLSConfig,
}

c := client.NewClient(cfg)
c.Connect()
```

## Custom Certificate Validation

You can implement custom certificate validation logic using hooks:

```go
import "github.com/kawaiirei0/reitunnel/hooks"

// Create custom validator
customValidator := func(cert interface{}) error {
    // Cast to x509.Certificate
    x509Cert, ok := cert.(*x509.Certificate)
    if !ok {
        return fmt.Errorf("invalid certificate type")
    }
    
    // Implement custom validation
    if x509Cert.SerialNumber.Cmp(expectedSerial) != 0 {
        return fmt.Errorf("invalid certificate serial number")
    }
    
    return nil
}

// Create hook with custom validator
certAuthHook := hooks.NewCertAuthHookWithValidator(customValidator)

hm := reitunnel.NewHookManager()
hm.Register(certAuthHook)

srv := server.NewServer(cfg, server.WithHookManager(hm))
```

## Manual TLS Configuration

For advanced use cases, you can create `tls.Config` manually:

```go
import "crypto/tls"

// Server
cert, err := tls.LoadX509KeyPair("server-cert.pem", "server-key.pem")
if err != nil {
    log.Fatal(err)
}

tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{cert},
    MinVersion:   tls.VersionTLS12,
    CipherSuites: []uint16{
        tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    },
}

cfg := config.ServerConfig{
    Addr:      ":7000",
    Transport: "tcp",
    TLS:       tlsConfig,
}

srv := server.NewServer(cfg)
```

## Generating Test Certificates

For testing purposes, you can generate self-signed certificates:

```bash
# Generate server certificate
openssl req -x509 -newkey rsa:4096 -keyout server-key.pem -out server-cert.pem -days 365 -nodes -subj "/CN=localhost"

# Generate client certificate
openssl req -x509 -newkey rsa:4096 -keyout client-key.pem -out client-cert.pem -days 365 -nodes -subj "/CN=client.example.com/O=Example Org"

# For mutual TLS, you'll need a CA certificate
openssl req -x509 -newkey rsa:4096 -keyout ca-key.pem -out ca-cert.pem -days 365 -nodes -subj "/CN=CA"

# Generate server certificate signed by CA
openssl req -newkey rsa:4096 -keyout server-key.pem -out server-csr.pem -nodes -subj "/CN=localhost"
openssl x509 -req -in server-csr.pem -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out server-cert.pem -days 365

# Generate client certificate signed by CA
openssl req -newkey rsa:4096 -keyout client-key.pem -out client-csr.pem -nodes -subj "/CN=client.example.com/O=Example Org"
openssl x509 -req -in client-csr.pem -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out client-cert.pem -days 365
```

## Security Best Practices

1. **Always use TLS in production**: Never transmit sensitive data over unencrypted connections.

2. **Use strong cipher suites**: Configure `tls.Config` with modern, secure cipher suites.

3. **Enable client certificate authentication**: For high-security environments, require client certificates.

4. **Verify certificates**: Never set `InsecureSkipVerify: true` in production.

5. **Use proper CA certificates**: Don't use self-signed certificates in production.

6. **Keep certificates up to date**: Monitor certificate expiration and rotate regularly.

7. **Protect private keys**: Store private keys securely and never commit them to version control.

8. **Use TLS 1.2 or higher**: Set `MinVersion: tls.VersionTLS12` or higher.

## Troubleshooting

### Certificate Verification Failed

```
Error: x509: certificate signed by unknown authority
```

**Solution**: Ensure the client has the correct CA certificate configured in `RootCAs`.

### Client Certificate Required

```
Error: tls: client didn't provide a certificate
```

**Solution**: The server requires client certificate authentication. Provide a valid client certificate.

### Certificate CN Mismatch

```
Error: certificate CN mismatch: expected client.example.com, got other.example.com
```

**Solution**: Ensure the client certificate has the correct Common Name (CN) as required by the server.

### Handshake Timeout

```
Error: tls: handshake timeout
```

**Solution**: Check network connectivity and increase the timeout in `ClientConfig.Timeout`.

## API Reference

### Helper Functions

#### `NewServerTLSConfig`

```go
func NewServerTLSConfig(certFile, keyFile string, clientAuth bool, clientCAFile string) (*tls.Config, error)
```

Creates a TLS configuration for the server.

**Parameters:**
- `certFile`: Path to server certificate file
- `keyFile`: Path to server private key file
- `clientAuth`: Enable client certificate authentication
- `clientCAFile`: Path to client CA certificate (required if `clientAuth` is true)

#### `NewClientTLSConfig`

```go
func NewClientTLSConfig(certFile, keyFile string, serverCAFile string, insecureSkipVerify bool) (*tls.Config, error)
```

Creates a TLS configuration for the client.

**Parameters:**
- `certFile`: Path to client certificate file (optional, for mutual TLS)
- `keyFile`: Path to client private key file (optional, for mutual TLS)
- `serverCAFile`: Path to server CA certificate (optional)
- `insecureSkipVerify`: Skip server certificate verification (not recommended for production)

#### `GetClientCertificate`

```go
func GetClientCertificate(state *tls.ConnectionState) (*x509.Certificate, error)
```

Extracts the client certificate from a TLS connection state.

#### `VerifyClientCertificate`

```go
func VerifyClientCertificate(cert *x509.Certificate, expectedCN string, expectedOrg string) error
```

Verifies that the client certificate matches expected criteria.

### Hooks

#### `CertAuthHook`

Certificate-based authentication hook.

```go
type CertAuthHook struct {
    RequiredCN  string
    RequiredOrg string
}

func NewCertAuthHook(requiredCN, requiredOrg string) *CertAuthHook
func NewCertAuthHookWithValidator(validator func(cert interface{}) error) *CertAuthHook
```

## Examples

See `examples/tls_example.go` for complete working examples of:
- Basic TLS setup
- Mutual TLS with client certificate authentication
- WebSocket with TLS
- Custom certificate validation
- Graceful shutdown with TLS

## License

This TLS implementation follows the same license as the Reitunnel project.
