package config

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// Package config provides configuration structures for Reitunnel
// Server and Client components.

var (
	// ErrInvalidAddr is returned when an address is invalid or empty
	ErrInvalidAddr = errors.New("invalid or empty address")

	// ErrInvalidTransport is returned when transport type is not supported
	ErrInvalidTransport = errors.New("invalid transport type, must be 'tcp' or 'websocket'")

	// ErrInvalidMaxConns is returned when MaxConns is negative
	ErrInvalidMaxConns = errors.New("MaxConns cannot be negative")

	// ErrInvalidTimeout is returned when Timeout is negative
	ErrInvalidTimeout = errors.New("Timeout cannot be negative")
)

// ServerConfig holds configuration for the Server Component.
type ServerConfig struct {
	// Addr is the address to listen on (e.g., ":7000")
	Addr string

	// Transport specifies the transport protocol ("tcp" or "websocket")
	Transport string

	// TLS configuration for secure connections (optional)
	TLS *tls.Config

	// MaxConns is the maximum number of concurrent client connections (0 = unlimited)
	MaxConns int

	// Timeout for connection operations
	Timeout time.Duration
}

// ClientConfig holds configuration for the Client Component.
type ClientConfig struct {
	// ServerAddr is the server address to connect to
	ServerAddr string

	// Transport specifies the transport protocol ("tcp" or "websocket")
	Transport string

	// TLS configuration for secure connections (optional)
	TLS *tls.Config

	// Reconnect enables automatic reconnection on disconnect
	Reconnect bool

	// Timeout for connection operations
	Timeout time.Duration
}

// Validate checks if the ServerConfig is valid
func (c *ServerConfig) Validate() error {
	// Validate address
	if c.Addr == "" {
		return ErrInvalidAddr
	}

	// Try to parse the address to ensure it's valid
	host, port, err := net.SplitHostPort(c.Addr)
	if err != nil {
		// If SplitHostPort fails, check if it's just a port (e.g., ":7000")
		if !strings.HasPrefix(c.Addr, ":") {
			return fmt.Errorf("%w: %v", ErrInvalidAddr, err)
		}
	} else {
		// Validate that port is not empty
		if port == "" {
			return fmt.Errorf("%w: port is required", ErrInvalidAddr)
		}
		// Host can be empty (means all interfaces)
		_ = host
	}

	// Validate transport
	if c.Transport == "" {
		c.Transport = "tcp" // default to tcp
	}
	if c.Transport != "tcp" && c.Transport != "websocket" {
		return ErrInvalidTransport
	}

	// Validate MaxConns
	if c.MaxConns < 0 {
		return ErrInvalidMaxConns
	}

	// Validate Timeout
	if c.Timeout < 0 {
		return ErrInvalidTimeout
	}

	return nil
}

// Validate checks if the ClientConfig is valid
func (c *ClientConfig) Validate() error {
	// Validate server address
	if c.ServerAddr == "" {
		return ErrInvalidAddr
	}

	// Try to parse the address to ensure it's valid
	host, port, err := net.SplitHostPort(c.ServerAddr)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidAddr, err)
	}

	// Both host and port are required for client
	if host == "" {
		return fmt.Errorf("%w: host is required", ErrInvalidAddr)
	}
	if port == "" {
		return fmt.Errorf("%w: port is required", ErrInvalidAddr)
	}

	// Validate transport
	if c.Transport == "" {
		c.Transport = "tcp" // default to tcp
	}
	if c.Transport != "tcp" && c.Transport != "websocket" {
		return ErrInvalidTransport
	}

	// Validate Timeout
	if c.Timeout < 0 {
		return ErrInvalidTimeout
	}

	return nil
}
