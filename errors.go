package reitunnel

import (
	"errors"
	"fmt"
)

// Standard error constants for common error conditions in the Reitunnel System.
// These errors can be used with errors.Is() for error checking.
var (
	// ErrServerClosed indicates that the server has been closed and is no longer accepting connections.
	ErrServerClosed = errors.New("server closed")

	// ErrClientDisconnected indicates that the client has disconnected from the server.
	ErrClientDisconnected = errors.New("client disconnected")

	// ErrTunnelClosed indicates that the tunnel session has been closed.
	ErrTunnelClosed = errors.New("tunnel closed")

	// ErrInvalidConfig indicates that the provided configuration is invalid.
	ErrInvalidConfig = errors.New("invalid configuration")

	// ErrAuthFailed indicates that authentication or authorization failed.
	ErrAuthFailed = errors.New("authentication failed")

	// ErrHookFailed indicates that a hook execution failed.
	ErrHookFailed = errors.New("hook execution failed")

	// ErrNotConnected indicates that the client is not connected to the server.
	ErrNotConnected = errors.New("not connected")

	// ErrAlreadyConnected indicates that the client is already connected to the server.
	ErrAlreadyConnected = errors.New("already connected")

	// ErrTunnelNotFound indicates that the requested tunnel was not found.
	ErrTunnelNotFound = errors.New("tunnel not found")

	// ErrMaxConnectionsReached indicates that the maximum number of connections has been reached.
	ErrMaxConnectionsReached = errors.New("maximum connections reached")

	// ErrTimeout indicates that an operation timed out.
	ErrTimeout = errors.New("operation timed out")

	// ErrInvalidMessage indicates that a protocol message is invalid or malformed.
	ErrInvalidMessage = errors.New("invalid message")
)

// TunnelError represents an error that occurred during tunnel operations.
// It includes contextual information such as the tunnel ID, operation being performed,
// and the underlying error. This type implements the error interface and supports
// error wrapping/unwrapping.
type TunnelError struct {
	// TunnelID is the unique identifier of the tunnel where the error occurred.
	TunnelID string

	// Op is the operation that was being performed when the error occurred.
	// Examples: "read", "write", "open", "close"
	Op string

	// Err is the underlying error that caused this tunnel error.
	Err error

	// Meta contains additional contextual information about the error.
	// This can include client ID, addresses, or other relevant data.
	Meta map[string]string
}

// Error implements the error interface for TunnelError.
// It returns a formatted error message that includes the tunnel ID, operation,
// and the underlying error message.
func (e *TunnelError) Error() string {
	if e.TunnelID != "" {
		return fmt.Sprintf("tunnel %s: %s: %v", e.TunnelID, e.Op, e.Err)
	}
	return fmt.Sprintf("tunnel error: %s: %v", e.Op, e.Err)
}

// Unwrap implements error unwrapping for TunnelError.
// This allows errors.Is() and errors.As() to work with wrapped errors.
func (e *TunnelError) Unwrap() error {
	return e.Err
}

// NewTunnelError creates a new TunnelError with the given parameters.
func NewTunnelError(tunnelID, op string, err error) *TunnelError {
	return &TunnelError{
		TunnelID: tunnelID,
		Op:       op,
		Err:      err,
		Meta:     make(map[string]string),
	}
}

// WithMeta adds metadata to the TunnelError and returns the error for chaining.
func (e *TunnelError) WithMeta(key, value string) *TunnelError {
	if e.Meta == nil {
		e.Meta = make(map[string]string)
	}
	e.Meta[key] = value
	return e
}

// ClientError represents an error that occurred during client operations.
// It includes contextual information such as the client ID, operation being performed,
// and the underlying error.
type ClientError struct {
	// ClientID is the unique identifier of the client where the error occurred.
	ClientID string

	// Op is the operation that was being performed when the error occurred.
	// Examples: "connect", "disconnect", "send", "receive"
	Op string

	// Err is the underlying error that caused this client error.
	Err error

	// Meta contains additional contextual information about the error.
	Meta map[string]string
}

// Error implements the error interface for ClientError.
func (e *ClientError) Error() string {
	if e.ClientID != "" {
		return fmt.Sprintf("client %s: %s: %v", e.ClientID, e.Op, e.Err)
	}
	return fmt.Sprintf("client error: %s: %v", e.Op, e.Err)
}

// Unwrap implements error unwrapping for ClientError.
func (e *ClientError) Unwrap() error {
	return e.Err
}

// NewClientError creates a new ClientError with the given parameters.
func NewClientError(clientID, op string, err error) *ClientError {
	return &ClientError{
		ClientID: clientID,
		Op:       op,
		Err:      err,
		Meta:     make(map[string]string),
	}
}

// WithMeta adds metadata to the ClientError and returns the error for chaining.
func (e *ClientError) WithMeta(key, value string) *ClientError {
	if e.Meta == nil {
		e.Meta = make(map[string]string)
	}
	e.Meta[key] = value
	return e
}

// ServerError represents an error that occurred during server operations.
// It includes contextual information about the operation and underlying error.
type ServerError struct {
	// Op is the operation that was being performed when the error occurred.
	// Examples: "start", "stop", "accept", "shutdown"
	Op string

	// Err is the underlying error that caused this server error.
	Err error

	// Meta contains additional contextual information about the error.
	Meta map[string]string
}

// Error implements the error interface for ServerError.
func (e *ServerError) Error() string {
	return fmt.Sprintf("server: %s: %v", e.Op, e.Err)
}

// Unwrap implements error unwrapping for ServerError.
func (e *ServerError) Unwrap() error {
	return e.Err
}

// NewServerError creates a new ServerError with the given parameters.
func NewServerError(op string, err error) *ServerError {
	return &ServerError{
		Op:   op,
		Err:  err,
		Meta: make(map[string]string),
	}
}

// WithMeta adds metadata to the ServerError and returns the error for chaining.
func (e *ServerError) WithMeta(key, value string) *ServerError {
	if e.Meta == nil {
		e.Meta = make(map[string]string)
	}
	e.Meta[key] = value
	return e
}

// HookError represents an error that occurred during hook execution.
// It includes information about which hook failed and during which event.
type HookError struct {
	// HookName is the name or type of the hook that failed.
	HookName string

	// Event is the event that was being processed when the hook failed.
	// Examples: "OnServerStart", "OnClientConnect", "OnTunnelOpen"
	Event string

	// Err is the underlying error returned by the hook.
	Err error

	// Meta contains additional contextual information about the error.
	Meta map[string]string
}

// Error implements the error interface for HookError.
func (e *HookError) Error() string {
	if e.HookName != "" {
		return fmt.Sprintf("hook %s failed on %s: %v", e.HookName, e.Event, e.Err)
	}
	return fmt.Sprintf("hook failed on %s: %v", e.Event, e.Err)
}

// Unwrap implements error unwrapping for HookError.
func (e *HookError) Unwrap() error {
	return e.Err
}

// NewHookError creates a new HookError with the given parameters.
func NewHookError(hookName, event string, err error) *HookError {
	return &HookError{
		HookName: hookName,
		Event:    event,
		Err:      err,
		Meta:     make(map[string]string),
	}
}

// WithMeta adds metadata to the HookError and returns the error for chaining.
func (e *HookError) WithMeta(key, value string) *HookError {
	if e.Meta == nil {
		e.Meta = make(map[string]string)
	}
	e.Meta[key] = value
	return e
}

// ErrorMetadata extracts metadata from an error if it contains any.
// This works with TunnelError, ClientError, ServerError, and HookError types.
// Returns nil if the error doesn't contain metadata.
func ErrorMetadata(err error) map[string]string {
	if err == nil {
		return nil
	}

	// Check for TunnelError
	var tunnelErr *TunnelError
	if errors.As(err, &tunnelErr) && tunnelErr.Meta != nil {
		meta := make(map[string]string, len(tunnelErr.Meta)+2)
		for k, v := range tunnelErr.Meta {
			meta[k] = v
		}
		meta["tunnel_id"] = tunnelErr.TunnelID
		meta["operation"] = tunnelErr.Op
		return meta
	}

	// Check for ClientError
	var clientErr *ClientError
	if errors.As(err, &clientErr) && clientErr.Meta != nil {
		meta := make(map[string]string, len(clientErr.Meta)+2)
		for k, v := range clientErr.Meta {
			meta[k] = v
		}
		meta["client_id"] = clientErr.ClientID
		meta["operation"] = clientErr.Op
		return meta
	}

	// Check for ServerError
	var serverErr *ServerError
	if errors.As(err, &serverErr) && serverErr.Meta != nil {
		meta := make(map[string]string, len(serverErr.Meta)+1)
		for k, v := range serverErr.Meta {
			meta[k] = v
		}
		meta["operation"] = serverErr.Op
		return meta
	}

	// Check for HookError
	var hookErr *HookError
	if errors.As(err, &hookErr) && hookErr.Meta != nil {
		meta := make(map[string]string, len(hookErr.Meta)+2)
		for k, v := range hookErr.Meta {
			meta[k] = v
		}
		meta["hook_name"] = hookErr.HookName
		meta["event"] = hookErr.Event
		return meta
	}

	return nil
}
