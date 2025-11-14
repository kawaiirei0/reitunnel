package reitunnel

import (
	"errors"
	"testing"
)

func TestErrorConstants(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"ErrServerClosed", ErrServerClosed},
		{"ErrClientDisconnected", ErrClientDisconnected},
		{"ErrTunnelClosed", ErrTunnelClosed},
		{"ErrInvalidConfig", ErrInvalidConfig},
		{"ErrAuthFailed", ErrAuthFailed},
		{"ErrHookFailed", ErrHookFailed},
		{"ErrNotConnected", ErrNotConnected},
		{"ErrAlreadyConnected", ErrAlreadyConnected},
		{"ErrTunnelNotFound", ErrTunnelNotFound},
		{"ErrMaxConnectionsReached", ErrMaxConnectionsReached},
		{"ErrTimeout", ErrTimeout},
		{"ErrInvalidMessage", ErrInvalidMessage},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Errorf("%s is nil", tt.name)
			}
			if tt.err.Error() == "" {
				t.Errorf("%s has empty error message", tt.name)
			}
		})
	}
}

func TestTunnelError(t *testing.T) {
	baseErr := errors.New("connection failed")
	tunnelErr := NewTunnelError("tunnel-123", "read", baseErr)

	// Test Error() method
	errMsg := tunnelErr.Error()
	if errMsg == "" {
		t.Error("TunnelError.Error() returned empty string")
	}
	if errMsg != "tunnel tunnel-123: read: connection failed" {
		t.Errorf("unexpected error message: %s", errMsg)
	}

	// Test Unwrap() method
	if !errors.Is(tunnelErr, baseErr) {
		t.Error("TunnelError does not unwrap to base error")
	}

	// Test WithMeta() method
	tunnelErr.WithMeta("client_id", "client-456")
	if tunnelErr.Meta["client_id"] != "client-456" {
		t.Error("WithMeta() did not set metadata correctly")
	}
}

func TestClientError(t *testing.T) {
	baseErr := errors.New("connection refused")
	clientErr := NewClientError("client-789", "connect", baseErr)

	// Test Error() method
	errMsg := clientErr.Error()
	if errMsg != "client client-789: connect: connection refused" {
		t.Errorf("unexpected error message: %s", errMsg)
	}

	// Test Unwrap() method
	if !errors.Is(clientErr, baseErr) {
		t.Error("ClientError does not unwrap to base error")
	}

	// Test WithMeta() method
	clientErr.WithMeta("server_addr", "localhost:7000")
	if clientErr.Meta["server_addr"] != "localhost:7000" {
		t.Error("WithMeta() did not set metadata correctly")
	}
}

func TestServerError(t *testing.T) {
	baseErr := errors.New("bind failed")
	serverErr := NewServerError("start", baseErr)

	// Test Error() method
	errMsg := serverErr.Error()
	if errMsg != "server: start: bind failed" {
		t.Errorf("unexpected error message: %s", errMsg)
	}

	// Test Unwrap() method
	if !errors.Is(serverErr, baseErr) {
		t.Error("ServerError does not unwrap to base error")
	}

	// Test WithMeta() method
	serverErr.WithMeta("addr", ":7000")
	if serverErr.Meta["addr"] != ":7000" {
		t.Error("WithMeta() did not set metadata correctly")
	}
}

func TestHookError(t *testing.T) {
	baseErr := errors.New("validation failed")
	hookErr := NewHookError("AuthHook", "OnClientConnect", baseErr)

	// Test Error() method
	errMsg := hookErr.Error()
	if errMsg != "hook AuthHook failed on OnClientConnect: validation failed" {
		t.Errorf("unexpected error message: %s", errMsg)
	}

	// Test Unwrap() method
	if !errors.Is(hookErr, baseErr) {
		t.Error("HookError does not unwrap to base error")
	}

	// Test WithMeta() method
	hookErr.WithMeta("client_id", "client-123")
	if hookErr.Meta["client_id"] != "client-123" {
		t.Error("WithMeta() did not set metadata correctly")
	}
}

func TestErrorMetadata(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected map[string]string
	}{
		{
			name: "TunnelError with metadata",
			err: NewTunnelError("tunnel-123", "read", errors.New("test")).
				WithMeta("key1", "value1"),
			expected: map[string]string{
				"tunnel_id": "tunnel-123",
				"operation": "read",
				"key1":      "value1",
			},
		},
		{
			name: "ClientError with metadata",
			err: NewClientError("client-456", "connect", errors.New("test")).
				WithMeta("key2", "value2"),
			expected: map[string]string{
				"client_id": "client-456",
				"operation": "connect",
				"key2":      "value2",
			},
		},
		{
			name: "ServerError with metadata",
			err: NewServerError("start", errors.New("test")).
				WithMeta("key3", "value3"),
			expected: map[string]string{
				"operation": "start",
				"key3":      "value3",
			},
		},
		{
			name: "HookError with metadata",
			err: NewHookError("TestHook", "OnServerStart", errors.New("test")).
				WithMeta("key4", "value4"),
			expected: map[string]string{
				"hook_name": "TestHook",
				"event":     "OnServerStart",
				"key4":      "value4",
			},
		},
		{
			name:     "nil error",
			err:      nil,
			expected: nil,
		},
		{
			name:     "standard error",
			err:      errors.New("standard error"),
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			meta := ErrorMetadata(tt.err)

			if tt.expected == nil {
				if meta != nil {
					t.Errorf("expected nil metadata, got %v", meta)
				}
				return
			}

			if meta == nil {
				t.Error("expected metadata, got nil")
				return
			}

			for k, v := range tt.expected {
				if meta[k] != v {
					t.Errorf("expected meta[%s] = %s, got %s", k, v, meta[k])
				}
			}
		})
	}
}

func TestErrorWrapping(t *testing.T) {
	baseErr := ErrAuthFailed
	tunnelErr := NewTunnelError("tunnel-123", "open", baseErr)

	// Test that errors.Is works with wrapped errors
	if !errors.Is(tunnelErr, ErrAuthFailed) {
		t.Error("errors.Is does not work with wrapped TunnelError")
	}

	// Test that errors.As works with custom error types
	var te *TunnelError
	if !errors.As(tunnelErr, &te) {
		t.Error("errors.As does not work with TunnelError")
	}

	if te.TunnelID != "tunnel-123" {
		t.Errorf("expected tunnel ID 'tunnel-123', got '%s'", te.TunnelID)
	}
}
