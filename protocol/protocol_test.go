package protocol

import (
	"bytes"
	"testing"
)

func TestMessageEncodeDecode(t *testing.T) {
	tests := []struct {
		name    string
		msg     *Message
		wantErr bool
	}{
		{
			name: "handshake message",
			msg: &Message{
				Type:     MsgTypeHandshake,
				TunnelID: "",
				Payload:  []byte("hello"),
			},
			wantErr: false,
		},
		{
			name: "tunnel open message",
			msg: &Message{
				Type:     MsgTypeTunnelOpen,
				TunnelID: "tunnel-123",
				Payload:  []byte("localhost:8080->0.0.0.0:80"),
			},
			wantErr: false,
		},
		{
			name: "data message",
			msg: &Message{
				Type:     MsgTypeData,
				TunnelID: "tunnel-456",
				Payload:  []byte("some data payload"),
			},
			wantErr: false,
		},
		{
			name: "tunnel close message",
			msg: &Message{
				Type:     MsgTypeTunnelClose,
				TunnelID: "tunnel-789",
				Payload:  nil,
			},
			wantErr: false,
		},
		{
			name: "error message",
			msg: &Message{
				Type:     MsgTypeError,
				TunnelID: "tunnel-error",
				Payload:  []byte("error occurred"),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode the message
			var buf bytes.Buffer
			err := tt.msg.Encode(&buf)
			if (err != nil) != tt.wantErr {
				t.Errorf("Message.Encode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Decode the message
			decoded, err := Decode(&buf)
			if err != nil {
				t.Errorf("Decode() error = %v", err)
				return
			}

			// Compare the messages
			if decoded.Type != tt.msg.Type {
				t.Errorf("Type mismatch: got %v, want %v", decoded.Type, tt.msg.Type)
			}
			if decoded.TunnelID != tt.msg.TunnelID {
				t.Errorf("TunnelID mismatch: got %v, want %v", decoded.TunnelID, tt.msg.TunnelID)
			}
			if !bytes.Equal(decoded.Payload, tt.msg.Payload) {
				t.Errorf("Payload mismatch: got %v, want %v", decoded.Payload, tt.msg.Payload)
			}
		})
	}
}

func TestMessageValidation(t *testing.T) {
	tests := []struct {
		name    string
		msg     *Message
		wantErr bool
	}{
		{
			name: "valid handshake",
			msg: &Message{
				Type:     MsgTypeHandshake,
				TunnelID: "",
				Payload:  []byte("test"),
			},
			wantErr: false,
		},
		{
			name: "invalid handshake with tunnel ID",
			msg: &Message{
				Type:     MsgTypeHandshake,
				TunnelID: "should-not-have-id",
				Payload:  []byte("test"),
			},
			wantErr: true,
		},
		{
			name: "tunnel open without tunnel ID",
			msg: &Message{
				Type:     MsgTypeTunnelOpen,
				TunnelID: "",
				Payload:  []byte("test"),
			},
			wantErr: true,
		},
		{
			name: "valid tunnel open",
			msg: &Message{
				Type:     MsgTypeTunnelOpen,
				TunnelID: "tunnel-123",
				Payload:  []byte("test"),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.msg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Message.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewMessageHelpers(t *testing.T) {
	t.Run("NewHandshakeMessage", func(t *testing.T) {
		msg := NewHandshakeMessage([]byte("hello"))
		if msg.Type != MsgTypeHandshake {
			t.Errorf("Expected type %v, got %v", MsgTypeHandshake, msg.Type)
		}
		if msg.TunnelID != "" {
			t.Errorf("Expected empty tunnel ID, got %v", msg.TunnelID)
		}
	})

	t.Run("NewTunnelOpenMessage", func(t *testing.T) {
		msg := NewTunnelOpenMessage("tunnel-123", []byte("data"))
		if msg.Type != MsgTypeTunnelOpen {
			t.Errorf("Expected type %v, got %v", MsgTypeTunnelOpen, msg.Type)
		}
		if msg.TunnelID != "tunnel-123" {
			t.Errorf("Expected tunnel ID 'tunnel-123', got %v", msg.TunnelID)
		}
	})

	t.Run("NewDataMessage", func(t *testing.T) {
		msg := NewDataMessage("tunnel-456", []byte("payload"))
		if msg.Type != MsgTypeData {
			t.Errorf("Expected type %v, got %v", MsgTypeData, msg.Type)
		}
	})
}
