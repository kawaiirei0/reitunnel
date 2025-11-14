package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Package protocol provides message handling for the Reitunnel protocol.
// It defines message types, encoding/decoding functions, and message routing.

// MessageType represents the type of protocol message.
type MessageType uint8

const (
	// MsgTypeHandshake is sent during initial connection handshake
	MsgTypeHandshake MessageType = iota

	// MsgTypeTunnelOpen is sent to request opening a new tunnel
	MsgTypeTunnelOpen

	// MsgTypeTunnelClose is sent to close an existing tunnel
	MsgTypeTunnelClose

	// MsgTypeData is sent to transfer data through a tunnel
	MsgTypeData

	// MsgTypeError is sent to communicate errors
	MsgTypeError
)

// String returns the string representation of a MessageType.
func (mt MessageType) String() string {
	switch mt {
	case MsgTypeHandshake:
		return "Handshake"
	case MsgTypeTunnelOpen:
		return "TunnelOpen"
	case MsgTypeTunnelClose:
		return "TunnelClose"
	case MsgTypeData:
		return "Data"
	case MsgTypeError:
		return "Error"
	default:
		return fmt.Sprintf("Unknown(%d)", mt)
	}
}

// Message represents a protocol message exchanged between client and server.
type Message struct {
	// Type is the message type
	Type MessageType

	// TunnelID identifies the tunnel this message relates to (empty for handshake)
	TunnelID string

	// Payload contains the message data
	Payload []byte
}

var (
	// ErrInvalidMessageType is returned when an unknown message type is encountered
	ErrInvalidMessageType = errors.New("invalid message type")

	// ErrMessageTooLarge is returned when a message exceeds the maximum size
	ErrMessageTooLarge = errors.New("message too large")

	// ErrInvalidMessage is returned when a message is malformed
	ErrInvalidMessage = errors.New("invalid message format")
)

const (
	// MaxMessageSize is the maximum size of a message (16MB)
	MaxMessageSize = 16 * 1024 * 1024

	// MaxTunnelIDLength is the maximum length of a tunnel ID
	MaxTunnelIDLength = 256
)

// Encode encodes a Message into binary format and writes it to the writer.
// Message format:
//   - 1 byte: MessageType
//   - 2 bytes: TunnelID length (uint16, big-endian)
//   - N bytes: TunnelID (UTF-8 string)
//   - 4 bytes: Payload length (uint32, big-endian)
//   - M bytes: Payload data
func (m *Message) Encode(w io.Writer) error {
	// Validate message
	if err := m.Validate(); err != nil {
		return err
	}

	// Write message type
	if err := binary.Write(w, binary.BigEndian, m.Type); err != nil {
		return fmt.Errorf("failed to write message type: %w", err)
	}

	// Write tunnel ID length
	tunnelIDLen := uint16(len(m.TunnelID))
	if err := binary.Write(w, binary.BigEndian, tunnelIDLen); err != nil {
		return fmt.Errorf("failed to write tunnel ID length: %w", err)
	}

	// Write tunnel ID
	if tunnelIDLen > 0 {
		if _, err := w.Write([]byte(m.TunnelID)); err != nil {
			return fmt.Errorf("failed to write tunnel ID: %w", err)
		}
	}

	// Write payload length
	payloadLen := uint32(len(m.Payload))
	if err := binary.Write(w, binary.BigEndian, payloadLen); err != nil {
		return fmt.Errorf("failed to write payload length: %w", err)
	}

	// Write payload
	if payloadLen > 0 {
		if _, err := w.Write(m.Payload); err != nil {
			return fmt.Errorf("failed to write payload: %w", err)
		}
	}

	return nil
}

// Decode reads and decodes a Message from the reader.
func Decode(r io.Reader) (*Message, error) {
	msg := &Message{}

	// Read message type
	var msgType MessageType
	if err := binary.Read(r, binary.BigEndian, &msgType); err != nil {
		return nil, fmt.Errorf("failed to read message type: %w", err)
	}
	msg.Type = msgType

	// Read tunnel ID length
	var tunnelIDLen uint16
	if err := binary.Read(r, binary.BigEndian, &tunnelIDLen); err != nil {
		return nil, fmt.Errorf("failed to read tunnel ID length: %w", err)
	}

	// Validate tunnel ID length
	if tunnelIDLen > MaxTunnelIDLength {
		return nil, fmt.Errorf("%w: tunnel ID length %d exceeds maximum %d",
			ErrInvalidMessage, tunnelIDLen, MaxTunnelIDLength)
	}

	// Read tunnel ID
	if tunnelIDLen > 0 {
		tunnelIDBytes := make([]byte, tunnelIDLen)
		if _, err := io.ReadFull(r, tunnelIDBytes); err != nil {
			return nil, fmt.Errorf("failed to read tunnel ID: %w", err)
		}
		msg.TunnelID = string(tunnelIDBytes)
	}

	// Read payload length
	var payloadLen uint32
	if err := binary.Read(r, binary.BigEndian, &payloadLen); err != nil {
		return nil, fmt.Errorf("failed to read payload length: %w", err)
	}

	// Validate payload length
	if payloadLen > MaxMessageSize {
		return nil, fmt.Errorf("%w: payload length %d exceeds maximum %d",
			ErrMessageTooLarge, payloadLen, MaxMessageSize)
	}

	// Read payload
	if payloadLen > 0 {
		msg.Payload = make([]byte, payloadLen)
		if _, err := io.ReadFull(r, msg.Payload); err != nil {
			return nil, fmt.Errorf("failed to read payload: %w", err)
		}
	}

	// Validate the decoded message
	if err := msg.Validate(); err != nil {
		return nil, err
	}

	return msg, nil
}

// Validate checks if the message is valid.
func (m *Message) Validate() error {
	// Validate message type
	if m.Type > MsgTypeError {
		return fmt.Errorf("%w: %d", ErrInvalidMessageType, m.Type)
	}

	// Validate tunnel ID length
	if len(m.TunnelID) > MaxTunnelIDLength {
		return fmt.Errorf("%w: tunnel ID too long", ErrInvalidMessage)
	}

	// Validate payload length
	if len(m.Payload) > MaxMessageSize {
		return ErrMessageTooLarge
	}

	// Type-specific validation
	switch m.Type {
	case MsgTypeTunnelOpen, MsgTypeTunnelClose, MsgTypeData:
		// These message types require a tunnel ID
		if m.TunnelID == "" {
			return fmt.Errorf("%w: %s message requires tunnel ID", ErrInvalidMessage, m.Type)
		}
	case MsgTypeHandshake:
		// Handshake should not have a tunnel ID
		if m.TunnelID != "" {
			return fmt.Errorf("%w: handshake message should not have tunnel ID", ErrInvalidMessage)
		}
	}

	return nil
}

// NewHandshakeMessage creates a new handshake message.
func NewHandshakeMessage(payload []byte) *Message {
	return &Message{
		Type:     MsgTypeHandshake,
		TunnelID: "",
		Payload:  payload,
	}
}

// NewTunnelOpenMessage creates a new tunnel open message.
func NewTunnelOpenMessage(tunnelID string, payload []byte) *Message {
	return &Message{
		Type:     MsgTypeTunnelOpen,
		TunnelID: tunnelID,
		Payload:  payload,
	}
}

// NewTunnelCloseMessage creates a new tunnel close message.
func NewTunnelCloseMessage(tunnelID string, payload []byte) *Message {
	return &Message{
		Type:     MsgTypeTunnelClose,
		TunnelID: tunnelID,
		Payload:  payload,
	}
}

// NewDataMessage creates a new data message.
func NewDataMessage(tunnelID string, data []byte) *Message {
	return &Message{
		Type:     MsgTypeData,
		TunnelID: tunnelID,
		Payload:  data,
	}
}

// NewErrorMessage creates a new error message.
func NewErrorMessage(tunnelID string, errorMsg []byte) *Message {
	return &Message{
		Type:     MsgTypeError,
		TunnelID: tunnelID,
		Payload:  errorMsg,
	}
}
