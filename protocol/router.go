package protocol

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// MessageHandler is a function that handles a specific message type.
type MessageHandler func(ctx context.Context, msg *Message) error

// Router routes incoming messages to registered handlers based on message type.
// It provides thread-safe registration and routing of protocol messages.
type Router struct {
	handlers map[MessageType]MessageHandler
	mu       sync.RWMutex
}

// NewRouter creates a new message router.
func NewRouter() *Router {
	return &Router{
		handlers: make(map[MessageType]MessageHandler),
	}
}

// Register registers a handler for a specific message type.
// If a handler is already registered for the type, it will be replaced.
func (r *Router) Register(msgType MessageType, handler MessageHandler) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.handlers[msgType] = handler
}

// Route reads a message from the reader and routes it to the appropriate handler.
// It returns an error if decoding fails or if no handler is registered for the message type.
func (r *Router) Route(ctx context.Context, reader io.Reader) error {
	// Decode the message
	msg, err := Decode(reader)
	if err != nil {
		return fmt.Errorf("failed to decode message: %w", err)
	}

	// Get the handler for this message type
	r.mu.RLock()
	handler, ok := r.handlers[msg.Type]
	r.mu.RUnlock()

	if !ok {
		return fmt.Errorf("no handler registered for message type %s", msg.Type)
	}

	// Call the handler
	if err := handler(ctx, msg); err != nil {
		return fmt.Errorf("handler failed for message type %s: %w", msg.Type, err)
	}

	return nil
}

// Handle is a convenience method that continuously reads and routes messages
// from the reader until an error occurs or the context is cancelled.
// It sets read deadlines on net.Conn to ensure responsiveness to cancellation.
func (r *Router) Handle(ctx context.Context, reader io.Reader) error {
	// Try to cast reader to net.Conn to set deadlines
	conn, isConn := reader.(net.Conn)

	for {
		// Check context before each read
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Set a read deadline if we have a net.Conn
		// This makes the blocking read operation cancellable
		if isConn {
			// Use context deadline if available, otherwise use a short timeout
			// to periodically check context cancellation
			deadline := time.Now().Add(1 * time.Second)
			if ctxDeadline, ok := ctx.Deadline(); ok {
				deadline = ctxDeadline
			}
			conn.SetReadDeadline(deadline)
		}

		err := r.Route(ctx, reader)
		if err != nil {
			// Check if it's a timeout error
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Check if context is cancelled
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
					// Just a read timeout, continue reading
					continue
				}
			}
			// Other error, return it
			return err
		}
	}
}

// Unregister removes the handler for a specific message type.
func (r *Router) Unregister(msgType MessageType) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.handlers, msgType)
}

// HasHandler checks if a handler is registered for the given message type.
func (r *Router) HasHandler(msgType MessageType) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.handlers[msgType]
	return ok
}
