package tunnel

import (
	"net"
	"sync"
	"time"
)

// Package tunnel provides tunnel session management for Reitunnel.
// It handles tunnel lifecycle, metadata, and statistics tracking.

// Tunnel represents a tunnel session with metadata and statistics.
type Tunnel struct {
	ID         string
	LocalAddr  string
	RemoteAddr string
	Conn       net.Conn
	Meta       map[string]string
	CreatedAt  time.Time
	BytesSent  int64
	BytesRecv  int64
	mu         sync.RWMutex
}

// Manager manages tunnel sessions with thread-safe operations.
type Manager struct {
	tunnels map[string]*Tunnel
	mu      sync.RWMutex
}

// NewManager creates a new tunnel Manager.
func NewManager() *Manager {
	return &Manager{
		tunnels: make(map[string]*Tunnel),
	}
}

// Create creates a new tunnel with the given parameters and adds it to the manager.
// It generates a unique ID using timestamp and returns the created tunnel.
func (m *Manager) Create(id, localAddr, remoteAddr string, meta map[string]string) (*Tunnel, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Create new tunnel
	tunnel := &Tunnel{
		ID:         id,
		LocalAddr:  localAddr,
		RemoteAddr: remoteAddr,
		Meta:       meta,
		CreatedAt:  time.Now(),
		BytesSent:  0,
		BytesRecv:  0,
	}

	m.tunnels[id] = tunnel
	return tunnel, nil
}

// Get retrieves a tunnel by ID with read lock protection.
// Returns the tunnel and true if found, nil and false otherwise.
func (m *Manager) Get(id string) (*Tunnel, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	tunnel, ok := m.tunnels[id]
	return tunnel, ok
}

// Remove removes a tunnel from the manager with write lock protection.
func (m *Manager) Remove(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.tunnels, id)
}

// List returns a slice of all tunnels currently managed.
func (m *Manager) List() []*Tunnel {
	m.mu.RLock()
	defer m.mu.RUnlock()

	tunnels := make([]*Tunnel, 0, len(m.tunnels))
	for _, tunnel := range m.tunnels {
		tunnels = append(tunnels, tunnel)
	}
	return tunnels
}

// AddBytesSent atomically adds to the BytesSent counter for a tunnel.
func (t *Tunnel) AddBytesSent(bytes int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.BytesSent += bytes
}

// AddBytesRecv atomically adds to the BytesRecv counter for a tunnel.
func (t *Tunnel) AddBytesRecv(bytes int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.BytesRecv += bytes
}

// GetStats returns the current statistics for the tunnel in a thread-safe manner.
func (t *Tunnel) GetStats() (sent int64, recv int64) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.BytesSent, t.BytesRecv
}
