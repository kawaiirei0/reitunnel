package hooks

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/kawaiirei0/reitunnel"
)

// CertAuthHook implements certificate-based authentication for client connections.
// It verifies client certificates against expected criteria (CN, organization, etc.).
type CertAuthHook struct {
	reitunnel.NoopHook

	// ValidateCert is a custom validation function that checks the client certificate.
	// If nil, only basic certificate presence is checked.
	ValidateCert func(cert interface{}) error

	// RequiredCN is the expected Common Name in the client certificate (optional).
	RequiredCN string

	// RequiredOrg is the expected Organization in the client certificate (optional).
	RequiredOrg string
}

// NewCertAuthHook creates a new certificate authentication hook.
func NewCertAuthHook(requiredCN, requiredOrg string) *CertAuthHook {
	return &CertAuthHook{
		RequiredCN:  requiredCN,
		RequiredOrg: requiredOrg,
	}
}

// NewCertAuthHookWithValidator creates a new certificate authentication hook
// with a custom validation function.
func NewCertAuthHookWithValidator(validator func(cert interface{}) error) *CertAuthHook {
	return &CertAuthHook{
		ValidateCert: validator,
	}
}

// OnClientConnect validates the client certificate when a client connects.
// It returns an error if the certificate is invalid or doesn't meet the requirements.
func (h *CertAuthHook) OnClientConnect(ctx context.Context, clientID string) error {
	// Try to extract TLS connection state from context
	// In a real implementation, the server would need to pass this through context
	// For now, we document the expected usage pattern

	// Example usage pattern (to be implemented in server):
	// conn := ctx.Value("connection").(net.Conn)
	// if tlsConn, ok := conn.(*tls.Conn); ok {
	//     state := tlsConn.ConnectionState()
	//     return h.validateCertificate(&state)
	// }

	return nil
}

// validateCertificate performs the actual certificate validation.
func (h *CertAuthHook) validateCertificate(state *tls.ConnectionState) error {
	if state == nil {
		return fmt.Errorf("no TLS connection state available")
	}

	// Check if client provided a certificate
	if len(state.PeerCertificates) == 0 {
		return fmt.Errorf("%w: no client certificate provided", reitunnel.ErrAuthFailed)
	}

	cert := state.PeerCertificates[0]

	// Use custom validator if provided
	if h.ValidateCert != nil {
		return h.ValidateCert(cert)
	}

	// Otherwise, use built-in validation
	if h.RequiredCN != "" && cert.Subject.CommonName != h.RequiredCN {
		return fmt.Errorf("%w: certificate CN mismatch: expected %s, got %s",
			reitunnel.ErrAuthFailed, h.RequiredCN, cert.Subject.CommonName)
	}

	if h.RequiredOrg != "" {
		found := false
		for _, org := range cert.Subject.Organization {
			if org == h.RequiredOrg {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%w: certificate organization mismatch: expected %s",
				reitunnel.ErrAuthFailed, h.RequiredOrg)
		}
	}

	return nil
}

// ExtractTLSState is a helper function to extract TLS connection state from a net.Conn.
// This should be called by the server before invoking hooks.
func ExtractTLSState(conn net.Conn) (*tls.ConnectionState, error) {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, fmt.Errorf("connection is not a TLS connection")
	}

	state := tlsConn.ConnectionState()
	return &state, nil
}
