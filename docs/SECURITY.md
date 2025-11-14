# Security Considerations

This guide provides comprehensive security recommendations for deploying and operating Reitunnel in production environments. Security should be a primary concern when exposing tunnel services.

## Table of Contents

- [Threat Model](#threat-model)
- [Authentication and Authorization](#authentication-and-authorization)
- [TLS Configuration](#tls-configuration)
- [Network Security](#network-security)
- [Input Validation](#input-validation)
- [Rate Limiting and DoS Protection](#rate-limiting-and-dos-protection)
- [Logging and Auditing](#logging-and-auditing)
- [Secure Deployment](#secure-deployment)
- [Security Checklist](#security-checklist)

## Threat Model

Understanding potential threats helps prioritize security measures:

### Threats

1. **Unauthorized Access**: Attackers connecting without proper credentials
2. **Man-in-the-Middle**: Interception of tunnel traffic
3. **Denial of Service**: Resource exhaustion attacks
4. **Privilege Escalation**: Unauthorized tunnel creation or port access
5. **Data Exfiltration**: Unauthorized data transfer through tunnels
6. **Replay Attacks**: Reusing captured authentication tokens
7. **Side-Channel Attacks**: Information leakage through timing or errors

### Assets to Protect

- Server infrastructure and resources
- Client credentials and certificates
- Tunnel data in transit
- Configuration and secrets
- Audit logs and metrics

## Authentication and Authorization

### Client Authentication

Always authenticate clients before allowing connections:

```go
// Token-based authentication
type TokenAuthHook struct {
    reitunnel.NoopHook
    validTokens map[string]bool
    mu          sync.RWMutex
}

func (h *TokenAuthHook) OnClientConnect(ctx context.Context, clientID string) error {
    // Extract token from clientID or context
    token := extractToken(clientID)
    
    h.mu.RLock()
    valid := h.validTokens[token]
    h.mu.RUnlock()
    
    if !valid {
        return fmt.Errorf("%w: invalid token", reitunnel.ErrAuthFailed)
    }
    return nil
}
```

**Best Practices**:
- Use strong, randomly generated tokens (minimum 32 bytes)
- Implement token rotation and expiration
- Store tokens securely (hashed, not plaintext)
- Use constant-time comparison to prevent timing attacks

### Certificate-Based Authentication

Use mutual TLS for strong authentication:

```go
// Server configuration with client certificate verification
tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{serverCert},
    ClientAuth:   tls.RequireAndVerifyClientCert,
    ClientCAs:    caCertPool,
    MinVersion:   tls.VersionTLS13,
}

srv := server.NewServer(config.ServerConfig{
    Addr: ":7000",
    TLS:  tlsConfig,
})

// Certificate validation hook
certHook := hooks.NewCertAuthHook("expected-cn", "expected-org")
hm.Register(certHook)
```

**Best Practices**:
- Use separate CA for client certificates
- Implement certificate revocation (CRL or OCSP)
- Set appropriate certificate validity periods (1 year maximum)
- Validate certificate fields (CN, Organization, etc.)
- Monitor certificate expiration

### Tunnel Authorization

Control which tunnels clients can create:

```go
type TunnelAuthHook struct {
    reitunnel.NoopHook
    allowedPorts map[string][]int // clientID -> allowed ports
    mu           sync.RWMutex
}

func (h *TunnelAuthHook) OnTunnelOpen(ctx context.Context, tunnelID string, meta map[string]string) error {
    clientID := meta["client_id"]
    remoteAddr := meta["remote_addr"]
    
    // Parse port from address
    _, portStr, err := net.SplitHostPort(remoteAddr)
    if err != nil {
        return fmt.Errorf("%w: invalid address", reitunnel.ErrAuthFailed)
    }
    
    port, _ := strconv.Atoi(portStr)
    
    // Check if client is allowed to use this port
    h.mu.RLock()
    allowed := h.allowedPorts[clientID]
    h.mu.RUnlock()
    
    for _, p := range allowed {
        if p == port {
            return nil
        }
    }
    
    return fmt.Errorf("%w: port %d not allowed", reitunnel.ErrAuthFailed, port)
}
```

**Best Practices**:
- Implement least privilege (only allow necessary ports)
- Restrict privileged ports (<1024) by default
- Validate both local and remote addresses
- Implement per-client quotas (max tunnels, bandwidth)
- Log all authorization decisions

## TLS Configuration

### Server TLS Configuration

Use strong TLS settings:

```go
tlsConfig := &tls.Config{
    // Use only strong cipher suites
    CipherSuites: []uint16{
        tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    },
    
    // Require TLS 1.3 (or minimum 1.2)
    MinVersion: tls.VersionTLS13,
    
    // Prefer server cipher suites
    PreferServerCipherSuites: true,
    
    // Require client certificates
    ClientAuth: tls.RequireAndVerifyClientCert,
    ClientCAs:  caCertPool,
    
    // Disable session tickets for forward secrecy
    SessionTicketsDisabled: false, // Enable for performance, disable for max security
}
```

**Best Practices**:
- Always use TLS 1.3 (or minimum TLS 1.2)
- Disable weak cipher suites (RC4, 3DES, CBC mode)
- Use ECDHE for forward secrecy
- Rotate certificates regularly
- Use strong key sizes (RSA 2048+, ECDSA 256+)

### Client TLS Configuration

```go
tlsConfig := &tls.Config{
    // Client certificate for mutual TLS
    Certificates: []tls.Certificate{clientCert},
    
    // Verify server certificate
    RootCAs:            caCertPool,
    InsecureSkipVerify: false, // NEVER set to true in production
    
    // Verify server name
    ServerName: "tunnel.example.com",
    
    // Minimum TLS version
    MinVersion: tls.VersionTLS13,
}
```

**Best Practices**:
- Always verify server certificates
- Pin expected server certificate or CA
- Use proper server name verification
- Never disable certificate verification in production

### Certificate Management

```go
// Load certificates securely
func loadCertificate(certFile, keyFile string) (tls.Certificate, error) {
    // Check file permissions (should be 0600 or 0400)
    info, err := os.Stat(keyFile)
    if err != nil {
        return tls.Certificate{}, err
    }
    
    if info.Mode().Perm() & 0077 != 0 {
        return tls.Certificate{}, fmt.Errorf("key file has insecure permissions: %v", info.Mode())
    }
    
    return tls.LoadX509KeyPair(certFile, keyFile)
}
```

**Best Practices**:
- Store private keys with restricted permissions (0600)
- Use hardware security modules (HSM) for production keys
- Implement automated certificate renewal
- Monitor certificate expiration
- Use separate certificates for different environments

## Network Security

### Firewall Configuration

Restrict network access:

```bash
# Allow only necessary ports
iptables -A INPUT -p tcp --dport 7000 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -j DROP

# Rate limit connections
iptables -A INPUT -p tcp --dport 7000 -m connlimit --connlimit-above 100 -j REJECT
```

**Best Practices**:
- Use firewall rules to restrict access
- Implement connection rate limiting
- Use VPN or private networks when possible
- Segment networks (separate tunnel network from internal)

### IP Whitelisting

Restrict access by IP address:

```go
type IPWhitelistHook struct {
    reitunnel.NoopHook
    allowedIPs map[string]bool
    mu         sync.RWMutex
}

func (h *IPWhitelistHook) OnClientConnect(ctx context.Context, clientID string) error {
    // Extract IP from clientID (format: "ip:port")
    ip, _, err := net.SplitHostPort(clientID)
    if err != nil {
        return fmt.Errorf("%w: invalid client ID", reitunnel.ErrAuthFailed)
    }
    
    h.mu.RLock()
    allowed := h.allowedIPs[ip]
    h.mu.RUnlock()
    
    if !allowed {
        return fmt.Errorf("%w: IP %s not whitelisted", reitunnel.ErrAuthFailed, ip)
    }
    return nil
}
```

**Best Practices**:
- Maintain IP whitelist for known clients
- Use CIDR ranges for network-based access
- Combine with other authentication methods
- Log rejected connection attempts

## Input Validation

### Address Validation

Validate all addresses before use:

```go
func validateAddress(addr string) error {
    host, port, err := net.SplitHostPort(addr)
    if err != nil {
        return fmt.Errorf("invalid address format: %w", err)
    }
    
    // Validate port range
    portNum, err := strconv.Atoi(port)
    if err != nil || portNum < 1 || portNum > 65535 {
        return fmt.Errorf("invalid port: %s", port)
    }
    
    // Prevent binding to privileged ports (unless explicitly allowed)
    if portNum < 1024 {
        return fmt.Errorf("privileged port not allowed: %d", portNum)
    }
    
    // Validate host (prevent SSRF)
    if host != "" && host != "0.0.0.0" && host != "localhost" {
        ip := net.ParseIP(host)
        if ip == nil {
            return fmt.Errorf("invalid IP address: %s", host)
        }
        
        // Prevent access to private networks
        if isPrivateIP(ip) {
            return fmt.Errorf("private IP not allowed: %s", host)
        }
    }
    
    return nil
}

func isPrivateIP(ip net.IP) bool {
    // Check for private IP ranges
    privateRanges := []string{
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
    }
    
    for _, cidr := range privateRanges {
        _, network, _ := net.ParseCIDR(cidr)
        if network.Contains(ip) {
            return true
        }
    }
    return false
}
```

**Best Practices**:
- Validate all user-provided addresses
- Prevent SSRF by blocking private IPs
- Restrict port ranges
- Sanitize metadata fields
- Use allowlists instead of denylists

### Protocol Message Validation

Validate all protocol messages:

```go
func (m *Message) Validate() error {
    // Check message type
    if m.Type > protocol.MsgTypeError {
        return fmt.Errorf("%w: invalid message type", reitunnel.ErrInvalidMessage)
    }
    
    // Check tunnel ID format
    if m.TunnelID != "" && !isValidTunnelID(m.TunnelID) {
        return fmt.Errorf("%w: invalid tunnel ID", reitunnel.ErrInvalidMessage)
    }
    
    // Check payload size
    if len(m.Payload) > MaxPayloadSize {
        return fmt.Errorf("%w: payload too large", reitunnel.ErrInvalidMessage)
    }
    
    return nil
}
```

**Best Practices**:
- Validate all message fields
- Enforce size limits
- Check for malformed data
- Reject invalid messages early

## Rate Limiting and DoS Protection

### Connection Rate Limiting

Limit connection attempts:

```go
type RateLimitHook struct {
    reitunnel.NoopHook
    limiters map[string]*rate.Limiter
    mu       sync.RWMutex
}

func NewRateLimitHook(rps int, burst int) *RateLimitHook {
    return &RateLimitHook{
        limiters: make(map[string]*rate.Limiter),
    }
}

func (h *RateLimitHook) OnClientConnect(ctx context.Context, clientID string) error {
    // Extract IP from clientID
    ip, _, _ := net.SplitHostPort(clientID)
    
    h.mu.Lock()
    limiter, ok := h.limiters[ip]
    if !ok {
        limiter = rate.NewLimiter(rate.Limit(10), 20) // 10 req/s, burst 20
        h.limiters[ip] = limiter
    }
    h.mu.Unlock()
    
    if !limiter.Allow() {
        return fmt.Errorf("rate limit exceeded for IP %s", ip)
    }
    return nil
}
```

**Best Practices**:
- Implement per-IP rate limiting
- Use token bucket algorithm
- Set appropriate limits (10-100 req/s)
- Implement exponential backoff for repeated violations

### Resource Limits

Limit resource consumption:

```go
cfg := config.ServerConfig{
    Addr:     ":7000",
    MaxConns: 1000, // Limit concurrent connections
    Timeout:  30 * time.Second,
}

// Per-client tunnel limits
type QuotaHook struct {
    reitunnel.NoopHook
    tunnelCount map[string]int
    maxTunnels  int
    mu          sync.RWMutex
}

func (h *QuotaHook) OnTunnelOpen(ctx context.Context, tunnelID string, meta map[string]string) error {
    clientID := meta["client_id"]
    
    h.mu.Lock()
    defer h.mu.Unlock()
    
    if h.tunnelCount[clientID] >= h.maxTunnels {
        return fmt.Errorf("tunnel quota exceeded for client %s", clientID)
    }
    
    h.tunnelCount[clientID]++
    return nil
}
```

**Best Practices**:
- Set MaxConns based on available resources
- Implement per-client quotas
- Monitor resource usage
- Implement graceful degradation

### Bandwidth Limiting

Control bandwidth usage:

```go
type BandwidthLimitHook struct {
    reitunnel.NoopHook
    limiters map[string]*rate.Limiter
    mu       sync.RWMutex
}

func (h *BandwidthLimitHook) OnDataSent(ctx context.Context, tunnelID string, bytes int64) error {
    h.mu.RLock()
    limiter := h.limiters[tunnelID]
    h.mu.RUnlock()
    
    if limiter != nil {
        // Reserve tokens for bytes sent
        if err := limiter.WaitN(ctx, int(bytes)); err != nil {
            return fmt.Errorf("bandwidth limit exceeded: %w", err)
        }
    }
    return nil
}
```

**Best Practices**:
- Implement per-tunnel bandwidth limits
- Use token bucket for smooth rate limiting
- Set limits based on subscription tier
- Monitor and alert on excessive usage

## Logging and Auditing

### Security Event Logging

Log all security-relevant events:

```go
type SecurityAuditHook struct {
    reitunnel.NoopHook
    logger *log.Logger
}

func (h *SecurityAuditHook) OnClientConnect(ctx context.Context, clientID string) error {
    h.logger.Printf("[SECURITY] Client connected: %s at %s", clientID, time.Now())
    return nil
}

func (h *SecurityAuditHook) OnError(ctx context.Context, err error, meta map[string]string) error {
    if errors.Is(err, reitunnel.ErrAuthFailed) {
        h.logger.Printf("[SECURITY] Authentication failed: %v, meta: %v", err, meta)
    }
    return nil
}
```

**Events to Log**:
- Authentication attempts (success and failure)
- Authorization decisions
- Tunnel creation and closure
- Configuration changes
- Errors and exceptions
- Rate limit violations

**Best Practices**:
- Use structured logging (JSON format)
- Include timestamps and client identifiers
- Log to secure, tamper-proof storage
- Implement log rotation and retention
- Monitor logs for suspicious patterns
- Comply with data protection regulations

### Audit Trail

Maintain comprehensive audit trail:

```go
type AuditTrail struct {
    Timestamp time.Time
    Event     string
    ClientID  string
    TunnelID  string
    Action    string
    Result    string
    Metadata  map[string]string
}

func (h *AuditHook) recordAudit(trail AuditTrail) {
    // Store in database or secure log
    h.db.Insert(trail)
}
```

**Best Practices**:
- Store audit logs separately from application logs
- Include sufficient context for investigation
- Implement tamper detection
- Retain logs according to compliance requirements
- Regularly review audit logs

## Secure Deployment

### Environment Configuration

Use environment variables for secrets:

```go
// ❌ BAD: Hardcoded secrets
tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{loadCert("cert.pem", "key.pem")},
}

// ✅ GOOD: Environment variables
certFile := os.Getenv("TLS_CERT_FILE")
keyFile := os.Getenv("TLS_KEY_FILE")
if certFile == "" || keyFile == "" {
    log.Fatal("TLS_CERT_FILE and TLS_KEY_FILE must be set")
}
tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{loadCert(certFile, keyFile)},
}
```

**Best Practices**:
- Never commit secrets to version control
- Use secret management systems (Vault, AWS Secrets Manager)
- Rotate secrets regularly
- Use different secrets for different environments
- Implement secret scanning in CI/CD

### Container Security

When deploying in containers:

```dockerfile
# Use minimal base image
FROM golang:1.21-alpine AS builder

# Run as non-root user
RUN adduser -D -u 1000 reitunnel
USER reitunnel

# Copy only necessary files
COPY --chown=reitunnel:reitunnel . /app
WORKDIR /app

# Build
RUN go build -o reitunnel

# Runtime image
FROM alpine:latest
RUN adduser -D -u 1000 reitunnel
USER reitunnel

COPY --from=builder /app/reitunnel /usr/local/bin/

# Drop capabilities
RUN setcap 'cap_net_bind_service=+ep' /usr/local/bin/reitunnel

ENTRYPOINT ["/usr/local/bin/reitunnel"]
```

**Best Practices**:
- Run as non-root user
- Use minimal base images
- Scan images for vulnerabilities
- Drop unnecessary capabilities
- Use read-only root filesystem
- Implement resource limits

### Monitoring and Alerting

Monitor security metrics:

```go
// Alert on suspicious patterns
func (h *SecurityMonitorHook) OnError(ctx context.Context, err error, meta map[string]string) error {
    if errors.Is(err, reitunnel.ErrAuthFailed) {
        h.authFailureCount.Add(1)
        
        // Alert if too many failures
        if h.authFailureCount.Load() > 100 {
            h.alerter.Send("High authentication failure rate", err, meta)
        }
    }
    return nil
}
```

**Metrics to Monitor**:
- Authentication failure rate
- Connection rate
- Bandwidth usage
- Error rates
- Resource utilization
- Certificate expiration

## Security Checklist

### Pre-Deployment

- [ ] Enable TLS with strong cipher suites
- [ ] Implement client authentication (certificates or tokens)
- [ ] Configure tunnel authorization
- [ ] Set up rate limiting
- [ ] Implement input validation
- [ ] Configure resource limits (MaxConns, timeouts)
- [ ] Set up security logging and auditing
- [ ] Review and harden firewall rules
- [ ] Scan for vulnerabilities
- [ ] Conduct security testing

### Production

- [ ] Monitor authentication failures
- [ ] Monitor resource usage
- [ ] Review audit logs regularly
- [ ] Rotate certificates and secrets
- [ ] Update dependencies regularly
- [ ] Implement intrusion detection
- [ ] Set up alerting for security events
- [ ] Conduct regular security audits
- [ ] Maintain incident response plan
- [ ] Keep documentation updated

### Ongoing

- [ ] Review and update security policies
- [ ] Train team on security best practices
- [ ] Conduct penetration testing
- [ ] Review and update access controls
- [ ] Monitor security advisories
- [ ] Update threat model
- [ ] Review and improve logging
- [ ] Conduct security drills

## Incident Response

### Detection

Monitor for security incidents:
- Unusual authentication patterns
- Excessive connection attempts
- Abnormal bandwidth usage
- Unexpected error rates
- Certificate validation failures

### Response

When an incident is detected:

1. **Contain**: Block malicious IPs, revoke compromised credentials
2. **Investigate**: Review logs, identify scope and impact
3. **Remediate**: Fix vulnerabilities, update configurations
4. **Recover**: Restore normal operations
5. **Learn**: Document incident, update procedures

### Example: Blocking Malicious Client

```go
type BlocklistHook struct {
    reitunnel.NoopHook
    blocked map[string]time.Time
    mu      sync.RWMutex
}

func (h *BlocklistHook) Block(clientID string, duration time.Duration) {
    h.mu.Lock()
    defer h.mu.Unlock()
    h.blocked[clientID] = time.Now().Add(duration)
}

func (h *BlocklistHook) OnClientConnect(ctx context.Context, clientID string) error {
    h.mu.RLock()
    blockedUntil, blocked := h.blocked[clientID]
    h.mu.RUnlock()
    
    if blocked && time.Now().Before(blockedUntil) {
        return fmt.Errorf("%w: client blocked", reitunnel.ErrAuthFailed)
    }
    return nil
}
```

## Conclusion

Security is an ongoing process, not a one-time configuration. Regularly review and update your security measures, monitor for threats, and stay informed about new vulnerabilities and best practices.

For more information, see:
- [Hook Development Guide](HOOKS.md)
- [Performance Best Practices](PERFORMANCE.md)
- [Examples](../examples/)
