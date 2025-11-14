# Hook Development Guide

This guide provides comprehensive information on developing custom hooks for Reitunnel. Hooks are the primary extension mechanism that allow you to respond to lifecycle events, implement authentication, collect metrics, and add custom functionality.

## Table of Contents

- [Hook Interface](#hook-interface)
- [Hook Lifecycle](#hook-lifecycle)
- [Creating Custom Hooks](#creating-custom-hooks)
- [Hook Execution Strategies](#hook-execution-strategies)
- [Best Practices](#best-practices)
- [Common Patterns](#common-patterns)
- [Performance Optimization](#performance-optimization)
- [Testing Hooks](#testing-hooks)

## Hook Interface

The `Hook` interface defines methods for all lifecycle and data transfer events in Reitunnel:

```go
type Hook interface {
    // Server lifecycle events
    OnServerStart(ctx context.Context) error
    OnServerStop(ctx context.Context) error
    
    // Client connection events
    OnClientConnect(ctx context.Context, clientID string) error
    OnClientDisconnect(ctx context.Context, clientID string, reason error) error
    
    // Tunnel session events
    OnTunnelOpen(ctx context.Context, tunnelID string, meta map[string]string) error
    OnTunnelClose(ctx context.Context, tunnelID string) error
    
    // Data transfer events (high frequency)
    OnDataSent(ctx context.Context, tunnelID string, bytes int64) error
    OnDataReceived(ctx context.Context, tunnelID string, bytes int64) error
    
    // Error events
    OnError(ctx context.Context, err error, meta map[string]string) error
}
```

### Event Descriptions

#### OnServerStart
- **When**: Invoked when the server starts, before accepting connections
- **Purpose**: Initialize resources, validate configuration, set up external connections
- **Error Handling**: If this returns an error, the server will fail to start
- **Example Use Cases**: Database connection setup, external service registration

#### OnServerStop
- **When**: Invoked when the server stops, after all connections are closed
- **Purpose**: Clean up resources, flush buffers, close external connections
- **Error Handling**: Errors are logged but don't prevent shutdown
- **Example Use Cases**: Flush metrics, close database connections, cleanup temporary files

#### OnClientConnect
- **When**: Invoked when a client connects to the server
- **Purpose**: Authenticate clients, initialize per-client resources, log connections
- **Error Handling**: If this returns an error, the client connection is rejected
- **Example Use Cases**: Token validation, IP whitelist checking, rate limiting

#### OnClientDisconnect
- **When**: Invoked when a client disconnects from the server
- **Purpose**: Clean up per-client resources, log disconnections, update metrics
- **Error Handling**: Errors are logged but don't affect disconnection
- **Example Use Cases**: Session cleanup, connection duration logging

#### OnTunnelOpen
- **When**: Invoked when a tunnel session is opened
- **Purpose**: Authorize tunnel creation, validate addresses, initialize tunnel resources
- **Error Handling**: If this returns an error, the tunnel creation is rejected
- **Example Use Cases**: Port range validation, tunnel quota checking, access control

#### OnTunnelClose
- **When**: Invoked when a tunnel session is closed
- **Purpose**: Clean up tunnel resources, log tunnel statistics, update metrics
- **Error Handling**: Errors are logged but don't affect tunnel closure
- **Example Use Cases**: Bandwidth logging, tunnel duration tracking

#### OnDataSent / OnDataReceived
- **When**: Invoked when data is transferred through a tunnel (high frequency)
- **Purpose**: Track bandwidth, implement rate limiting, collect statistics
- **Error Handling**: Errors are logged but don't stop data transfer
- **Example Use Cases**: Bandwidth metering, traffic analysis, quota enforcement
- **Performance Note**: These are called very frequently - use sampling or aggregation

#### OnError
- **When**: Invoked when an error occurs anywhere in the system
- **Purpose**: Centralized error logging, alerting, error analysis
- **Error Handling**: Errors from this hook are logged but don't propagate
- **Example Use Cases**: Error aggregation, alerting systems, debugging

## Hook Lifecycle

Understanding the order and timing of hook invocations is crucial for proper implementation:

### Server Lifecycle

```
1. Server.Run() called
2. OnServerStart() - All hooks executed
3. [If OnServerStart fails, cleanup and exit]
4. Accept connections loop starts
5. For each client:
   - OnClientConnect()
   - [If OnClientConnect fails, reject connection]
   - Handle client messages
   - OnClientDisconnect()
6. Server.Shutdown() called
7. Close all connections
8. OnServerStop() - All hooks executed
```

### Tunnel Lifecycle

```
1. Client.CreateTunnel() called
2. OnTunnelOpen() - All hooks executed
3. [If OnTunnelOpen fails, reject tunnel]
4. Tunnel established
5. Data transfer begins:
   - OnDataSent() for each send operation
   - OnDataReceived() for each receive operation
6. Tunnel closes (explicit or error)
7. OnTunnelClose() - All hooks executed
```

### Error Flow

```
1. Error occurs in any component
2. Error wrapped with context (TunnelError, ClientError, etc.)
3. OnError() invoked with error and metadata
4. Error propagated to caller
```

## Creating Custom Hooks

### Using NoopHook

The easiest way to create a custom hook is to embed `NoopHook` and override only the methods you need:

```go
package myhooks

import (
    "context"
    "github.com/kawaiirei0/reitunnel"
)

type MyCustomHook struct {
    reitunnel.NoopHook
    // Your custom fields
    db *sql.DB
}

func NewMyCustomHook(db *sql.DB) *MyCustomHook {
    return &MyCustomHook{
        db: db,
    }
}

// Override only the methods you need
func (h *MyCustomHook) OnClientConnect(ctx context.Context, clientID string) error {
    // Your custom logic
    _, err := h.db.Exec("INSERT INTO connections (client_id, timestamp) VALUES (?, ?)",
        clientID, time.Now())
    return err
}

func (h *MyCustomHook) OnClientDisconnect(ctx context.Context, clientID string, reason error) error {
    // Your custom logic
    _, err := h.db.Exec("UPDATE connections SET disconnected_at = ? WHERE client_id = ?",
        time.Now(), clientID)
    return err
}
```

### Implementing Full Interface

For complete control, implement the entire `Hook` interface:

```go
type FullCustomHook struct {
    // Your fields
}

func (h *FullCustomHook) OnServerStart(ctx context.Context) error {
    // Implementation
    return nil
}

// ... implement all other methods
```

## Hook Execution Strategies

The `HookManager` supports two execution strategies that control how errors are handled:

### StopOnError (Default)

Stops executing hooks immediately when one returns an error:

```go
hm := reitunnel.NewHookManager()
hm.SetStrategy(reitunnel.StopOnError)

hm.Register(hook1) // Executes
hm.Register(hook2) // Executes, returns error
hm.Register(hook3) // NOT executed
```

**Use When:**
- Authentication/authorization is critical
- Any hook failure should prevent the operation
- You need fail-fast behavior

### CollectAndContinue

Executes all hooks and collects errors, returning a `MultiError`:

```go
hm := reitunnel.NewHookManager()
hm.SetStrategy(reitunnel.CollectAndContinue)

hm.Register(hook1) // Executes
hm.Register(hook2) // Executes, returns error (collected)
hm.Register(hook3) // Still executes

// Check for multiple errors
if err := hm.ExecuteClientConnect(ctx, clientID); err != nil {
    if multiErr, ok := err.(*reitunnel.MultiError); ok {
        for _, e := range multiErr.Errors {
            log.Printf("Hook error: %v", e)
        }
    }
}
```

**Use When:**
- You want all hooks to execute regardless of errors
- Collecting metrics or logs where failures shouldn't block operations
- You need to see all errors, not just the first one

## Best Practices

### 1. Keep Hooks Fast

Hooks are called synchronously in the hot path. Keep them fast:

```go
// ❌ BAD: Slow synchronous operation
func (h *SlowHook) OnClientConnect(ctx context.Context, clientID string) error {
    // This blocks the connection!
    return h.expensiveExternalAPICall(clientID)
}

// ✅ GOOD: Async processing
func (h *FastHook) OnClientConnect(ctx context.Context, clientID string) error {
    // Queue for async processing
    h.queue <- clientID
    return nil
}
```

### 2. Handle Context Cancellation

Always respect context cancellation:

```go
func (h *MyHook) OnServerStart(ctx context.Context) error {
    select {
    case <-ctx.Done():
        return ctx.Err()
    case <-h.initComplete:
        return nil
    }
}
```

### 3. Use Sampling for High-Frequency Events

Don't log every data transfer event:

```go
type SampledHook struct {
    reitunnel.NoopHook
    counter atomic.Int64
    rate    int64 // Log every Nth event
}

func (h *SampledHook) OnDataSent(ctx context.Context, tunnelID string, bytes int64) error {
    count := h.counter.Add(1)
    if count%h.rate == 0 {
        log.Printf("Data sent: %d bytes (sample %d)", bytes, count)
    }
    return nil
}
```

### 4. Use Atomic Operations for Counters

For thread-safe counters, use atomic operations:

```go
type MetricsHook struct {
    reitunnel.NoopHook
    totalBytes atomic.Int64
}

func (h *MetricsHook) OnDataSent(ctx context.Context, tunnelID string, bytes int64) error {
    h.totalBytes.Add(bytes)
    return nil
}
```

### 5. Return Meaningful Errors

Provide context in error messages:

```go
func (h *AuthHook) OnClientConnect(ctx context.Context, clientID string) error {
    if !h.isAuthorized(clientID) {
        return fmt.Errorf("%w: client %s not in whitelist", 
            reitunnel.ErrAuthFailed, clientID)
    }
    return nil
}
```

### 6. Clean Up Resources

Always clean up in OnServerStop and OnClientDisconnect:

```go
type ResourceHook struct {
    reitunnel.NoopHook
    clients map[string]*ClientResource
    mu      sync.RWMutex
}

func (h *ResourceHook) OnClientConnect(ctx context.Context, clientID string) error {
    h.mu.Lock()
    defer h.mu.Unlock()
    h.clients[clientID] = &ClientResource{}
    return nil
}

func (h *ResourceHook) OnClientDisconnect(ctx context.Context, clientID string, reason error) error {
    h.mu.Lock()
    defer h.mu.Unlock()
    if resource, ok := h.clients[clientID]; ok {
        resource.Close()
        delete(h.clients, clientID)
    }
    return nil
}
```

## Common Patterns

### Audit Logging

```go
type AuditHook struct {
    reitunnel.NoopHook
    logger *log.Logger
}

func (h *AuditHook) OnClientConnect(ctx context.Context, clientID string) error {
    h.logger.Printf("[AUDIT] Client connected: %s at %s", clientID, time.Now())
    return nil
}

func (h *AuditHook) OnTunnelOpen(ctx context.Context, tunnelID string, meta map[string]string) error {
    h.logger.Printf("[AUDIT] Tunnel opened: %s, local=%s, remote=%s", 
        tunnelID, meta["local_addr"], meta["remote_addr"])
    return nil
}
```

### Rate Limiting

```go
type RateLimitHook struct {
    reitunnel.NoopHook
    limiters map[string]*rate.Limiter
    mu       sync.RWMutex
}

func (h *RateLimitHook) OnClientConnect(ctx context.Context, clientID string) error {
    h.mu.Lock()
    defer h.mu.Unlock()
    
    limiter, ok := h.limiters[clientID]
    if !ok {
        limiter = rate.NewLimiter(rate.Limit(10), 100) // 10 req/s, burst 100
        h.limiters[clientID] = limiter
    }
    
    if !limiter.Allow() {
        return fmt.Errorf("rate limit exceeded for client %s", clientID)
    }
    return nil
}
```

### Bandwidth Tracking

```go
type BandwidthHook struct {
    reitunnel.NoopHook
    tunnelStats map[string]*TunnelStats
    mu          sync.RWMutex
}

type TunnelStats struct {
    BytesSent     atomic.Int64
    BytesReceived atomic.Int64
    StartTime     time.Time
}

func (h *BandwidthHook) OnTunnelOpen(ctx context.Context, tunnelID string, meta map[string]string) error {
    h.mu.Lock()
    defer h.mu.Unlock()
    h.tunnelStats[tunnelID] = &TunnelStats{StartTime: time.Now()}
    return nil
}

func (h *BandwidthHook) OnDataSent(ctx context.Context, tunnelID string, bytes int64) error {
    h.mu.RLock()
    stats, ok := h.tunnelStats[tunnelID]
    h.mu.RUnlock()
    
    if ok {
        stats.BytesSent.Add(bytes)
    }
    return nil
}

func (h *BandwidthHook) OnTunnelClose(ctx context.Context, tunnelID string) error {
    h.mu.Lock()
    defer h.mu.Unlock()
    
    if stats, ok := h.tunnelStats[tunnelID]; ok {
        duration := time.Since(stats.StartTime)
        log.Printf("Tunnel %s: sent=%d, received=%d, duration=%s",
            tunnelID, stats.BytesSent.Load(), stats.BytesReceived.Load(), duration)
        delete(h.tunnelStats, tunnelID)
    }
    return nil
}
```

### Alerting

```go
type AlertHook struct {
    reitunnel.NoopHook
    alerter Alerter
}

func (h *AlertHook) OnError(ctx context.Context, err error, meta map[string]string) error {
    // Alert on critical errors
    if errors.Is(err, reitunnel.ErrAuthFailed) {
        h.alerter.Send("Authentication failure", err, meta)
    }
    return nil
}
```

## Performance Optimization

### Aggregation Pattern

For high-frequency events, aggregate data before processing:

```go
type AggregatingHook struct {
    reitunnel.NoopHook
    buffer   map[string]*Stats
    mu       sync.Mutex
    ticker   *time.Ticker
    done     chan struct{}
}

type Stats struct {
    BytesSent     int64
    BytesReceived int64
    EventCount    int64
}

func NewAggregatingHook(flushInterval time.Duration) *AggregatingHook {
    h := &AggregatingHook{
        buffer: make(map[string]*Stats),
        ticker: time.NewTicker(flushInterval),
        done:   make(chan struct{}),
    }
    go h.flushLoop()
    return h
}

func (h *AggregatingHook) OnDataSent(ctx context.Context, tunnelID string, bytes int64) error {
    h.mu.Lock()
    defer h.mu.Unlock()
    
    stats, ok := h.buffer[tunnelID]
    if !ok {
        stats = &Stats{}
        h.buffer[tunnelID] = stats
    }
    stats.BytesSent += bytes
    stats.EventCount++
    return nil
}

func (h *AggregatingHook) flushLoop() {
    for {
        select {
        case <-h.ticker.C:
            h.flush()
        case <-h.done:
            return
        }
    }
}

func (h *AggregatingHook) flush() {
    h.mu.Lock()
    buffer := h.buffer
    h.buffer = make(map[string]*Stats)
    h.mu.Unlock()
    
    // Process aggregated data
    for tunnelID, stats := range buffer {
        log.Printf("Tunnel %s: %d bytes sent in %d events",
            tunnelID, stats.BytesSent, stats.EventCount)
    }
}
```

### Async Processing Pattern

Offload expensive operations to background goroutines:

```go
type AsyncHook struct {
    reitunnel.NoopHook
    queue chan Event
    wg    sync.WaitGroup
}

type Event struct {
    Type     string
    TunnelID string
    Data     interface{}
}

func NewAsyncHook(workers int) *AsyncHook {
    h := &AsyncHook{
        queue: make(chan Event, 1000),
    }
    
    // Start worker goroutines
    for i := 0; i < workers; i++ {
        h.wg.Add(1)
        go h.worker()
    }
    
    return h
}

func (h *AsyncHook) OnDataSent(ctx context.Context, tunnelID string, bytes int64) error {
    select {
    case h.queue <- Event{Type: "data_sent", TunnelID: tunnelID, Data: bytes}:
    default:
        // Queue full, drop event or log
    }
    return nil
}

func (h *AsyncHook) worker() {
    defer h.wg.Done()
    for event := range h.queue {
        // Process event asynchronously
        h.processEvent(event)
    }
}

func (h *AsyncHook) Close() {
    close(h.queue)
    h.wg.Wait()
}
```

## Testing Hooks

### Mock Hook for Testing

```go
type MockHook struct {
    reitunnel.NoopHook
    Calls []HookCall
    mu    sync.Mutex
}

type HookCall struct {
    Method string
    Args   []interface{}
}

func (m *MockHook) OnClientConnect(ctx context.Context, clientID string) error {
    m.recordCall("OnClientConnect", clientID)
    return nil
}

func (m *MockHook) recordCall(method string, args ...interface{}) {
    m.mu.Lock()
    defer m.mu.Unlock()
    m.Calls = append(m.Calls, HookCall{Method: method, Args: args})
}

func (m *MockHook) GetCalls(method string) []HookCall {
    m.mu.Lock()
    defer m.mu.Unlock()
    var calls []HookCall
    for _, call := range m.Calls {
        if call.Method == method {
            calls = append(calls, call)
        }
    }
    return calls
}
```

### Testing Hook Behavior

```go
func TestMyHook(t *testing.T) {
    hook := NewMyCustomHook()
    ctx := context.Background()
    
    // Test OnClientConnect
    err := hook.OnClientConnect(ctx, "client-123")
    if err != nil {
        t.Errorf("OnClientConnect failed: %v", err)
    }
    
    // Verify side effects
    // ...
}
```

### Integration Testing

```go
func TestHookIntegration(t *testing.T) {
    // Create mock hook
    mock := &MockHook{}
    
    // Create hook manager
    hm := reitunnel.NewHookManager()
    hm.Register(mock)
    
    // Create server with hook manager
    srv := server.NewServer(config.ServerConfig{
        Addr: ":0",
    }, server.WithHookManager(hm))
    
    // Start server in goroutine
    go srv.Run()
    defer srv.Shutdown(context.Background())
    
    // Verify OnServerStart was called
    calls := mock.GetCalls("OnServerStart")
    if len(calls) != 1 {
        t.Errorf("Expected 1 OnServerStart call, got %d", len(calls))
    }
}
```

## Conclusion

Hooks are a powerful mechanism for extending Reitunnel's functionality. By following these patterns and best practices, you can create efficient, maintainable hooks that integrate seamlessly with the Reitunnel system.

For more examples, see the [examples](../examples/) directory and the default hook implementations in the [hooks](../hooks/) package.
