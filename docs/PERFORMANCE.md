# Performance Best Practices

This guide provides recommendations for optimizing Reitunnel performance in production environments. Following these practices will help you achieve low latency, high throughput, and efficient resource utilization.

## Table of Contents

- [Hook Performance](#hook-performance)
- [Network Optimization](#network-optimization)
- [Memory Management](#memory-management)
- [Concurrency Tuning](#concurrency-tuning)
- [Monitoring and Profiling](#monitoring-and-profiling)
- [Configuration Tuning](#configuration-tuning)
- [Benchmarking](#benchmarking)

## Hook Performance

Hooks are executed synchronously in the hot path, so their performance directly impacts overall system performance.

### High-Frequency Event Optimization

Data transfer events (`OnDataSent`, `OnDataReceived`) are called very frequently. Optimize these carefully:

#### 1. Use Sampling

Only process a fraction of events:

```go
type SampledMetricsHook struct {
    reitunnel.NoopHook
    counter    atomic.Int64
    sampleRate int64 // Process 1 in N events
}

func (h *SampledMetricsHook) OnDataSent(ctx context.Context, tunnelID string, bytes int64) error {
    count := h.counter.Add(1)
    if count%h.sampleRate == 0 {
        // Process only sampled events
        h.processMetrics(tunnelID, bytes)
    }
    return nil
}
```

**Recommendation**: For high-throughput scenarios (>1000 events/sec), use a sample rate of 100 or higher.

#### 2. Use Aggregation

Batch events and process them periodically:

```go
type AggregatingHook struct {
    reitunnel.NoopHook
    buffer   map[string]*Stats
    mu       sync.Mutex
    interval time.Duration
}

func (h *AggregatingHook) OnDataSent(ctx context.Context, tunnelID string, bytes int64) error {
    h.mu.Lock()
    h.buffer[tunnelID].BytesSent += bytes
    h.mu.Unlock()
    return nil
}

// Flush aggregated data every interval
func (h *AggregatingHook) flushPeriodically() {
    ticker := time.NewTicker(h.interval)
    for range ticker.C {
        h.flush()
    }
}
```

**Recommendation**: Flush interval of 1-10 seconds works well for most use cases.

#### 3. Use Async Processing

Offload expensive operations to background workers:

```go
type AsyncHook struct {
    reitunnel.NoopHook
    queue chan Event
}

func (h *AsyncHook) OnDataSent(ctx context.Context, tunnelID string, bytes int64) error {
    // Non-blocking send
    select {
    case h.queue <- Event{TunnelID: tunnelID, Bytes: bytes}:
    default:
        // Queue full - drop or log
    }
    return nil
}
```

**Recommendation**: Use buffered channels (1000-10000 capacity) and multiple workers.

### Hook Execution Strategy

Choose the right execution strategy based on your needs:

```go
// For authentication/authorization - fail fast
hm.SetStrategy(reitunnel.StopOnError)

// For logging/metrics - continue on errors
hm.SetStrategy(reitunnel.CollectAndContinue)
```

**Impact**: `StopOnError` is slightly faster as it stops on first error.

### Minimize Hook Count

Each registered hook adds overhead. Combine related functionality:

```go
// ❌ BAD: Multiple hooks for related functionality
hm.Register(loggerHook)
hm.Register(metricsHook)
hm.Register(auditHook)

// ✅ BETTER: Combined hook
type CombinedHook struct {
    logger  *log.Logger
    metrics *MetricsCollector
    auditor *Auditor
}
```

**Recommendation**: Keep hook count under 5 for optimal performance.

## Network Optimization

### Buffer Sizes

Configure appropriate buffer sizes for your workload:

```go
// In tunnel data transfer
buf := make([]byte, 32*1024) // 32KB default

// For high-throughput scenarios
buf := make([]byte, 64*1024) // 64KB

// For low-latency scenarios
buf := make([]byte, 8*1024)  // 8KB
```

**Recommendations**:
- High throughput: 64KB - 128KB buffers
- Low latency: 8KB - 16KB buffers
- Balanced: 32KB buffers (default)

### TCP Tuning

For TCP transport, tune socket options:

```go
// In transport implementation
if tcpConn, ok := conn.(*net.TCPConn); ok {
    // Disable Nagle's algorithm for low latency
    tcpConn.SetNoDelay(true)
    
    // Set keep-alive
    tcpConn.SetKeepAlive(true)
    tcpConn.SetKeepAlivePeriod(30 * time.Second)
    
    // Set buffer sizes
    tcpConn.SetReadBuffer(64 * 1024)
    tcpConn.SetWriteBuffer(64 * 1024)
}
```

**Recommendations**:
- Enable `NoDelay` for interactive applications
- Disable `NoDelay` for bulk data transfer
- Set keep-alive to detect dead connections

### Connection Pooling

Reuse connections when possible:

```go
type ConnectionPool struct {
    conns chan net.Conn
    max   int
}

func (p *ConnectionPool) Get() (net.Conn, error) {
    select {
    case conn := <-p.conns:
        return conn, nil
    default:
        return net.Dial("tcp", addr)
    }
}

func (p *ConnectionPool) Put(conn net.Conn) {
    select {
    case p.conns <- conn:
    default:
        conn.Close()
    }
}
```

**Recommendation**: Pool size of 10-100 connections depending on load.

## Memory Management

### Object Pooling

Use `sync.Pool` for frequently allocated objects:

```go
var bufferPool = sync.Pool{
    New: func() interface{} {
        return make([]byte, 32*1024)
    },
}

func handleData() {
    buf := bufferPool.Get().([]byte)
    defer bufferPool.Put(buf)
    
    // Use buffer
}
```

**Recommendation**: Pool buffers, message objects, and other frequently allocated types.

### Avoid Memory Leaks

Properly clean up resources:

```go
// ✅ GOOD: Clean up in defer
func (c *Client) CreateTunnel(localAddr, remoteAddr string) (*tunnel.Tunnel, error) {
    tun, err := c.tunnelMgr.Create(tunnelID, localAddr, remoteAddr, meta)
    if err != nil {
        return nil, err
    }
    
    // Ensure cleanup on error
    success := false
    defer func() {
        if !success {
            c.closeTunnel(tun)
        }
    }()
    
    // ... setup code ...
    
    success = true
    return tun, nil
}
```

### Limit Concurrent Connections

Prevent memory exhaustion:

```go
cfg := config.ServerConfig{
    Addr:     ":7000",
    MaxConns: 1000, // Limit concurrent connections
}
```

**Recommendation**: Set `MaxConns` based on available memory (roughly 1MB per connection).

## Concurrency Tuning

### Goroutine Management

Limit goroutine creation:

```go
// ❌ BAD: Unbounded goroutine creation
for {
    conn, _ := listener.Accept()
    go handleClient(conn) // Can create millions of goroutines
}

// ✅ GOOD: Use worker pool
type WorkerPool struct {
    jobs chan net.Conn
}

func (p *WorkerPool) Start(workers int) {
    for i := 0; i < workers; i++ {
        go p.worker()
    }
}

func (p *WorkerPool) worker() {
    for conn := range p.jobs {
        handleClient(conn)
    }
}
```

**Recommendation**: Worker pool size = 2-4x CPU cores for I/O-bound workloads.

### Lock Contention

Minimize lock contention:

```go
// ❌ BAD: Single lock for everything
type Manager struct {
    mu      sync.Mutex
    tunnels map[string]*Tunnel
    metrics map[string]*Metrics
}

// ✅ GOOD: Separate locks
type Manager struct {
    tunnelsMu sync.RWMutex
    tunnels   map[string]*Tunnel
    
    metricsMu sync.RWMutex
    metrics   map[string]*Metrics
}
```

**Recommendation**: Use `RWMutex` for read-heavy workloads, separate locks for independent data.

### Atomic Operations

Use atomic operations for simple counters:

```go
// ✅ GOOD: Atomic for simple counters
type Metrics struct {
    bytesSent atomic.Int64
}

func (m *Metrics) AddBytes(n int64) {
    m.bytesSent.Add(n)
}

// ❌ BAD: Mutex for simple counter
type Metrics struct {
    mu        sync.Mutex
    bytesSent int64
}

func (m *Metrics) AddBytes(n int64) {
    m.mu.Lock()
    m.bytesSent += n
    m.mu.Unlock()
}
```

**Impact**: Atomic operations are 10-100x faster than mutex for simple operations.

## Monitoring and Profiling

### Enable Metrics Collection

Use the built-in metrics hook:

```go
metricsHook := hooks.NewMetricsHook()
hm.Register(metricsHook)

// Periodically export metrics
go func() {
    ticker := time.NewTicker(10 * time.Second)
    for range ticker.C {
        metrics := metricsHook.GetMetrics()
        log.Printf("Metrics: connections=%d, tunnels=%d, bytes_sent=%d",
            metrics.ActiveConnections, metrics.ActiveTunnels, metrics.BytesSent)
    }
}()
```

### CPU Profiling

Profile your application:

```go
import _ "net/http/pprof"

func main() {
    // Start pprof server
    go func() {
        log.Println(http.ListenAndServe("localhost:6060", nil))
    }()
    
    // Your application code
}
```

Access profiles at:
- CPU: `http://localhost:6060/debug/pprof/profile?seconds=30`
- Memory: `http://localhost:6060/debug/pprof/heap`
- Goroutines: `http://localhost:6060/debug/pprof/goroutine`

### Memory Profiling

```bash
# Capture heap profile
curl http://localhost:6060/debug/pprof/heap > heap.prof

# Analyze with pprof
go tool pprof heap.prof
```

### Trace Analysis

```go
import "runtime/trace"

func main() {
    f, _ := os.Create("trace.out")
    defer f.Close()
    
    trace.Start(f)
    defer trace.Stop()
    
    // Your application code
}
```

Analyze with:
```bash
go tool trace trace.out
```

## Configuration Tuning

### Timeout Configuration

Set appropriate timeouts:

```go
cfg := config.ServerConfig{
    Addr:    ":7000",
    Timeout: 30 * time.Second, // Connection timeout
}
```

**Recommendations**:
- LAN: 5-10 seconds
- WAN: 30-60 seconds
- Unreliable networks: 60-120 seconds

### Transport Selection

Choose the right transport:

```go
// TCP: Best performance, lowest latency
cfg := config.ServerConfig{
    Transport: "tcp",
}

// WebSocket: Better firewall traversal, slightly higher overhead
cfg := config.ServerConfig{
    Transport: "websocket",
}
```

**Performance Impact**: TCP is ~5-10% faster than WebSocket.

### TLS Configuration

Optimize TLS settings:

```go
tlsConfig := &tls.Config{
    // Use modern cipher suites
    CipherSuites: []uint16{
        tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    },
    
    // Use TLS 1.3 for best performance
    MinVersion: tls.VersionTLS13,
    
    // Enable session resumption
    ClientSessionCache: tls.NewLRUClientSessionCache(100),
}
```

**Impact**: TLS 1.3 is ~30% faster than TLS 1.2.

## Benchmarking

### Throughput Benchmark

```go
func BenchmarkThroughput(b *testing.B) {
    // Setup server and client
    srv := setupServer()
    defer srv.Shutdown(context.Background())
    
    client := setupClient()
    defer client.Close()
    
    tunnel, _ := client.CreateTunnel("localhost:8080", "0.0.0.0:80")
    
    data := make([]byte, 1024)
    
    b.ResetTimer()
    b.SetBytes(int64(len(data)))
    
    for i := 0; i < b.N; i++ {
        tunnel.Conn.Write(data)
    }
}
```

### Latency Benchmark

```go
func BenchmarkLatency(b *testing.B) {
    // Setup
    srv := setupServer()
    defer srv.Shutdown(context.Background())
    
    client := setupClient()
    defer client.Close()
    
    tunnel, _ := client.CreateTunnel("localhost:8080", "0.0.0.0:80")
    
    data := make([]byte, 64)
    
    b.ResetTimer()
    
    for i := 0; i < b.N; i++ {
        start := time.Now()
        tunnel.Conn.Write(data)
        // Wait for response
        tunnel.Conn.Read(data)
        latency := time.Since(start)
        b.ReportMetric(float64(latency.Microseconds()), "µs/op")
    }
}
```

### Hook Performance Benchmark

```go
func BenchmarkHookExecution(b *testing.B) {
    hm := reitunnel.NewHookManager()
    hm.Register(hooks.NewStdLoggerHook(log.New(io.Discard, "", 0), 0))
    hm.Register(hooks.NewMetricsHook())
    
    ctx := context.Background()
    
    b.ResetTimer()
    
    for i := 0; i < b.N; i++ {
        hm.ExecuteDataSent(ctx, "tunnel-1", 1024)
    }
}
```

## Performance Targets

### Expected Performance

Under typical conditions, Reitunnel should achieve:

| Metric | Target | Notes |
|--------|--------|-------|
| Throughput | 1-10 Gbps | Depends on hardware and network |
| Latency | <1ms | Additional latency over raw TCP |
| Connections | 10,000+ | Per server instance |
| Tunnels | 1,000+ | Per client instance |
| Hook overhead | <100µs | Per hook invocation |

### Optimization Checklist

- [ ] Use sampling for high-frequency hooks (rate ≥ 100)
- [ ] Enable async processing for expensive operations
- [ ] Set appropriate buffer sizes (32KB-64KB)
- [ ] Configure MaxConns based on available memory
- [ ] Use RWMutex for read-heavy data structures
- [ ] Use atomic operations for simple counters
- [ ] Enable TCP NoDelay for low latency
- [ ] Use TLS 1.3 with session resumption
- [ ] Pool frequently allocated objects
- [ ] Limit goroutine creation with worker pools
- [ ] Monitor metrics and profile regularly
- [ ] Set appropriate timeouts
- [ ] Clean up resources properly

## Troubleshooting Performance Issues

### High CPU Usage

1. Profile CPU usage: `go tool pprof http://localhost:6060/debug/pprof/profile`
2. Check for:
   - Too many hooks
   - Expensive hook operations
   - Lock contention
   - Excessive goroutines

### High Memory Usage

1. Profile memory: `go tool pprof http://localhost:6060/debug/pprof/heap`
2. Check for:
   - Memory leaks (unclosed connections)
   - Large buffer sizes
   - Too many concurrent connections
   - Unbounded caches

### High Latency

1. Check network latency first
2. Profile with trace: `go tool trace trace.out`
3. Check for:
   - Slow hooks in hot path
   - Lock contention
   - Large buffer sizes
   - TCP Nagle's algorithm enabled

### Low Throughput

1. Check network bandwidth
2. Profile CPU and identify bottlenecks
3. Check for:
   - Small buffer sizes
   - Too many hooks
   - Synchronous I/O operations
   - Insufficient worker goroutines

## Conclusion

Performance optimization is an iterative process. Start with these best practices, measure your specific workload, and tune accordingly. Always profile before optimizing to identify actual bottlenecks rather than assumed ones.

For more information, see:
- [Hook Development Guide](HOOKS.md)
- [Security Considerations](SECURITY.md)
- [Examples](../examples/)
