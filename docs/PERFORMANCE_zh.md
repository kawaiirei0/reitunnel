# 性能最佳实践

本指南提供了在生产环境中优化 Reitunnel 性能的建议。遵循这些实践将帮助您实现低延迟、高吞吐量和高效的资源利用。

## 目录

- [钩子性能](#钩子性能)
- [网络优化](#网络优化)
- [内存管理](#内存管理)
- [并发调优](#并发调优)
- [监控和分析](#监控和分析)
- [配置调优](#配置调优)
- [基准测试](#基准测试)

## 钩子性能

钩子在热路径中同步执行，因此它们的性能直接影响整体系统性能。

### 高频事件优化

数据传输事件（`OnDataSent`、`OnDataReceived`）调用非常频繁。仔细优化这些：

#### 1. 使用采样

仅处理一部分事件：

```go
type SampledMetricsHook struct {
    reitunnel.NoopHook
    counter    atomic.Int64
    sampleRate int64 // 处理 N 个事件中的 1 个
}

func (h *SampledMetricsHook) OnDataSent(ctx context.Context, tunnelID string, bytes int64) error {
    count := h.counter.Add(1)
    if count%h.sampleRate == 0 {
        // 仅处理采样的事件
        h.processMetrics(tunnelID, bytes)
    }
    return nil
}
```

**建议**：对于高吞吐量场景（>1000 事件/秒），使用 100 或更高的采样率。

#### 2. 使用聚合

批量处理事件并定期处理：

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

// 每个间隔刷新聚合数据
func (h *AggregatingHook) flushPeriodically() {
    ticker := time.NewTicker(h.interval)
    for range ticker.C {
        h.flush()
    }
}
```

**建议**：1-10 秒的刷新间隔适用于大多数用例。

#### 3. 使用异步处理

将昂贵的操作卸载到后台工作线程：

```go
type AsyncHook struct {
    reitunnel.NoopHook
    queue chan Event
}

func (h *AsyncHook) OnDataSent(ctx context.Context, tunnelID string, bytes int64) error {
    // 非阻塞发送
    select {
    case h.queue <- Event{TunnelID: tunnelID, Bytes: bytes}:
    default:
        // 队列已满 - 丢弃或记录
    }
    return nil
}
```

**建议**：使用缓冲通道（1000-10000 容量）和多个工作线程。

### 钩子执行策略

根据需求选择正确的执行策略：

```go
// 对于身份验证/授权 - 快速失败
hm.SetStrategy(reitunnel.StopOnError)

// 对于日志/指标 - 出错时继续
hm.SetStrategy(reitunnel.CollectAndContinue)
```

**影响**：`StopOnError` 稍快，因为它在第一个错误时停止。

### 最小化钩子数量

每个注册的钩子都会增加开销。合并相关功能：

```go
// ❌ 不好：多个钩子用于相关功能
hm.Register(loggerHook)
hm.Register(metricsHook)
hm.Register(auditHook)

// ✅ 更好：组合钩子
type CombinedHook struct {
    logger  *log.Logger
    metrics *MetricsCollector
    auditor *Auditor
}
```

**建议**：保持钩子数量在 5 个以下以获得最佳性能。

## 网络优化

### 缓冲区大小

为您的工作负载配置适当的缓冲区大小：

```go
// 在隧道数据传输中
buf := make([]byte, 32*1024) // 32KB 默认

// 对于高吞吐量场景
buf := make([]byte, 64*1024) // 64KB

// 对于低延迟场景
buf := make([]byte, 8*1024)  // 8KB
```

**建议**：
- 高吞吐量：64KB - 128KB 缓冲区
- 低延迟：8KB - 16KB 缓冲区
- 平衡：32KB 缓冲区（默认）

### TCP 调优

对于 TCP 传输，调整套接字选项：

```go
// 在传输实现中
if tcpConn, ok := conn.(*net.TCPConn); ok {
    // 禁用 Nagle 算法以实现低延迟
    tcpConn.SetNoDelay(true)
    
    // 设置保活
    tcpConn.SetKeepAlive(true)
    tcpConn.SetKeepAlivePeriod(30 * time.Second)
    
    // 设置缓冲区大小
    tcpConn.SetReadBuffer(64 * 1024)
    tcpConn.SetWriteBuffer(64 * 1024)
}
```

**建议**：
- 对交互式应用程序启用 `NoDelay`
- 对批量数据传输禁用 `NoDelay`
- 设置保活以检测死连接

### 连接池

尽可能重用连接：

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

**建议**：根据负载，池大小为 10-100 个连接。

## 内存管理

### 对象池

对频繁分配的对象使用 `sync.Pool`：

```go
var bufferPool = sync.Pool{
    New: func() interface{} {
        return make([]byte, 32*1024)
    },
}

func handleData() {
    buf := bufferPool.Get().([]byte)
    defer bufferPool.Put(buf)
    
    // 使用缓冲区
}
```

**建议**：池化缓冲区、消息对象和其他频繁分配的类型。

### 避免内存泄漏

正确清理资源：

```go
// ✅ 好：在 defer 中清理
func (c *Client) CreateTunnel(localAddr, remoteAddr string) (*tunnel.Tunnel, error) {
    tun, err := c.tunnelMgr.Create(tunnelID, localAddr, remoteAddr, meta)
    if err != nil {
        return nil, err
    }
    
    // 确保出错时清理
    success := false
    defer func() {
        if !success {
            c.closeTunnel(tun)
        }
    }()
    
    // ... 设置代码 ...
    
    success = true
    return tun, nil
}
```

### 限制并发连接

防止内存耗尽：

```go
cfg := config.ServerConfig{
    Addr:     ":7000",
    MaxConns: 1000, // 限制并发连接
}
```

**建议**：根据可用内存设置 `MaxConns`（每个连接大约 1MB）。

## 并发调优

### Goroutine 管理

限制 goroutine 创建：

```go
// ❌ 不好：无限制的 goroutine 创建
for {
    conn, _ := listener.Accept()
    go handleClient(conn) // 可能创建数百万个 goroutine
}

// ✅ 好：使用工作池
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

**建议**：对于 I/O 密集型工作负载，工作池大小 = 2-4 倍 CPU 核心数。

### 锁竞争

最小化锁竞争：

```go
// ❌ 不好：所有内容使用单个锁
type Manager struct {
    mu      sync.Mutex
    tunnels map[string]*Tunnel
    metrics map[string]*Metrics
}

// ✅ 好：分离锁
type Manager struct {
    tunnelsMu sync.RWMutex
    tunnels   map[string]*Tunnel
    
    metricsMu sync.RWMutex
    metrics   map[string]*Metrics
}
```

**建议**：对读密集型工作负载使用 `RWMutex`，对独立数据使用分离锁。

### 原子操作

对简单计数器使用原子操作：

```go
// ✅ 好：对简单计数器使用原子操作
type Metrics struct {
    bytesSent atomic.Int64
}

func (m *Metrics) AddBytes(n int64) {
    m.bytesSent.Add(n)
}

// ❌ 不好：对简单计数器使用互斥锁
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

**影响**：对于简单操作，原子操作比互斥锁快 10-100 倍。

## 监控和分析

### 启用指标收集

使用内置的指标钩子：

```go
metricsHook := hooks.NewMetricsHook()
hm.Register(metricsHook)

// 定期导出指标
go func() {
    ticker := time.NewTicker(10 * time.Second)
    for range ticker.C {
        metrics := metricsHook.GetMetrics()
        log.Printf("指标: 连接数=%d, 隧道数=%d, 已发送字节数=%d",
            metrics.ActiveConnections, metrics.ActiveTunnels, metrics.BytesSent)
    }
}()
```

### CPU 分析

分析您的应用程序：

```go
import _ "net/http/pprof"

func main() {
    // 启动 pprof 服务器
    go func() {
        log.Println(http.ListenAndServe("localhost:6060", nil))
    }()
    
    // 您的应用程序代码
}
```

访问分析：
- CPU：`http://localhost:6060/debug/pprof/profile?seconds=30`
- 内存：`http://localhost:6060/debug/pprof/heap`
- Goroutines：`http://localhost:6060/debug/pprof/goroutine`

### 内存分析

```bash
# 捕获堆分析
curl http://localhost:6060/debug/pprof/heap > heap.prof

# 使用 pprof 分析
go tool pprof heap.prof
```

### 跟踪分析

```go
import "runtime/trace"

func main() {
    f, _ := os.Create("trace.out")
    defer f.Close()
    
    trace.Start(f)
    defer trace.Stop()
    
    // 您的应用程序代码
}
```

分析：
```bash
go tool trace trace.out
```

## 配置调优

### 超时配置

设置适当的超时：

```go
cfg := config.ServerConfig{
    Addr:    ":7000",
    Timeout: 30 * time.Second, // 连接超时
}
```

**建议**：
- 局域网：5-10 秒
- 广域网：30-60 秒
- 不可靠网络：60-120 秒

### 传输选择

选择正确的传输：

```go
// TCP：最佳性能，最低延迟
cfg := config.ServerConfig{
    Transport: "tcp",
}

// WebSocket：更好的防火墙穿透，略高的开销
cfg := config.ServerConfig{
    Transport: "websocket",
}
```

**性能影响**：TCP 比 WebSocket 快约 5-10%。

### TLS 配置

优化 TLS 设置：

```go
tlsConfig := &tls.Config{
    // 使用现代密码套件
    CipherSuites: []uint16{
        tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    },
    
    // 使用 TLS 1.3 以获得最佳性能
    MinVersion: tls.VersionTLS13,
    
    // 启用会话恢复
    ClientSessionCache: tls.NewLRUClientSessionCache(100),
}
```

**影响**：TLS 1.3 比 TLS 1.2 快约 30%。

## 基准测试

### 吞吐量基准测试

```go
func BenchmarkThroughput(b *testing.B) {
    // 设置服务器和客户端
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

### 延迟基准测试

```go
func BenchmarkLatency(b *testing.B) {
    // 设置
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
        // 等待响应
        tunnel.Conn.Read(data)
        latency := time.Since(start)
        b.ReportMetric(float64(latency.Microseconds()), "µs/op")
    }
}
```

### 钩子性能基准测试

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

## 性能目标

### 预期性能

在典型条件下，Reitunnel 应该实现：

| 指标 | 目标 | 注释 |
|------|------|------|
| 吞吐量 | 1-10 Gbps | 取决于硬件和网络 |
| 延迟 | <1ms | 相对于原始 TCP 的额外延迟 |
| 连接数 | 10,000+ | 每个服务器实例 |
| 隧道数 | 1,000+ | 每个客户端实例 |
| 钩子开销 | <100µs | 每次钩子调用 |

### 优化检查清单

- [ ] 对高频钩子使用采样（速率 ≥ 100）
- [ ] 对昂贵操作启用异步处理
- [ ] 设置适当的缓冲区大小（32KB-64KB）
- [ ] 根据可用内存配置 MaxConns
- [ ] 对读密集型数据结构使用 RWMutex
- [ ] 对简单计数器使用原子操作
- [ ] 启用 TCP NoDelay 以实现低延迟
- [ ] 使用带会话恢复的 TLS 1.3
- [ ] 池化频繁分配的对象
- [ ] 使用工作池限制 goroutine 创建
- [ ] 定期监控指标和分析
- [ ] 设置适当的超时
- [ ] 正确清理资源

## 性能问题故障排除

### 高 CPU 使用率

1. 分析 CPU 使用率：`go tool pprof http://localhost:6060/debug/pprof/profile`
2. 检查：
   - 钩子太多
   - 昂贵的钩子操作
   - 锁竞争
   - 过多的 goroutine

### 高内存使用率

1. 分析内存：`go tool pprof http://localhost:6060/debug/pprof/heap`
2. 检查：
   - 内存泄漏（未关闭的连接）
   - 大缓冲区大小
   - 太多并发连接
   - 无限制的缓存

### 高延迟

1. 首先检查网络延迟
2. 使用跟踪分析：`go tool trace trace.out`
3. 检查：
   - 热路径中的慢钩子
   - 锁竞争
   - 大缓冲区大小
   - 启用了 TCP Nagle 算法

### 低吞吐量

1. 检查网络带宽
2. 分析 CPU 并识别瓶颈
3. 检查：
   - 小缓冲区大小
   - 钩子太多
   - 同步 I/O 操作
   - 工作 goroutine 不足

## 结论

性能优化是一个迭代过程。从这些最佳实践开始，测量您的特定工作负载，并相应地进行调整。在优化之前始终进行分析，以识别实际瓶颈而不是假设的瓶颈。

有关更多信息，请参阅：
- [钩子开发指南](HOOKS_zh.md)
- [安全注意事项](SECURITY_zh.md)
- [示例](../examples/)
