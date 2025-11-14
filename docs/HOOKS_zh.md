# 钩子开发指南

本指南提供了为 Reitunnel 开发自定义钩子的全面信息。钩子是主要的扩展机制，允许您响应生命周期事件、实现身份验证、收集指标并添加自定义功能。

## 目录

- [钩子接口](#钩子接口)
- [钩子生命周期](#钩子生命周期)
- [创建自定义钩子](#创建自定义钩子)
- [钩子执行策略](#钩子执行策略)
- [最佳实践](#最佳实践)
- [常见模式](#常见模式)
- [性能优化](#性能优化)
- [测试钩子](#测试钩子)

## 钩子接口

`Hook` 接口定义了 Reitunnel 中所有生命周期和数据传输事件的方法：

```go
type Hook interface {
    // 服务器生命周期事件
    OnServerStart(ctx context.Context) error
    OnServerStop(ctx context.Context) error
    
    // 客户端连接事件
    OnClientConnect(ctx context.Context, clientID string) error
    OnClientDisconnect(ctx context.Context, clientID string, reason error) error
    
    // 隧道会话事件
    OnTunnelOpen(ctx context.Context, tunnelID string, meta map[string]string) error
    OnTunnelClose(ctx context.Context, tunnelID string) error
    
    // 数据传输事件（高频）
    OnDataSent(ctx context.Context, tunnelID string, bytes int64) error
    OnDataReceived(ctx context.Context, tunnelID string, bytes int64) error
    
    // 错误事件
    OnError(ctx context.Context, err error, meta map[string]string) error
}
```

### 事件说明

#### OnServerStart
- **触发时机**：服务器启动时，在接受连接之前调用
- **用途**：初始化资源、验证配置、建立外部连接
- **错误处理**：如果返回错误，服务器将无法启动
- **示例用例**：数据库连接设置、外部服务注册

#### OnServerStop
- **触发时机**：服务器停止时，在所有连接关闭后调用
- **用途**：清理资源、刷新缓冲区、关闭外部连接
- **错误处理**：错误会被记录但不会阻止关闭
- **示例用例**：刷新指标、关闭数据库连接、清理临时文件

#### OnClientConnect
- **触发时机**：客户端连接到服务器时调用
- **用途**：验证客户端、初始化每个客户端的资源、记录连接
- **错误处理**：如果返回错误，客户端连接将被拒绝
- **示例用例**：令牌验证、IP 白名单检查、速率限制

#### OnClientDisconnect
- **触发时机**：客户端从服务器断开连接时调用
- **用途**：清理每个客户端的资源、记录断开连接、更新指标
- **错误处理**：错误会被记录但不影响断开连接
- **示例用例**：会话清理、连接持续时间记录

#### OnTunnelOpen
- **触发时机**：打开隧道会话时调用
- **用途**：授权隧道创建、验证地址、初始化隧道资源
- **错误处理**：如果返回错误，隧道创建将被拒绝
- **示例用例**：端口范围验证、隧道配额检查、访问控制

#### OnTunnelClose
- **触发时机**：关闭隧道会话时调用
- **用途**：清理隧道资源、记录隧道统计信息、更新指标
- **错误处理**：错误会被记录但不影响隧道关闭
- **示例用例**：带宽记录、隧道持续时间跟踪

#### OnDataSent / OnDataReceived
- **触发时机**：通过隧道传输数据时调用（高频）
- **用途**：跟踪带宽、实现速率限制、收集统计信息
- **错误处理**：错误会被记录但不会停止数据传输
- **示例用例**：带宽计量、流量分析、配额执行
- **性能注意**：这些方法调用非常频繁 - 使用采样或聚合

#### OnError
- **触发时机**：系统中任何地方发生错误时调用
- **用途**：集中式错误记录、告警、错误分析
- **错误处理**：此钩子的错误会被记录但不会传播
- **示例用例**：错误聚合、告警系统、调试

## 钩子生命周期

了解钩子调用的顺序和时机对于正确实现至关重要：

### 服务器生命周期

```
1. 调用 Server.Run()
2. OnServerStart() - 执行所有钩子
3. [如果 OnServerStart 失败，清理并退出]
4. 开始接受连接循环
5. 对于每个客户端：
   - OnClientConnect()
   - [如果 OnClientConnect 失败，拒绝连接]
   - 处理客户端消息
   - OnClientDisconnect()
6. 调用 Server.Shutdown()
7. 关闭所有连接
8. OnServerStop() - 执行所有钩子
```

### 隧道生命周期

```
1. 调用 Client.CreateTunnel()
2. OnTunnelOpen() - 执行所有钩子
3. [如果 OnTunnelOpen 失败，拒绝隧道]
4. 建立隧道
5. 开始数据传输：
   - 每次发送操作调用 OnDataSent()
   - 每次接收操作调用 OnDataReceived()
6. 隧道关闭（显式或错误）
7. OnTunnelClose() - 执行所有钩子
```

### 错误流程

```
1. 任何组件发生错误
2. 用上下文包装错误（TunnelError、ClientError 等）
3. 调用 OnError() 并传入错误和元数据
4. 错误传播给调用者
```

## 创建自定义钩子

### 使用 NoopHook

创建自定义钩子最简单的方法是嵌入 `NoopHook` 并仅覆盖您需要的方法：

```go
package myhooks

import (
    "context"
    "github.com/kawaiirei0/reitunnel"
)

type MyCustomHook struct {
    reitunnel.NoopHook
    // 您的自定义字段
    db *sql.DB
}

func NewMyCustomHook(db *sql.DB) *MyCustomHook {
    return &MyCustomHook{
        db: db,
    }
}

// 仅覆盖您需要的方法
func (h *MyCustomHook) OnClientConnect(ctx context.Context, clientID string) error {
    // 您的自定义逻辑
    _, err := h.db.Exec("INSERT INTO connections (client_id, timestamp) VALUES (?, ?)",
        clientID, time.Now())
    return err
}

func (h *MyCustomHook) OnClientDisconnect(ctx context.Context, clientID string, reason error) error {
    // 您的自定义逻辑
    _, err := h.db.Exec("UPDATE connections SET disconnected_at = ? WHERE client_id = ?",
        time.Now(), clientID)
    return err
}
```

### 实现完整接口

为了完全控制，实现整个 `Hook` 接口：

```go
type FullCustomHook struct {
    // 您的字段
}

func (h *FullCustomHook) OnServerStart(ctx context.Context) error {
    // 实现
    return nil
}

// ... 实现所有其他方法
```

## 钩子执行策略

`HookManager` 支持两种执行策略来控制错误处理方式：

### StopOnError（默认）

当一个钩子返回错误时立即停止执行：

```go
hm := reitunnel.NewHookManager()
hm.SetStrategy(reitunnel.StopOnError)

hm.Register(hook1) // 执行
hm.Register(hook2) // 执行，返回错误
hm.Register(hook3) // 不执行
```

**适用场景：**
- 身份验证/授权至关重要
- 任何钩子失败都应阻止操作
- 需要快速失败行为

### CollectAndContinue

执行所有钩子并收集错误，返回 `MultiError`：

```go
hm := reitunnel.NewHookManager()
hm.SetStrategy(reitunnel.CollectAndContinue)

hm.Register(hook1) // 执行
hm.Register(hook2) // 执行，返回错误（已收集）
hm.Register(hook3) // 仍然执行

// 检查多个错误
if err := hm.ExecuteClientConnect(ctx, clientID); err != nil {
    if multiErr, ok := err.(*reitunnel.MultiError); ok {
        for _, e := range multiErr.Errors {
            log.Printf("钩子错误: %v", e)
        }
    }
}
```

**适用场景：**
- 希望所有钩子都执行，无论是否有错误
- 收集指标或日志，失败不应阻止操作
- 需要查看所有错误，而不仅仅是第一个

## 最佳实践

### 1. 保持钩子快速

钩子在热路径中同步调用。保持它们快速：

```go
// ❌ 不好：慢速同步操作
func (h *SlowHook) OnClientConnect(ctx context.Context, clientID string) error {
    // 这会阻塞连接！
    return h.expensiveExternalAPICall(clientID)
}

// ✅ 好：异步处理
func (h *FastHook) OnClientConnect(ctx context.Context, clientID string) error {
    // 排队进行异步处理
    h.queue <- clientID
    return nil
}
```

### 2. 处理 Context 取消

始终尊重 context 取消：

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

### 3. 对高频事件使用采样

不要记录每个数据传输事件：

```go
type SampledHook struct {
    reitunnel.NoopHook
    counter atomic.Int64
    rate    int64 // 每 N 个事件记录一次
}

func (h *SampledHook) OnDataSent(ctx context.Context, tunnelID string, bytes int64) error {
    count := h.counter.Add(1)
    if count%h.rate == 0 {
        log.Printf("数据已发送: %d 字节（样本 %d）", bytes, count)
    }
    return nil
}
```

### 4. 对计数器使用原子操作

对于线程安全的计数器，使用原子操作：

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

### 5. 返回有意义的错误

在错误消息中提供上下文：

```go
func (h *AuthHook) OnClientConnect(ctx context.Context, clientID string) error {
    if !h.isAuthorized(clientID) {
        return fmt.Errorf("%w: 客户端 %s 不在白名单中", 
            reitunnel.ErrAuthFailed, clientID)
    }
    return nil
}
```

### 6. 清理资源

始终在 OnServerStop 和 OnClientDisconnect 中清理：

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

## 常见模式

### 审计日志

```go
type AuditHook struct {
    reitunnel.NoopHook
    logger *log.Logger
}

func (h *AuditHook) OnClientConnect(ctx context.Context, clientID string) error {
    h.logger.Printf("[审计] 客户端已连接: %s 于 %s", clientID, time.Now())
    return nil
}

func (h *AuditHook) OnTunnelOpen(ctx context.Context, tunnelID string, meta map[string]string) error {
    h.logger.Printf("[审计] 隧道已打开: %s, 本地=%s, 远程=%s", 
        tunnelID, meta["local_addr"], meta["remote_addr"])
    return nil
}
```

### 速率限制

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
        limiter = rate.NewLimiter(rate.Limit(10), 100) // 10 请求/秒，突发 100
        h.limiters[clientID] = limiter
    }
    
    if !limiter.Allow() {
        return fmt.Errorf("客户端 %s 超过速率限制", clientID)
    }
    return nil
}
```

### 带宽跟踪

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
        log.Printf("隧道 %s: 已发送=%d, 已接收=%d, 持续时间=%s",
            tunnelID, stats.BytesSent.Load(), stats.BytesReceived.Load(), duration)
        delete(h.tunnelStats, tunnelID)
    }
    return nil
}
```

### 告警

```go
type AlertHook struct {
    reitunnel.NoopHook
    alerter Alerter
}

func (h *AlertHook) OnError(ctx context.Context, err error, meta map[string]string) error {
    // 对关键错误发出告警
    if errors.Is(err, reitunnel.ErrAuthFailed) {
        h.alerter.Send("身份验证失败", err, meta)
    }
    return nil
}
```

## 性能优化

### 聚合模式

对于高频事件，在处理之前聚合数据：

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
    
    // 处理聚合数据
    for tunnelID, stats := range buffer {
        log.Printf("隧道 %s: %d 个事件中发送了 %d 字节",
            tunnelID, stats.BytesSent, stats.EventCount)
    }
}
```

### 异步处理模式

将昂贵的操作卸载到后台 goroutine：

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
    
    // 启动工作 goroutine
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
        // 队列已满，丢弃事件或记录
    }
    return nil
}

func (h *AsyncHook) worker() {
    defer h.wg.Done()
    for event := range h.queue {
        // 异步处理事件
        h.processEvent(event)
    }
}

func (h *AsyncHook) Close() {
    close(h.queue)
    h.wg.Wait()
}
```

## 测试钩子

### 用于测试的模拟钩子

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

### 测试钩子行为

```go
func TestMyHook(t *testing.T) {
    hook := NewMyCustomHook()
    ctx := context.Background()
    
    // 测试 OnClientConnect
    err := hook.OnClientConnect(ctx, "client-123")
    if err != nil {
        t.Errorf("OnClientConnect 失败: %v", err)
    }
    
    // 验证副作用
    // ...
}
```

### 集成测试

```go
func TestHookIntegration(t *testing.T) {
    // 创建模拟钩子
    mock := &MockHook{}
    
    // 创建钩子管理器
    hm := reitunnel.NewHookManager()
    hm.Register(mock)
    
    // 使用钩子管理器创建服务器
    srv := server.NewServer(config.ServerConfig{
        Addr: ":0",
    }, server.WithHookManager(hm))
    
    // 在 goroutine 中启动服务器
    go srv.Run()
    defer srv.Shutdown(context.Background())
    
    // 验证 OnServerStart 被调用
    calls := mock.GetCalls("OnServerStart")
    if len(calls) != 1 {
        t.Errorf("预期 1 次 OnServerStart 调用，得到 %d", len(calls))
    }
}
```

## 结论

钩子是扩展 Reitunnel 功能的强大机制。通过遵循这些模式和最佳实践，您可以创建高效、可维护的钩子，与 Reitunnel 系统无缝集成。

有关更多示例，请参阅 [examples](../examples/) 目录和 [hooks](../hooks/) 包中的默认钩子实现。
