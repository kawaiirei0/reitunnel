# 🌀 Reitunnel — 通用 Go 隧道库（库级 API 设计，含日志等 Hook）

> Author: Rei
> Version: 0.1.0
> Repo: github.com/kawaiirei0/reitunnel

**定位**：一个**通用**、**可嵌入**的 Go 隧道库（不是独立二进制工具）。设计目标是作为其他服务或库的一部分被引用，提供稳定的隧道通信与丰富的生命周期/事件 Hook（默认包含日志 Hook，方便替换扩展）。

---

## 🎯 设计原则（再强调）

* **库而非工具**：不包含强制性的 CLI。所有功能通过包 API 暴露，使用者在应用层决定如何启动/集成。
* **Hook-first**：所有关键生命周期/事件都可通过 Hook 扩展 —— 日志、认证、审计、指标、流量控制、报表等。
* **小而可组合**：核心保持精简，扩展点和中间件链用于复杂功能。
* **并发安全**：默认并发安全；明确文档化锁/上下文语义。

---

## 🧩 核心包结构（建议）

```
/reitunnel
  ├─ server/         # Server 实现（用于 embedding）
  ├─ client/         # Client 实现（用于 embedding）
  ├─ tunnel/         # 核心隧道、连接、映射抽象
  ├─ hooks/          # 提供若干默认 hook（logger, metrics, auth）
  ├─ transport/      # 传输协议实现（tcp, ws, custom）
  ├─ config/         # 配置结构体与解析
  └─ examples/
```

---

## 🔌 Hook 与事件模型概览

库暴露一组 **事件**，使用者可以注册任意实现 `Hook` 的插件来响应这些事件。事件采用异步/同步两种调用方式可选（默认同步以便错误传播；关键日志建议异步实现）。

### 主要事件

* `OnServerStart(ctx)` / `OnServerStop(ctx)`
* `OnClientConnect(ctx, clientID)` / `OnClientDisconnect(ctx, clientID, err)`
* `OnTunnelOpen(ctx, tunnelID, meta)` / `OnTunnelClose(ctx, tunnelID)`
* `OnMapAdded(ctx, clientID, mapping)` / `OnMapRemoved(ctx, clientID, mapping)`
* `OnDataSent(ctx, tunnelID, bytes)` / `OnDataReceived(ctx, tunnelID, bytes)`
* `OnError(ctx, err, meta)`

---

## ✅ Hook 接口 (Go)

下面是推荐的 Hook 接口定义（放 `hooks` 包或根包）：

```go
package reitunnel

import "context"

// Hook 表示可以注册到 Reitunnel 的事件处理器。
type Hook interface {
    // Called when server starts. Return error to stop startup if synchronous.
    OnServerStart(ctx context.Context) error

    // Called when server stops.
    OnServerStop(ctx context.Context) error

    // Called when a client connects to the server.
    OnClientConnect(ctx context.Context, clientID string) error

    // Called when a client disconnects.
    OnClientDisconnect(ctx context.Context, clientID string, reason error) error

    // Called when a tunnel is opened (a mapping session between remote and local).
    OnTunnelOpen(ctx context.Context, tunnelID string, meta map[string]string) error

    // Called when a tunnel is closed.
    OnTunnelClose(ctx context.Context, tunnelID string) error

    // Bytes transferred events (may be high frequency; implementations should be efficient).
    OnDataSent(ctx context.Context, tunnelID string, bytes int64) error
    OnDataReceived(ctx context.Context, tunnelID string, bytes int64) error

    // Generic error hook.
    OnError(ctx context.Context, err error, meta map[string]string) error
}
```

> 说明：以上方法可以根据需要拆分为更细接口（比如 `StartStopHook`, `ConnectionHook`, `DataHook`）以便用户只实现需要的部分。库内会提供 `type NoopHook struct{}` 实现默认空方法，方便组合。

---

## 🎛 Hook 管理（注册与执行策略）

库提供 Hook 管理器（`HookManager`），支持：

* 注册多个 Hook（有序），执行时按注册顺序调用。
* 支持同步或者异步执行。
* 支持错误策略：`StopOnError`（默认）或 `CollectAndContinue`。

示例 API：

```go
hm := reitunnel.NewHookManager()
hm.Register(myLoggerHook)
hm.Register(metricsHook)
srv := reitunnel.NewServer(cfg, reitunnel.WithHookManager(hm))
```

---

## 📦 默认日志 Hook（StdLoggerHook）

库内置一个简单但实用的 `StdLoggerHook`，使用 `log.Logger`（或可接受 `interface{ Info, Warn, Error }`）：

```go
package hooks

import (
    "context"
    "log"
    "github.com/kawaiirei0/reitunnel"
)

type StdLoggerHook struct {
    L *log.Logger
}

func NewStdLoggerHook(l *log.Logger) *StdLoggerHook {
    return &StdLoggerHook{L: l}
}

func (h *StdLoggerHook) OnServerStart(ctx context.Context) error {
    h.L.Println("[reitunnel] server start")
    return nil
}
// ... 其余方法简单打印事件和 meta ...
```

使用：

```go
import (
    "log"
    "os"
    "github.com/kawaiirei0/reitunnel"
    "github.com/kawaiirei0/reitunnel/hooks"
)

func main() {
    l := log.New(os.Stdout, "", log.LstdFlags)
    loggerHook := hooks.NewStdLoggerHook(l)

    hm := reitunnel.NewHookManager()
    hm.Register(loggerHook)

    srv := reitunnel.NewServer(":7000", reitunnel.WithHookManager(hm))
    srv.Run()
}
```

> 默认日志 Hook 设计要轻量并且非阻塞（对于高频 `OnData*` 事件可以在内部采用采样、聚合或异步队列）。

---

## 🧩 自定义 Hook 示例（Metrics Hook）

下面是一个简单的自定义 hook 示例（将数据上报到 Prometheus/Grafana 之类的系统：伪代码）：

```go
type MetricsHook struct {
    bytesSent   prometheus.Counter
    bytesRecv   prometheus.Counter
}

func (m *MetricsHook) OnDataSent(ctx context.Context, tunnelID string, bytes int64) error {
    m.bytesSent.Add(float64(bytes))
    return nil
}

// 实现其余 Hook 方法...
```

注册方式同上。

---

## 🧠 生命周期 & 错误传播

* `OnServerStart` 在所有网络监听和资源申请完成前调用（允许 Hook 做初始化）；如果 Hook 返回错误且策略为 `StopOnError`，服务器启动应失败并清理已分配资源。
* `OnClientConnect` 在验证与握手完成后触发（可在 Hook 里进行审计或初始化 per-client state）。
* `OnError` 提供统一的错误通知，包含 `meta` 信息（clientID、tunnelID、op）。
* `OnData*` 事件可能非常频繁，Hook 实现**必须高效**或采用异步聚合。

---

## ⛓ Hook 链组合范式（中间件式）

为便于组合，建议实现中间件链风格：每个 Hook 收到 `next` 回调或 `Context` 中包含 `Proceed()`，不过为了简单起见，也可以由 `HookManager` 在注册顺序上串联同步调用。

---

## 🧰 样例：完整 Server 嵌入（代码）

```go
package main

import (
    "context"
    "log"
    "os"
    "time"

    "github.com/kawaiirei0/reitunnel"
    "github.com/kawaiirei0/reitunnel/hooks"
)

func main() {
    // 配置
    cfg := reitunnel.ServerConfig{
        Addr: ":7000",
        TLS:  nil, // or TLS config
        // ... other options
    }

    // Hook 管理器 + 默认日志 hook
    l := log.New(os.Stdout, "[reitunnel] ", log.LstdFlags)
    loggerHook := hooks.NewStdLoggerHook(l)
    hm := reitunnel.NewHookManager()
    hm.Register(loggerHook)

    srv := reitunnel.NewServer(cfg, reitunnel.WithHookManager(hm))

    // 可选：在另外的 goroutine 中安全地停止
    go func() {
        time.Sleep(24 * time.Hour)
        _ = srv.Shutdown(context.Background())
    }()

    if err := srv.Run(); err != nil {
        l.Fatalf("server exit: %v", err)
    }
}
```

---

## 🔐 Hook 用于安全（认证 / 授权）

Hook 也可用于接入认证流程，例如 `OnClientConnect` 中检查 `clientID` 与 token，或在 `OnTunnelOpen` 中验证目标端口是否允许映射。若验证不通过，Hook 返回错误，底层会关闭连接并触发 `OnError/OnClientDisconnect`。

---

## 📈 性能与采样建议（高频事件）

`OnDataSent/OnDataReceived` 为高频事件，推荐策略：

* **聚合**：在 Hook 内部对短时间窗口（如 1s）内的字节数进行聚合再上报。
* **采样**：对流量统计做采样（例如 1% 的事件上报详细数据）。
* **异步队列**：使用无锁环形缓冲或 channel + worker 批量写出。

---

## 🧪 测试建议

* 为每个 Hook 提供 mock 实现与断言（例如记录调用次数与参数）。
* 模拟高并发数据流以测试 `OnData*` 路径的性能与内存占用。
* 对错误传播路径进行单元测试（Hook 抛错 → server 行为符合策略）。

---

## 🧾 文档示例条目（README 推荐写法）

* 快速上手（Server / Client 嵌入示例）
* Hook 开发指南（接口、示例、性能最佳实践）
* 默认 Hook（StdLoggerHook、MetricsHook、AuthHook）使用说明
* API 文档：`Server`, `Client`, `HookManager`, `Tunnel` types
* 扩展点：如何添加自定义传输、封包协议、加密算法
