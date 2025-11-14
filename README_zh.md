# Reitunnel

[![Go Reference](https://pkg.go.dev/badge/github.com/kawaiirei0/reitunnel.svg)](https://pkg.go.dev/github.com/kawaiirei0/reitunnel)
[![Go Report Card](https://goreportcard.com/badge/github.com/kawaiirei0/reitunnel)](https://goreportcard.com/report/github.com/kawaiirei0/reitunnel)

Reitunnel 是一个通用的、可嵌入的 Go 隧道库，旨在集成到其他服务或应用程序中。它提供稳定的隧道通信和丰富的生命周期/事件钩子机制，遵循钩子优先架构，支持日志记录、身份验证、审计、指标收集等扩展功能，并保证并发安全。

## 特性

- **可嵌入库**：设计为库而非独立工具 - 直接集成到您的 Go 应用程序中
- **钩子优先架构**：通过全面的钩子系统扩展所有生命周期事件的功能
- **并发安全**：所有核心组件都支持多个 goroutine 的并发访问
- **多种传输协议**：内置支持 TCP 和 WebSocket 协议，具有可扩展的传输接口
- **TLS 支持**：完整的 TLS 支持，包括客户端证书认证
- **灵活的错误处理**：可配置的错误策略（StopOnError、CollectAndContinue）
- **默认钩子**：开箱即用的日志、指标和认证钩子
- **优雅关闭**：适当的资源清理和连接管理
- **基于 Context**：使用 Go 的 context 支持取消和超时

## 快速开始

### 安装

```bash
go get github.com/kawaiirei0/reitunnel
```

### 基础服务器

```go
package main

import (
    "log"
    "os"
    
    "github.com/kawaiirei0/reitunnel"
    "github.com/kawaiirei0/reitunnel/config"
    "github.com/kawaiirei0/reitunnel/hooks"
    "github.com/kawaiirei0/reitunnel/server"
)

func main() {
    // 创建日志钩子
    logger := log.New(os.Stdout, "[reitunnel] ", log.LstdFlags)
    loggerHook := hooks.NewStdLoggerHook(logger, 0)
    
    // 创建钩子管理器并注册钩子
    hm := reitunnel.NewHookManager()
    hm.Register(loggerHook)
    
    // 创建服务器配置
    cfg := config.ServerConfig{
        Addr:      ":7000",
        Transport: "tcp",
        MaxConns:  100,
    }
    
    // 创建并启动服务器
    srv := server.NewServer(cfg, server.WithHookManager(hm))
    
    if err := srv.Run(); err != nil {
        log.Fatalf("服务器错误: %v", err)
    }
}
```

### 基础客户端

```go
package main

import (
    "log"
    
    "github.com/kawaiirei0/reitunnel/client"
    "github.com/kawaiirei0/reitunnel/config"
)

func main() {
    // 创建客户端配置
    cfg := config.ClientConfig{
        ServerAddr: "localhost:7000",
        Transport:  "tcp",
        Reconnect:  true,
    }
    
    // 创建并连接客户端
    c := client.NewClient(cfg)
    
    if err := c.Connect(); err != nil {
        log.Fatalf("连接错误: %v", err)
    }
    
    // 创建隧道：本地端口 8080 映射到远程端口 80
    tunnel, err := c.CreateTunnel("localhost:8080", "0.0.0.0:80")
    if err != nil {
        log.Fatalf("创建隧道错误: %v", err)
    }
    
    log.Printf("隧道已创建: %s", tunnel.ID)
    
    // 保持运行
    select {}
}
```

## 架构

Reitunnel 遵循钩子优先架构，所有关键事件都会触发钩子，可用于扩展功能：

```
应用程序代码
    ├── 服务器组件
    │   ├── 钩子管理器
    │   │   ├── 日志钩子
    │   │   ├── 指标钩子
    │   │   ├── 认证钩子
    │   │   └── 自定义钩子
    │   ├── 隧道管理器
    │   └── 传输层
    └── 客户端组件
        ├── 钩子管理器
        ├── 隧道管理器
        └── 传输层
```

## 核心概念

### 钩子（Hooks）

钩子是 Reitunnel 的主要扩展机制。`Hook` 接口定义了所有生命周期和数据传输事件的方法：

- `OnServerStart` / `OnServerStop` - 服务器生命周期
- `OnClientConnect` / `OnClientDisconnect` - 客户端连接
- `OnTunnelOpen` / `OnTunnelClose` - 隧道会话
- `OnDataSent` / `OnDataReceived` - 数据传输
- `OnError` - 错误处理

详见[钩子开发指南](docs/HOOKS_zh.md)了解如何创建自定义钩子。

### 钩子管理器

`HookManager` 管理钩子注册和执行，支持可配置的错误处理策略：

- **StopOnError**（默认）：当钩子返回错误时停止执行
- **CollectAndContinue**：收集错误但继续执行剩余钩子

### 传输层

Reitunnel 通过统一接口支持多种传输协议：

- **TCP**：标准 TCP 连接
- **WebSocket**：WebSocket 连接，便于穿透防火墙
- **自定义**：实现 `Transport` 接口以支持自定义协议

### 配置

服务器和客户端都使用带验证的配置结构：

```go
// 服务器配置
type ServerConfig struct {
    Addr      string        // 监听地址（例如 ":7000"）
    Transport string        // "tcp" 或 "websocket"
    TLS       *tls.Config   // 可选的 TLS 配置
    MaxConns  int           // 最大并发连接数（0 = 无限制）
    Timeout   time.Duration // 连接超时
}

// 客户端配置
type ClientConfig struct {
    ServerAddr string        // 要连接的服务器地址
    Transport  string        // "tcp" 或 "websocket"
    TLS        *tls.Config   // 可选的 TLS 配置
    Reconnect  bool          // 启用自动重连
    Timeout    time.Duration // 连接超时
}
```

## 默认钩子

### 日志钩子

记录所有生命周期事件，支持高频数据事件的可选采样：

```go
logger := log.New(os.Stdout, "[reitunnel] ", log.LstdFlags)
// 采样率：0 = 记录所有事件，N = 每 N 个事件记录一次
loggerHook := hooks.NewStdLoggerHook(logger, 100)
```

### 指标钩子

收集有关连接、隧道和数据传输的指标：

```go
metricsHook := hooks.NewMetricsHook()

// 获取当前指标
metrics := metricsHook.GetMetrics()
fmt.Printf("活跃连接数: %d\n", metrics.ActiveConnections)
fmt.Printf("已发送字节数: %d\n", metrics.BytesSent)
```

### 认证钩子

为客户端和隧道提供身份验证和授权：

```go
authHook := hooks.NewAuthHook(
    // 客户端验证器
    func(clientID string) error {
        if !isValidClient(clientID) {
            return reitunnel.ErrAuthFailed
        }
        return nil
    },
    // 隧道验证器
    func(tunnelID string, meta map[string]string) error {
        if !isAllowedTunnel(meta) {
            return reitunnel.ErrAuthFailed
        }
        return nil
    },
)
```

## 高级用法

### 多个钩子

注册多个钩子以组合功能：

```go
hm := reitunnel.NewHookManager()
hm.Register(authHook)      // 首先进行身份验证
hm.Register(loggerHook)    // 然后记录日志
hm.Register(metricsHook)   // 最后收集指标
```

### TLS 配置

启用 TLS 以实现安全连接：

```go
// 带 TLS 的服务器
tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{cert},
    ClientAuth:   tls.RequireAndVerifyClientCert,
    ClientCAs:    caCertPool,
}

srv := server.NewServer(config.ServerConfig{
    Addr: ":7000",
    TLS:  tlsConfig,
})

// 带 TLS 的客户端
clientTLSConfig := &tls.Config{
    Certificates: []tls.Certificate{clientCert},
    RootCAs:      caCertPool,
}

c := client.NewClient(config.ClientConfig{
    ServerAddr: "localhost:7000",
    TLS:        clientTLSConfig,
})
```

### 优雅关闭

使用 context 超时正确关闭服务器：

```go
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

if err := srv.Shutdown(ctx); err != nil {
    log.Printf("关闭错误: %v", err)
}
```

### 自定义传输

实现自定义传输协议：

```go
type CustomTransport struct{}

func (t *CustomTransport) Listen(addr string) (net.Listener, error) {
    // 自定义监听实现
}

func (t *CustomTransport) Dial(addr string) (net.Conn, error) {
    // 自定义拨号实现
}

func (t *CustomTransport) Name() string {
    return "custom"
}

// 使用自定义传输
srv := server.NewServer(cfg, server.WithTransport(&CustomTransport{}))
```

## 错误处理

Reitunnel 提供带上下文的结构化错误类型：

```go
// 检查特定错误
if errors.Is(err, reitunnel.ErrAuthFailed) {
    // 处理身份验证失败
}

// 提取错误元数据
if meta := reitunnel.ErrorMetadata(err); meta != nil {
    log.Printf("错误上下文: %v", meta)
}

// 使用类型化错误
var tunnelErr *reitunnel.TunnelError
if errors.As(err, &tunnelErr) {
    log.Printf("隧道 %s 在 %s 期间失败", tunnelErr.TunnelID, tunnelErr.Op)
}
```

## 示例

查看 [examples](examples/) 目录获取完整的工作示例：

- [basic_server.go](examples/basic_server.go) - 简单的服务器设置
- [basic_client.go](examples/basic_client.go) - 简单的客户端设置
- [multiple_hooks.go](examples/multiple_hooks.go) - 一起使用多个钩子
- [custom_hook.go](examples/custom_hook.go) - 创建自定义钩子
- [tls_example.go](examples/tls_example.go) - TLS 配置

## 文档

- [钩子开发指南](docs/HOOKS_zh.md) - 创建自定义钩子的综合指南
- [API 参考](https://pkg.go.dev/github.com/kawaiirei0/reitunnel) - 完整的 API 文档
- [性能最佳实践](docs/PERFORMANCE_zh.md) - 优化指南
- [安全注意事项](docs/SECURITY_zh.md) - 安全指南和最佳实践

## 性能考虑

- 对钩子中的高频数据事件使用采样
- 为您的用例配置适当的缓冲区大小
- 在需要时使用 `MaxConns` 限制并发连接
- 使用连接池创建隧道
- 考虑对昂贵的钩子操作进行异步处理

详见[性能最佳实践](docs/PERFORMANCE_zh.md)了解详细的优化指南。

## 安全

- 在生产环境中始终使用 TLS
- 通过认证钩子实现适当的身份验证
- 验证所有客户端输入和隧道参数
- 使用速率限制防止滥用
- 保护证书和密钥的安全
- 定期更新依赖项

详见[安全注意事项](docs/SECURITY_zh.md)了解全面的安全指南。

## 贡献

欢迎贡献！请随时提交问题、功能请求或拉取请求。

## 许可证

[MIT License](LICENSE)

## 致谢

Reitunnel 的设计灵感来自现代隧道解决方案，同时专注于通过钩子实现可嵌入性和可扩展性。
