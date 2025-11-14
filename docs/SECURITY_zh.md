# 安全注意事项

本指南提供了在生产环境中部署和运营 Reitunnel 的全面安全建议。在暴露隧道服务时，安全应该是首要关注点。

## 目录

- [威胁模型](#威胁模型)
- [身份验证和授权](#身份验证和授权)
- [TLS 配置](#tls-配置)
- [网络安全](#网络安全)
- [输入验证](#输入验证)
- [速率限制和 DoS 防护](#速率限制和-dos-防护)
- [日志记录和审计](#日志记录和审计)
- [安全部署](#安全部署)
- [安全检查清单](#安全检查清单)

## 威胁模型

了解潜在威胁有助于优先考虑安全措施：

### 威胁

1. **未授权访问**：攻击者在没有适当凭据的情况下连接
2. **中间人攻击**：拦截隧道流量
3. **拒绝服务**：资源耗尽攻击
4. **权限提升**：未授权的隧道创建或端口访问
5. **数据泄露**：通过隧道进行未授权的数据传输
6. **重放攻击**：重用捕获的身份验证令牌
7. **侧信道攻击**：通过时序或错误泄露信息

### 要保护的资产

- 服务器基础设施和资源
- 客户端凭据和证书
- 传输中的隧道数据
- 配置和密钥
- 审计日志和指标

## 身份验证和授权

### 客户端身份验证

在允许连接之前始终验证客户端：

```go
// 基于令牌的身份验证
type TokenAuthHook struct {
    reitunnel.NoopHook
    validTokens map[string]bool
    mu          sync.RWMutex
}

func (h *TokenAuthHook) OnClientConnect(ctx context.Context, clientID string) error {
    // 从 clientID 或 context 中提取令牌
    token := extractToken(clientID)
    
    h.mu.RLock()
    valid := h.validTokens[token]
    h.mu.RUnlock()
    
    if !valid {
        return fmt.Errorf("%w: 无效令牌", reitunnel.ErrAuthFailed)
    }
    return nil
}
```

**最佳实践**：
- 使用强随机生成的令牌（至少 32 字节）
- 实现令牌轮换和过期
- 安全存储令牌（哈希，而非明文）
- 使用恒定时间比较以防止时序攻击

### 基于证书的身份验证

使用双向 TLS 进行强身份验证：

```go
// 带客户端证书验证的服务器配置
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

// 证书验证钩子
certHook := hooks.NewCertAuthHook("expected-cn", "expected-org")
hm.Register(certHook)
```

**最佳实践**：
- 为客户端证书使用单独的 CA
- 实现证书吊销（CRL 或 OCSP）
- 设置适当的证书有效期（最长 1 年）
- 验证证书字段（CN、Organization 等）
- 监控证书过期

### 隧道授权

控制客户端可以创建哪些隧道：

```go
type TunnelAuthHook struct {
    reitunnel.NoopHook
    allowedPorts map[string][]int // clientID -> 允许的端口
    mu           sync.RWMutex
}

func (h *TunnelAuthHook) OnTunnelOpen(ctx context.Context, tunnelID string, meta map[string]string) error {
    clientID := meta["client_id"]
    remoteAddr := meta["remote_addr"]
    
    // 从地址解析端口
    _, portStr, err := net.SplitHostPort(remoteAddr)
    if err != nil {
        return fmt.Errorf("%w: 无效地址", reitunnel.ErrAuthFailed)
    }
    
    port, _ := strconv.Atoi(portStr)
    
    // 检查客户端是否允许使用此端口
    h.mu.RLock()
    allowed := h.allowedPorts[clientID]
    h.mu.RUnlock()
    
    for _, p := range allowed {
        if p == port {
            return nil
        }
    }
    
    return fmt.Errorf("%w: 不允许端口 %d", reitunnel.ErrAuthFailed, port)
}
```

**最佳实践**：
- 实施最小权限（仅允许必要的端口）
- 默认限制特权端口（<1024）
- 验证本地和远程地址
- 实施每个客户端的配额（最大隧道数、带宽）
- 记录所有授权决策

## TLS 配置

### 服务器 TLS 配置

使用强 TLS 设置：

```go
tlsConfig := &tls.Config{
    // 仅使用强密码套件
    CipherSuites: []uint16{
        tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    },
    
    // 要求 TLS 1.3（或最低 1.2）
    MinVersion: tls.VersionTLS13,
    
    // 优先使用服务器密码套件
    PreferServerCipherSuites: true,
    
    // 要求客户端证书
    ClientAuth: tls.RequireAndVerifyClientCert,
    ClientCAs:  caCertPool,
    
    // 禁用会话票证以实现前向保密
    SessionTicketsDisabled: false, // 启用以提高性能，禁用以获得最大安全性
}
```

**最佳实践**：
- 始终使用 TLS 1.3（或最低 TLS 1.2）
- 禁用弱密码套件（RC4、3DES、CBC 模式）
- 使用 ECDHE 实现前向保密
- 定期轮换证书
- 使用强密钥大小（RSA 2048+、ECDSA 256+）

### 客户端 TLS 配置

```go
tlsConfig := &tls.Config{
    // 用于双向 TLS 的客户端证书
    Certificates: []tls.Certificate{clientCert},
    
    // 验证服务器证书
    RootCAs:            caCertPool,
    InsecureSkipVerify: false, // 在生产环境中永远不要设置为 true
    
    // 验证服务器名称
    ServerName: "tunnel.example.com",
    
    // 最低 TLS 版本
    MinVersion: tls.VersionTLS13,
}
```

**最佳实践**：
- 始终验证服务器证书
- 固定预期的服务器证书或 CA
- 使用适当的服务器名称验证
- 在生产环境中永远不要禁用证书验证

### 证书管理

```go
// 安全加载证书
func loadCertificate(certFile, keyFile string) (tls.Certificate, error) {
    // 检查文件权限（应为 0600 或 0400）
    info, err := os.Stat(keyFile)
    if err != nil {
        return tls.Certificate{}, err
    }
    
    if info.Mode().Perm() & 0077 != 0 {
        return tls.Certificate{}, fmt.Errorf("密钥文件权限不安全: %v", info.Mode())
    }
    
    return tls.LoadX509KeyPair(certFile, keyFile)
}
```

**最佳实践**：
- 使用受限权限存储私钥（0600）
- 对生产密钥使用硬件安全模块（HSM）
- 实施自动证书续订
- 监控证书过期
- 对不同环境使用单独的证书

## 网络安全

### 防火墙配置

限制网络访问：

```bash
# 仅允许必要的端口
iptables -A INPUT -p tcp --dport 7000 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -j DROP

# 速率限制连接
iptables -A INPUT -p tcp --dport 7000 -m connlimit --connlimit-above 100 -j REJECT
```

**最佳实践**：
- 使用防火墙规则限制访问
- 实施连接速率限制
- 尽可能使用 VPN 或私有网络
- 分段网络（将隧道网络与内部网络分离）

### IP 白名单

按 IP 地址限制访问：

```go
type IPWhitelistHook struct {
    reitunnel.NoopHook
    allowedIPs map[string]bool
    mu         sync.RWMutex
}

func (h *IPWhitelistHook) OnClientConnect(ctx context.Context, clientID string) error {
    // 从 clientID 提取 IP（格式："ip:port"）
    ip, _, err := net.SplitHostPort(clientID)
    if err != nil {
        return fmt.Errorf("%w: 无效的客户端 ID", reitunnel.ErrAuthFailed)
    }
    
    h.mu.RLock()
    allowed := h.allowedIPs[ip]
    h.mu.RUnlock()
    
    if !allowed {
        return fmt.Errorf("%w: IP %s 不在白名单中", reitunnel.ErrAuthFailed, ip)
    }
    return nil
}
```

**最佳实践**：
- 为已知客户端维护 IP 白名单
- 使用 CIDR 范围进行基于网络的访问
- 与其他身份验证方法结合使用
- 记录被拒绝的连接尝试

## 输入验证

### 地址验证

在使用之前验证所有地址：

```go
func validateAddress(addr string) error {
    host, port, err := net.SplitHostPort(addr)
    if err != nil {
        return fmt.Errorf("无效的地址格式: %w", err)
    }
    
    // 验证端口范围
    portNum, err := strconv.Atoi(port)
    if err != nil || portNum < 1 || portNum > 65535 {
        return fmt.Errorf("无效端口: %s", port)
    }
    
    // 防止绑定到特权端口（除非明确允许）
    if portNum < 1024 {
        return fmt.Errorf("不允许特权端口: %d", portNum)
    }
    
    // 验证主机（防止 SSRF）
    if host != "" && host != "0.0.0.0" && host != "localhost" {
        ip := net.ParseIP(host)
        if ip == nil {
            return fmt.Errorf("无效的 IP 地址: %s", host)
        }
        
        // 防止访问私有网络
        if isPrivateIP(ip) {
            return fmt.Errorf("不允许私有 IP: %s", host)
        }
    }
    
    return nil
}

func isPrivateIP(ip net.IP) bool {
    // 检查私有 IP 范围
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

**最佳实践**：
- 验证所有用户提供的地址
- 通过阻止私有 IP 防止 SSRF
- 限制端口范围
- 清理元数据字段
- 使用白名单而不是黑名单

### 协议消息验证

验证所有协议消息：

```go
func (m *Message) Validate() error {
    // 检查消息类型
    if m.Type > protocol.MsgTypeError {
        return fmt.Errorf("%w: 无效的消息类型", reitunnel.ErrInvalidMessage)
    }
    
    // 检查隧道 ID 格式
    if m.TunnelID != "" && !isValidTunnelID(m.TunnelID) {
        return fmt.Errorf("%w: 无效的隧道 ID", reitunnel.ErrInvalidMessage)
    }
    
    // 检查有效负载大小
    if len(m.Payload) > MaxPayloadSize {
        return fmt.Errorf("%w: 有效负载过大", reitunnel.ErrInvalidMessage)
    }
    
    return nil
}
```

**最佳实践**：
- 验证所有消息字段
- 强制执行大小限制
- 检查格式错误的数据
- 尽早拒绝无效消息

## 速率限制和 DoS 防护

### 连接速率限制

限制连接尝试：

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
    // 从 clientID 提取 IP
    ip, _, _ := net.SplitHostPort(clientID)
    
    h.mu.Lock()
    limiter, ok := h.limiters[ip]
    if !ok {
        limiter = rate.NewLimiter(rate.Limit(10), 20) // 10 请求/秒，突发 20
        h.limiters[ip] = limiter
    }
    h.mu.Unlock()
    
    if !limiter.Allow() {
        return fmt.Errorf("IP %s 超过速率限制", ip)
    }
    return nil
}
```

**最佳实践**：
- 实施每个 IP 的速率限制
- 使用令牌桶算法
- 设置适当的限制（10-100 请求/秒）
- 对重复违规实施指数退避

### 资源限制

限制资源消耗：

```go
cfg := config.ServerConfig{
    Addr:     ":7000",
    MaxConns: 1000, // 限制并发连接
    Timeout:  30 * time.Second,
}

// 每个客户端的隧道限制
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
        return fmt.Errorf("客户端 %s 超过隧道配额", clientID)
    }
    
    h.tunnelCount[clientID]++
    return nil
}
```

**最佳实践**：
- 根据可用资源设置 MaxConns
- 实施每个客户端的配额
- 监控资源使用情况
- 实施优雅降级

### 带宽限制

控制带宽使用：

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
        // 为发送的字节预留令牌
        if err := limiter.WaitN(ctx, int(bytes)); err != nil {
            return fmt.Errorf("超过带宽限制: %w", err)
        }
    }
    return nil
}
```

**最佳实践**：
- 实施每个隧道的带宽限制
- 使用令牌桶实现平滑速率限制
- 根据订阅层级设置限制
- 监控并告警过度使用

## 日志记录和审计

### 安全事件日志记录

记录所有与安全相关的事件：

```go
type SecurityAuditHook struct {
    reitunnel.NoopHook
    logger *log.Logger
}

func (h *SecurityAuditHook) OnClientConnect(ctx context.Context, clientID string) error {
    h.logger.Printf("[安全] 客户端已连接: %s 于 %s", clientID, time.Now())
    return nil
}

func (h *SecurityAuditHook) OnError(ctx context.Context, err error, meta map[string]string) error {
    if errors.Is(err, reitunnel.ErrAuthFailed) {
        h.logger.Printf("[安全] 身份验证失败: %v, 元数据: %v", err, meta)
    }
    return nil
}
```

**要记录的事件**：
- 身份验证尝试（成功和失败）
- 授权决策
- 隧道创建和关闭
- 配置更改
- 错误和异常
- 速率限制违规

**最佳实践**：
- 使用结构化日志记录（JSON 格式）
- 包含时间戳和客户端标识符
- 记录到安全、防篡改的存储
- 实施日志轮换和保留
- 监控日志中的可疑模式
- 遵守数据保护法规

### 审计跟踪

维护全面的审计跟踪：

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
    // 存储在数据库或安全日志中
    h.db.Insert(trail)
}
```

**最佳实践**：
- 将审计日志与应用程序日志分开存储
- 包含足够的上下文以进行调查
- 实施篡改检测
- 根据合规要求保留日志
- 定期审查审计日志

## 安全部署

### 环境配置

使用环境变量存储密钥：

```go
// ❌ 不好：硬编码密钥
tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{loadCert("cert.pem", "key.pem")},
}

// ✅ 好：环境变量
certFile := os.Getenv("TLS_CERT_FILE")
keyFile := os.Getenv("TLS_KEY_FILE")
if certFile == "" || keyFile == "" {
    log.Fatal("必须设置 TLS_CERT_FILE 和 TLS_KEY_FILE")
}
tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{loadCert(certFile, keyFile)},
}
```

**最佳实践**：
- 永远不要将密钥提交到版本控制
- 使用密钥管理系统（Vault、AWS Secrets Manager）
- 定期轮换密钥
- 对不同环境使用不同的密钥
- 在 CI/CD 中实施密钥扫描

### 容器安全

在容器中部署时：

```dockerfile
# 使用最小基础镜像
FROM golang:1.21-alpine AS builder

# 以非 root 用户运行
RUN adduser -D -u 1000 reitunnel
USER reitunnel

# 仅复制必要的文件
COPY --chown=reitunnel:reitunnel . /app
WORKDIR /app

# 构建
RUN go build -o reitunnel

# 运行时镜像
FROM alpine:latest
RUN adduser -D -u 1000 reitunnel
USER reitunnel

COPY --from=builder /app/reitunnel /usr/local/bin/

# 删除能力
RUN setcap 'cap_net_bind_service=+ep' /usr/local/bin/reitunnel

ENTRYPOINT ["/usr/local/bin/reitunnel"]
```

**最佳实践**：
- 以非 root 用户运行
- 使用最小基础镜像
- 扫描镜像中的漏洞
- 删除不必要的能力
- 使用只读根文件系统
- 实施资源限制

### 监控和告警

监控安全指标：

```go
// 对可疑模式发出告警
func (h *SecurityMonitorHook) OnError(ctx context.Context, err error, meta map[string]string) error {
    if errors.Is(err, reitunnel.ErrAuthFailed) {
        h.authFailureCount.Add(1)
        
        // 如果失败次数过多则告警
        if h.authFailureCount.Load() > 100 {
            h.alerter.Send("身份验证失败率高", err, meta)
        }
    }
    return nil
}
```

**要监控的指标**：
- 身份验证失败率
- 连接速率
- 带宽使用
- 错误率
- 资源利用率
- 证书过期

## 安全检查清单

### 部署前

- [ ] 使用强密码套件启用 TLS
- [ ] 实施客户端身份验证（证书或令牌）
- [ ] 配置隧道授权
- [ ] 设置速率限制
- [ ] 实施输入验证
- [ ] 配置资源限制（MaxConns、超时）
- [ ] 设置安全日志记录和审计
- [ ] 审查并加固防火墙规则
- [ ] 扫描漏洞
- [ ] 进行安全测试

### 生产环境

- [ ] 监控身份验证失败
- [ ] 监控资源使用
- [ ] 定期审查审计日志
- [ ] 轮换证书和密钥
- [ ] 定期更新依赖项
- [ ] 实施入侵检测
- [ ] 为安全事件设置告警
- [ ] 进行定期安全审计
- [ ] 维护事件响应计划
- [ ] 保持文档更新

### 持续进行

- [ ] 审查和更新安全策略
- [ ] 培训团队安全最佳实践
- [ ] 进行渗透测试
- [ ] 审查和更新访问控制
- [ ] 监控安全公告
- [ ] 更新威胁模型
- [ ] 审查和改进日志记录
- [ ] 进行安全演练

## 事件响应

### 检测

监控安全事件：
- 异常的身份验证模式
- 过多的连接尝试
- 异常的带宽使用
- 意外的错误率
- 证书验证失败

### 响应

检测到事件时：

1. **遏制**：阻止恶意 IP，吊销受损凭据
2. **调查**：审查日志，识别范围和影响
3. **修复**：修复漏洞，更新配置
4. **恢复**：恢复正常操作
5. **学习**：记录事件，更新程序

### 示例：阻止恶意客户端

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
        return fmt.Errorf("%w: 客户端已被阻止", reitunnel.ErrAuthFailed)
    }
    return nil
}
```

## 结论

安全是一个持续的过程，而不是一次性的配置。定期审查和更新您的安全措施，监控威胁，并了解新的漏洞和最佳实践。

有关更多信息，请参阅：
- [钩子开发指南](HOOKS_zh.md)
- [性能最佳实践](PERFORMANCE_zh.md)
- [示例](../examples/)
