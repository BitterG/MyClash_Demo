# 从零手写一个迷你 Clash：完整学习记录

> 这是一篇学习笔记：从"Clash 是什么"开始，用 Go 从零实现一个功能完整的迷你 Clash 内核，
> 最终用真实机场订阅成功访问。所有代码都是教学项目的一部分，边写边讲原理，
> 每个里程碑都附关键实现代码。
---
![main_img.png](main_img.png)
## 目录

- [项目概述](#项目概述)
- [Clash 内核的架构](#clash-内核的架构)
- [里程碑 0+1：工程骨架与 HTTP 代理](#里程碑-01工程骨架与-http-代理)
- [里程碑 2：DNS 与 fake-ip](#里程碑-2dns-与-fake-ip)
- [里程碑 3：SOCKS5 与节点切换](#里程碑-3socks5-与节点切换)
- [里程碑 4：加密协议与真实订阅](#里程碑-4加密协议与真实订阅)
- [踩坑记录：四个真实 bug](#踩坑记录四个真实-bug)
- [概念延伸：系统代理、TUN 与加速器](#概念延伸系统代理tun-与加速器)
- [最终成果与可扩展方向](#最终成果与可扩展方向)

---

## 项目概述

**目标**：理解 Clash 的工作原理，并手写一个可运行的简易版。

**技术栈**：Go 1.23+、gopkg.in/yaml.v3、github.com/quic-go/quic-go（后期引入）

**最终成果**：一个约 3000 行的 Go 程序，具备：

- HTTP 代理入站（CONNECT 隧道 + 明文转发）
- SOCKS5 代理入站（完整握手）
- fake-ip DNS 服务器（UDP）
- 规则引擎（DOMAIN-SUFFIX / IP-CIDR / MATCH）
- 出站组 Selector（运行时切换节点）
- 六种出站协议：DIRECT / REJECT / SOCKS5 / Shadowsocks / Trojan / Hysteria2
- DNS-over-HTTPS 防污染解析
- 真实机场订阅可用（hysteria2 节点实测连通）

**项目结构**（完全对齐真实 mihomo 的分层）：

```
main.go                 # 入口：加载配置、装配内核、启动监听
internal/
  constant/             # 全局类型：Metadata（元数据）、常量、标准错误
  config/               # YAML 配置加载 + 规则行解析
  adapter/              # 公共抽象：Adapter（出站契约）、Transport（内核契约）
  inbound/              # 入站：HTTP 代理、SOCKS5 代理、监听器
  outbound/             # 出站：DIRECT/REJECT/SOCKS5/SS/Trojan/Hysteria2
  outboundgroup/        # 出站组：Selector（节点选择）
  router/               # 规则引擎：逐条匹配规则
  tunnel/               # 内核调度：入站 → 选路 → 出站拨号
  dns/                  # DNS：fake-ip 池、UDP 服务器、DoH 客户端
  socks5/               # SOCKS5 地址编解码（协议样板）
  netutil/              # 双向转发（relay）
  hub/                  # 装配车间：配置 → 运行时对象树
  subscribe/            # 订阅解析器
cmd/
  minidig/              # 迷你 dig：测试 DNS 服务器
  minisocks/            # 迷你 SOCKS5 服务器：本地测试节点
  dohquery/             # DoH 查询工具：诊断防污染
```

---

## Clash 内核的架构

### 连接流水线：四步处理

Clash 内核处理每条连接，固定走四步：

```
入站(inbound) ──► 路由(router) ──► 出站(outbound) ──► 转发(relay)
  解析流量            匹配规则            拨号              双向拷贝
```

每一层都是一个**接口**，这是 Clash 能无限扩展协议的原因：

| 抽象 | 职责 | 接口 |
|---|---|---|
| Metadata | 一条连接的"目的地描述"（host/port），全链路传递 | 结构体 |
| Adapter | "给我元数据，我还你一条已拨通的连接" | `Dial(ctx, m) (net.Conn, error)` |
| Transport | 入站把解析好的连接交给内核 | `Conn(ctx, m, conn) (net.Conn, error)` |

### 核心抽象代码

```go
// internal/adapter/adapter.go —— 整个内核的两个契约

// Adapter：所有出站协议的共同接口。
// 加一个协议 = 加一个 Dial() 实现，其余零改动。
type Adapter interface {
    Name() string
    Dial(ctx context.Context, m *constant.Metadata) (net.Conn, error)
}

// Transport：内核对入站暴露的接口。
// 入站解析出 Metadata 后交给内核，内核负责选路 + 拨号。
type Transport interface {
    Conn(ctx context.Context, m *constant.Metadata, conn net.Conn) (net.Conn, error)
}
```

```go
// internal/constant/metadata.go —— 血液：一条连接的目的地描述

type Metadata struct {
    NetWork string `json:"network"` // "tcp" / "udp"
    Type    string `json:"type"`    // 出站协议类型
    Host    string `json:"host"`    // 目标主机名（可能是 IP）
    DstPort string `json:"dstPort"` // 目标端口
}

// Pure 返回副本：Clash 铁律——规则命中时"换一条新的 Metadata"，
// 不修改原始信息，保证任何阶段都能追溯。
func (m *Metadata) Pure() *Metadata {
    if m == nil {
        return nil
    }
    cpy := *m
    return &cpy
}
```

### 内核调度主链

```go
// internal/tunnel/tunnel.go —— 总调度室：入站 → 选路 → 拨号

func (t *Tunnel) Conn(ctx context.Context, m *constant.Metadata, conn net.Conn) (net.Conn, error) {
    // fake-ip 反查：如果 Host 是假 IP，反查回真域名
    if ip, err := netip.ParseAddr(m.Host); err == nil && t.resolver != nil {
        if host, ok := t.resolver.LookBack(ip); ok {
            m2 := m.Pure()
            m2.Host = host
            m = m2
        }
    }

    // 1) 规则匹配：得到目标出站名
    targetName := t.router.Match(m)

    // 2) 解析出站适配器
    a := t.router.Resolve(targetName)
    if a == nil {
        return nil, errors.New("no adapter found: " + targetName)
    }

    // 3) 出站拨号
    target, err := a.Dial(ctx, m)
    if err != nil {
        log.Warnf("[tunnel] dial %s -> %s failed: %v", targetName, m.DestinationAddress(), err)
        return nil, err
    }

    log.Infof("[tunnel] %s | %s -> %s", targetName, conn.RemoteAddr(), m.DestinationAddress())
    return target, nil
}
```

---

## 里程碑 0+1：工程骨架与 HTTP 代理

### 学到的第一课：骨架不用手写

Clash 的分层（constant/adapter/inbound/outbound/router/tunnel/hub）是 mihomo 团队几年演化的物理形状。价值不在"有这些目录"，而在**接口边界为什么划在这里**。骨架可以抄，数据流必须自己写。

### HTTP 代理的两种模式

**CONNECT 隧道**（https 流量）：

```
客户端: CONNECT host:443 HTTP/1.1
代理:   拨通目标 → 回 "200 Connection Established"
之后:   双向转发原始字节流（TLS 加密在客户端和真实目标之间，代理看不见内容）
```

**普通 HTTP 转发**（http 明文流量）：

```
客户端: GET http://host/path HTTP/1.1  （绝对 URI 形式）
代理:   重建请求（origin-form）发到目标 → 响应抄回客户端
```

### 关键代码：CONNECT 处理

```go
// internal/inbound/http.go —— 入站处理器核心

func (h *Http) handleConnect(w http.ResponseWriter, r *http.Request) {
    host := r.Host // CONNECT 时是 "example.com:443"
    if !strings.Contains(host, ":") {
        host = net.JoinHostPort(host, "443")
    }
    hostname, port, _ := net.SplitHostPort(host)

    meta := &constant.Metadata{
        NetWork: "tcp",
        Type:    constant.HTTP,
        Host:    hostname,
        DstPort: port,
    }

    // 劫持底层连接
    clientConn, err := hijackConn(w)
    if err != nil {
        return
    }

    // 交给内核：选路 + 出站拨号
    target, err := h.transport.Conn(r.Context(), meta, clientConn)
    if err != nil {
        code := "502 Bad Gateway"
        if errors.Is(err, constant.ErrBlocked) {
            code = "403 Forbidden"
        }
        fmt.Fprintf(clientConn, "HTTP/1.1 %s\r\n\r\n", code)
        clientConn.Close()
        return
    }

    // 拨号成功 → 先回 200，再双向转发
    fmt.Fprintf(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n")
    log.Infof("[http] CONNECT %s -> %s", host, target.RemoteAddr())
    go netutil.Relay(clientConn, target)
}
```

### 关键代码：连接劫持与缓冲回填

```go
// 劫持时 http 层可能已经把请求后面的字节读进缓冲区，
// 必须把这些字节"放回"读流，否则数据凭空消失。
func hijackConn(w http.ResponseWriter) (net.Conn, error) {
    hj, ok := w.(http.Hijacker)
    if !ok {
        return nil, errors.New("hijacking not supported")
    }
    conn, rw, err := hj.Hijack()
    if err != nil {
        return nil, err
    }
    if n := rw.Reader.Buffered(); n > 0 {
        peeked, _ := rw.Reader.Peek(n)
        conn = &bufferedConn{
            Conn:   conn,
            reader: io.MultiReader(bytes.NewReader(peeked), conn),
        }
    }
    return conn, nil
}
```

### 关键代码：规则引擎

```go
// internal/router/router.go —— 心脏：拿 Metadata 匹配规则

// Match 按顺序匹配规则，返回命中的目标出站名。
// 规则顺序就是配置文件里的顺序：第一条命中即返回。
func (r *Router) Match(m *constant.Metadata) string {
    for _, rule := range r.rules {
        if matchRule(rule, m) {
            return rule.Target
        }
    }
    return r.defaultProxy
}

func matchRule(rule Rule, m *constant.Metadata) bool {
    host := strings.ToLower(m.Host)
    payload := strings.ToLower(rule.Payload)

    switch rule.Type {
    case "MATCH":
        return true // 兜底规则，永远命中
    case "DOMAIN-SUFFIX":
        return host == payload || strings.HasSuffix(host, "."+payload)
    case "DOMAIN-KEYWORD":
        return strings.Contains(host, payload)
    case "IP-CIDR":
        ip := net.ParseIP(m.Host)
        if ip == nil {
            return false
        }
        _, ipNet, err := net.ParseCIDR(rule.Payload)
        if err != nil {
            return false
        }
        return ipNet.Contains(ip)
    }
    return false
}
```

### 验收

```powershell
curl -x http://127.0.0.1:7891 https://www.baidu.com -I   # 200 OK
curl -x http://127.0.0.1:7891 http://example.com -I       # 200 OK
# REJECT 规则测试：example.com 返回 403
```

---

## 里程碑 2：DNS 与 fake-ip

### 要解决的问题

DIRECT 出站直接 `net.JoinHostPort(host, port)`，域名由**系统**解析。但系统 DNS 有两个坑：

1. 解析发生在"系统默认服务器"上，代理控制不了
2. 解析在拨号之前，Clash 没法在"知道域名"和"开始拨号"之间插逻辑

### fake-ip 原理

```
客户端(浏览器) ──DNS查询──► mini-clash :5353 ──┬─► 记下映射
                                               └─► 回一个 198.18.x.x 假IP
客户端 ──CONNECT 198.18.x.x:443──► mini-clash ──► 反查映射得真域名
                                        └─► 按真域名走规则 ──► 用真域名拨号
```

**本质**：给客户端一个假 IP，让"域名信息"继续留在内核手里。路由决策用反查回来的真域名做，而不是拿 IP 匹配。

### 关键代码：Resolver（域名 ↔ IP 的双向调度）

```go
// internal/dns/resolver.go

type Resolver struct {
    pool   *Pool   // 假 IP 池
    hosts  *Hosts  // 映射表
    fakeIP bool    // 是否启用 fake-ip
}

// Resolve 要一个 IP：fake-ip 模式三步走
func (r *Resolver) Resolve(host string) (netip.Addr, error) {
    if !r.fakeIP {
        return realResolve(host)
    }
    // 1. 已有映射 → 复用（同一域名永远同一个假 IP）
    if ip, ok := r.hosts.Lookup(host); ok {
        return ip, nil
    }
    // 2. 没有 → 分配新假 IP
    ip := r.pool.Next()
    // 3. 记账
    r.hosts.Add(ip, host)
    return ip, nil
}

// LookBack 反查：假 IP → 真域名（流量阶段内核用）
func (r *Resolver) LookBack(ip netip.Addr) (string, bool) {
    if !r.fakeIP || !r.pool.IsFake(ip) {
        return "", false
    }
    return r.hosts.LookBack(ip)
}
```

### 关键代码：假 IP 池

```go
// internal/dns/pool.go —— IP 本质是 32 位数字，"分配 IP"就是数数

func (p *Pool) Next() netip.Addr {
    p.mu.Lock()
    defer p.mu.Unlock()
    base := p.prefix.Addr()
    n := binary.BigEndian.Uint32(base.As4()[:])
    n += p.next               // 数字加 1 = 下一个 IP
    var out [4]byte
    binary.BigEndian.PutUint32(out[:], n)
    p.next++
    return netip.AddrFrom4(out)
}

// IsFake 判断 IP 是否在本池网段内
func (p *Pool) IsFake(ip netip.Addr) bool {
    return p.prefix.Contains(ip)
}
```

### 关键代码：UDP DNS 服务器

```go
// internal/dns/server.go —— 收包、拆包、回包循环

func (s *Server) Serve() error {
    conn, err := net.ListenPacket("udp", s.addr)
    if err != nil {
        return err
    }
    s.conn = conn

    buf := make([]byte, 512) // 标准 DNS over UDP 单包上限
    for {
        // UDP 无连接：ReadFrom 收包 + 知道谁发的
        n, clientAddr, err := conn.ReadFrom(buf)
        if err != nil {
            return err
        }
        // 拆包：字节流 → 域名/类型/ID/问题段
        host, qtype, id, question, ok := ParseQuery(buf[:n])
        if !ok || qtype != 1 { // 只处理 A 记录
            continue
        }
        // 换 IP：业务层
        ip, err := s.resolver.Resolve(host)
        if err != nil {
            continue
        }
        // 打包回信：字段 → 字节流，WriteTo 发回
        resp := BuildAResponse(id, question, net.IP(ip.AsSlice()))
        s.conn.WriteTo(resp, clientAddr)
    }
}
```

### 学到的协议知识

**DNS 是二进制协议**，域名是"长度+内容"编码，不是明文字符串：

```
07 | e x a m p l e | 03 | c o m | 00
↑长度7               ↑长度3       ↑结束
```

定长字段才能用固定偏移切片，变长字段必须**游标循环**一段一段读：

```go
// 正确的域名解析：一段一段跳着读
func parseName(data []byte) (string, int, error) {
    off := 0
    var labels []string
    for {
        l := int(data[off])
        if l == 0 {
            break // 0 = 域名结束
        }
        labels = append(labels, string(data[off+1:off+1+l]))
        off += 1 + l // 跳过"长度字节+内容"，继续下一段
    }
    return strings.Join(labels, "."), off + 1, nil
}
```

### 验收

```powershell
go run ./cmd/minidig 127.0.0.1:15353 example.com   # 198.18.0.1
go run ./cmd/minidig 127.0.0.1:15353 example.com   # 198.18.0.1（复用映射）
go run ./cmd/minidig 127.0.0.1:15353 www.baidu.com # 198.18.0.2（池递增）
# 假 IP 走真实流量：curl 连 198.18.0.1，内核反查 example.com，真拨 Cloudflare
```

---

## 里程碑 3：SOCKS5 与节点切换

### SOCKS5：所有代理协议的祖宗

握手三阶段（RFC 1928），全是"客户端发一句，服务器答一句"：

```
阶段1 方法协商：  C→S: [05 01 00]      （VER=5，1个方法，no-auth）
                 S→C: [05 00]          （就用 no-auth）

阶段2 连接请求：  C→S: [05 01 00] + 地址字段
                 S→C: [05 00 00] + 绑定地址

阶段3 透明隧道：  之后连接变成裸 TCP，双向转发
```

**地址字段**（ATYP）三种编码：

```
0x01 IPv4: [01] + 4字节IP + 2字节端口        → 7 字节
0x03 域名: [03] + 1字节长度 + 域名 + 2字节端口  → 变长
0x04 IPv6: [04] + 16字节IP + 2字节端口       → 19 字节
```

**关键**：`0x03 域名` 意味着 SOCKS5 支持"把域名交给服务器解析"——这就是 Clash 的 remote DNS（远端解析）的协议基础。

### 关键代码：SOCKS5 出站（客户端侧）

```go
// internal/outbound/socks5.go —— 所有代理型协议的模板：
// 壳都一样，区别只在握手时交换的字节。

func (s *Socks5) Dial(ctx context.Context, m *constant.Metadata) (net.Conn, error) {
    // 1. 拨到节点服务器（TCP 三次握手在 net.Dial 内部已完成）
    node, err := s.dialer(ctx, "tcp", net.JoinHostPort(s.server, strconv.Itoa(s.port)))
    if err != nil {
        return nil, err
    }
    success := false
    defer func() {
        if !success {
            node.Close() // 任何一步失败都关掉，不泄露连接
        }
    }()
    node.SetDeadline(time.Now().Add(15 * time.Second)) // 握手限时

    // 2. 方法协商：发 [05 01 00]，读 2 字节应答
    node.Write([]byte{0x05, 0x01, 0x00})
    var methodResp [2]byte
    io.ReadFull(node, methodResp[:]) // 定长字段必须读满
    if methodResp[1] != 0x00 {
        return nil, fmt.Errorf("socks5: unsupported auth method 0x%02x", methodResp[1])
    }

    // 3. 连接请求：发 [05 01 00] + 地址字段
    node.Write([]byte{0x05, 0x01, 0x00})
    target := socks5.NewAddr(m.Host, uint16(m.PortInt()))
    target.WriteTo(node) // m.Host 是域名就发域名，节点会替我们解析

    // 4. 读应答：头 3 字节 [VER, REP, RSV]，ATYP 留给 ReadFrom 自己读
    var respHdr [3]byte
    io.ReadFull(node, respHdr[:])
    if respHdr[1] != 0x00 {
        return nil, fmt.Errorf("socks5: connect failed, REP=0x%02x", respHdr[1])
    }
    socks5.ReadFrom(node) // 读掉绑定地址（不读掉会混进隧道数据流）

    // 5. 握手完成，交还隧道
    node.SetDeadline(time.Time{}) // 清超时：隧道阶段不能有超时
    success = true
    return node, nil
}
```

### 关键代码：SOCKS5 入站（服务器侧）

```go
// internal/inbound/socks.go —— 与独立测试节点 minisocks 是同一份逻辑的两种命运：
// 独立进程握手后【自己拨号】，内核入站握手后【交给内核】

func (l *SocksListener) handle(client net.Conn) {
    defer client.Close()
    client.SetDeadline(time.Now().Add(15 * time.Second))

    // 阶段 1：方法协商
    var greeting [2]byte
    io.ReadFull(client, greeting[:])
    methods := make([]byte, int(greeting[1]))
    io.ReadFull(client, methods)
    client.Write([]byte{0x05, 0x00}) // 挑 no-auth

    // 阶段 2：连接请求
    var reqHdr [3]byte
    io.ReadFull(client, reqHdr[:])
    target, _ := socks5.ReadFrom(client) // 读地址字段

    // 交给内核：填 Metadata → 选路 + 拨号
    meta := &constant.Metadata{
        NetWork: "tcp",
        Type:    constant.SOCKS,
        Host:    target.Host,
        DstPort: fmt.Sprintf("%d", target.Port),
    }
    targetConn, err := l.transport.Conn(context.Background(), meta, client)
    if err != nil {
        client.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // REP=5 拒绝
        return
    }

    // 回成功应答 + 进入隧道
    client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // REP=0
    client.SetDeadline(time.Time{})
    netutil.Relay(client, targetConn)
}
```

### 关键代码：出站组 Selector

```go
// internal/outboundgroup/selector.go —— "点一下节点"背后的全部逻辑

func (s *Selector) Set(name string) bool {
    s.mu.Lock()
    defer s.mu.Unlock()
    for _, p := range s.proxies {
        if p.Name() == name {
            s.current = name // 改一个字符串
            return true
        }
    }
    return false
}

func (s *Selector) Dial(ctx context.Context, m *constant.Metadata) (net.Conn, error) {
    p := s.Selected() // 下一次 Dial 就走新节点
    if p == nil {
        return nil, constant.ErrNoRoute
    }
    return p.Dial(ctx, m)
}
```

### 双层 SOCKS5 测试（最漂亮的时刻）

```
curl ──(SOCKS5客户端)──► mini-clash:7892 入站 ──► 规则NODE ──► socks5出站 ──► minisocks:1080 ──► example.com
```

同一个 mini-clash，既是 SOCKS5 服务器（入站），又是 SOCKS5 客户端（出站），中间是规则引擎在调度。

---

## 里程碑 4：加密协议与真实订阅

### 三个新出站协议

#### Trojan（最简加密代理）

```
TCP 拨号 → 真实 TLS 握手 → 发 hex(SHA224(密码)) + CRLF + SOCKS5式地址 + CRLF
```

**特点**：没有应答字节。服务器验证失败就伪装成 HTTPS 站点——这是它抗探测的设计。SNI 字段让流量看起来像在访问正常网站。

```go
// internal/outbound/trojan.go —— Dial 核心

func (t *Trojan) Dial(ctx context.Context, m *constant.Metadata) (net.Conn, error) {
    // 1. TCP 拨节点
    raw, _ := (&net.Dialer{}).DialContext(ctx, "tcp",
        net.JoinHostPort(t.server, strconv.Itoa(t.port)))

    // 2. 真实 TLS 握手（SNI 是伪装关键）
    tlsConn := tls.Client(raw, &tls.Config{
        ServerName:         t.sni,
        InsecureSkipVerify: t.skipVerify,
    })
    tlsConn.HandshakeContext(ctx)

    // 3. 认证头：hex(SHA224(password))，56 个 ASCII 字符
    hash := sha256.Sum224([]byte(t.password))
    key := hex.EncodeToString(hash[:])

    // 4. 协议格式：key + CRLF + CMD + 地址 + CRLF
    tlsConn.Write([]byte(key + "\r\n"))
    tlsConn.Write([]byte{0x01}) // CMD=CONNECT
    socks5.NewAddr(m.Host, uint16(m.PortInt())).WriteTo(tlsConn)
    tlsConn.Write([]byte("\r\n"))

    // 5. 无应答字节，直接进入隧道
    tlsConn.SetDeadline(time.Time{})
    return tlsConn, nil
}
```

#### Shadowsocks（第一个"加密隧道"协议）

与 SOCKS5/Trojan 的本质区别：返回的连接不是裸 TCP，而是**双向加密隧道**：

```
写方向：明文 → AEAD 分块加密 → 发出
读方向：密文 → AEAD 分块解密 → 交给上层
```

```go
// internal/outbound/shadowsocks.go —— 加密隧道包装

// Write 实现：明文 → 分块加密 → 写底层连接
func (c *ssConn) Write(p []byte) (int, error) {
    total := 0
    for len(p) > 0 {
        n := len(p)
        if n > maxChunkPayload {
            n = maxChunkPayload // 每块 ≤ 16383 字节
        }
        writeChunk(c.Conn, c.wc, c.wnonce, p[:n])
        p = p[n:]
        total += n
    }
    return total, nil
}

// Read 实现：密文分块 → 解密 → 交给上层
func (c *ssConn) Read(p []byte) (int, error) {
    // 读加密长度（2B + tag）
    var lbuf [18]byte
    io.ReadFull(c.Conn, lbuf[:])
    plainLen, _ := c.rc.Open(nil, c.rnonce, lbuf[:], nil)
    increment(c.rnonce) // nonce 按小端序 +1（协议规定）
    n := int(binary.BigEndian.Uint16(plainLen))

    // 读加密负载（n + tag）
    ebuf := make([]byte, n+tagLen)
    io.ReadFull(c.Conn, ebuf)
    plain, _ := c.rc.Open(nil, c.rnonce, ebuf, nil)
    increment(c.rnonce)

    c.rbuf = plain
    return c.Read(p)
}
```

密钥派生链：`password → EVP_BytesToKey(masterKey) → HKDF-SHA1(masterKey, salt, "ss-subkey")`，双向各自独立 salt。

#### Hysteria2（里程碑主角，实测打通）

基于 QUIC（UDP）的现代协议，完整链路：

```
UDP 拨号 → (可选 Salamander 混淆) → QUIC 握手 → HTTP/3 伪装认证(233) → TCP 流
```

```go
// internal/outbound/hysteria2.go —— Dial 全流程

func (h *Hysteria2) Dial(ctx context.Context, m *constant.Metadata) (net.Conn, error) {
    port := h.pickPort()              // 端口跳变：从 45000-55000 随机选
    addr, _ := h.resolveServer(port)  // DoH 防污染：拿真实 IP

    // 1. UDP socket + Salamander 混淆层
    udpConn, _ := net.ListenUDP("udp", nil)
    pconn := &salamanderConn{UDPConn: udpConn, key: []byte(h.obfsKey), remote: mustUDPAddr(addr)}

    // 2. QUIC 拨号（强制 v1）
    quicCfg := &quic.Config{
        KeepAlivePeriod: 15 * time.Second,
        Versions:        []quic.Version{quic.Version1},
    }
    conn, err := quic.Dial(ctx, pconn, mustUDPAddr(addr), tlsCfg, quicCfg)

    // 3. HTTP/3 伪装认证（POST /auth，服务器回 233）
    h.auth(ctx, conn, sni)

    // 4. 开 TCP 流，发 TCPRequest 帧
    stream, _ := conn.OpenStreamSync(ctx)
    reqFrame := buildTCPRequest(net.JoinHostPort(m.Host, m.DstPort))
    stream.Write(reqFrame)

    // 5. 读 TCPResponse：status + msgLen + msg + padLen + padding
    var statusByte [1]byte
    io.ReadFull(stream, statusByte[:])
    // ... 读掉 msg 和 padding

    return &hysteriaConn{Stream: stream, conn: conn, udp: udpConn}, nil
}
```

QUIC varint 编码（踩过坑的地方）：

```go
// QUIC varint（RFC 9000）：最高 2 位编码长度，不是 protobuf varint！
func appendQuicVarint(dst []byte, v uint64) []byte {
    switch {
    case v < 1<<6:
        return append(dst, byte(v))
    case v < 1<<14:
        return append(dst, byte(0x40|v>>8), byte(v))
    case v < 1<<30:
        return append(dst, byte(0x80|v>>24), byte(v>>16), byte(v>>8), byte(v))
    default:
        return append(dst, byte(0xC0|v>>56), byte(v>>48), byte(v>>40), byte(v>>32),
            byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
    }
}
```

Salamander 混淆层：

```go
// 每个 UDP 包：[8B salt] [payload XOR blake2b-256(key+salt) 循环]
func (s *salamanderConn) WriteTo(p []byte, addr net.Addr) (int, error) {
    salt := make([]byte, 8)
    rand.Read(salt)
    hash := blake2b.Sum256(append(append([]byte{}, s.key...), salt...))
    payload := make([]byte, 8+len(p))
    copy(payload[:8], salt)
    for i, b := range p {
        payload[8+i] = b ^ hash[i%32]
    }
    s.UDPConn.WriteTo(payload, s.remote)
    return len(p), nil
}
```

### DoH 防污染解析（关键转折）

```go
// internal/dns/doh.go —— 通过专属 DoH 拿真实 IP

func ResolveDOH(host, dohURL string) ([]netip.Addr, error) {
    // 构造 DNS 查询报文
    q := make([]byte, 12)
    binary.BigEndian.PutUint16(q[0:2], 0x1234)
    binary.BigEndian.PutUint16(q[2:4], 0x0100)
    binary.BigEndian.PutUint16(q[4:6], 1)
    for _, label := range strings.Split(host, ".") {
        q = append(q, byte(len(label)))
        q = append(q, label...)
    }
    q = append(q, 0, 0, 1, 0, 1) // A 记录

    // HTTP GET + base64url，强制 HTTP/2（RFC 8484 要求）
    client := &http.Client{
        Transport: &http.Transport{
            TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
            ForceAttemptHTTP2: true,
        },
    }
    resp, _ := client.Get(dohURL + "?dns=" + base64URL(q))
    // ... 解析 DNS 应答报文，提取 A 记录
}
```

排查过程：

```
现象: 新订阅节点全部超时，但 Clash Verge 能用
  ↓ 对比双方配置
Verge 有 nameserver-policy: +.节点域名 → 专属 DoH
  ↓ 用 dohquery 工具验证
系统 DNS 给 [国内 CDN 假 IP]; 专属 DoH 给 [真实 AWS IP]
  ↓ 根因
机场对节点域名做了 DNS 防污染（给探测者发假 IP）
  ↓ 修复
出站加 per-node DoH 解析
  ↓ 结果
200 OK，0.8 秒
```

### 最终实测

```
默认 HK-hy2-1:   HTTP 200, 0.82 秒   （AWS 香港）
切换 SG-hy2-1:   HTTP 200, 1.93 秒   （AWS 新加坡）
切换 JP-hy2-1:   HTTP 200, 0.78 秒   （AWS 日本）
```

日志证据（假 IP 反查 + DoH 真实 IP 拨号全链路）：

```
[tunnel] 节点组 | 127.0.0.1:59301 -> example.com:443
[http] CONNECT example.com:443 -> [节点真实IP]:49839
```

---

## 踩坑记录：四个真实 bug

### Bug 1：nil 指针崩溃（里程碑 2）

```
panic: runtime error: invalid memory address or nil pointer dereference
    mini-clash/internal/dns.(*Resolver).Resolve(...)
        resolver.go:80
```

**根因**：hub.go 创建了 resolver 但返回 Hub 时忘了装进去，`h.resolver` 是 nil。DNS 查询进来时 `nil.Resolve()` 崩溃。

```go
// 修复：返回时把 resolver 装进 Hub（漏掉的一行）
return &Hub{
    Router:   r,
    Listener: listener,
    resolver: resolver, // ← 关键：漏了这行就是 nil 崩溃
    cfg:      cfg,
}, nil
```

**教训**：panic 报告连崩在哪个字段都能看出来（`addr=0x10` 是结构体里 fakeIP 字段的偏移）。"编译过 ≠ 逻辑对"。

### Bug 2：ATYP 被读了两次（里程碑 3）

```
现象：minisocks 日志说 CONNECT ok，但 mini-clash 回 502
```

**根因**：应答头读了 4 字节 `[VER, REP, RSV, ATYP]`，把 ATYP 也吃了。然后 `socks5.ReadFrom` 开头又读 ATYP——把绑定 IP 的第一个字节 0x00 当成了 ATYP，报"unsupported ATYP"。握手成功被读成失败。

```go
// 错误：头读 4 字节，ATYP 被吃掉
var respHdr [4]byte
io.ReadFull(node, respHdr[:])
socks5.ReadFrom(node) // ← 这里读到的下一个字节是绑定 IP 的第一字节

// 正确：头只读 3 字节，把 ATYP 留给 ReadFrom 自己读
var respHdr [3]byte
io.ReadFull(node, respHdr[:])
socks5.ReadFrom(node) // ← ReadFrom 开头自己读 ATYP
```

**教训**：协议字段的"归属权"——**谁定义的接口谁负责消费自己的字段**。这类"成功被读成失败"的 bug 没有崩溃堆栈，只能靠对端日志定位。

### Bug 3：varint 编码错误（里程碑 4，最难查）

```
现象：curl 静默超时 40 秒，服务器不回一个字
```

**根因**：Hysteria2 的 TCPRequest 帧用 **QUIC varint**（RFC 9000：高 2 位编码长度），误用了 **protobuf varint**（0x40 位做续传标记）：

```
值 1025 (帧ID 0x401):
  protobuf: 81 08          ← 错的
  QUIC:     44 01          ← 对的
```

服务器用 QUIC varint 解码，读到垃圾，判定非法，**静默丢弃**。没有报错、没有日志、没有任何提示。

**教训**：二进制协议里，"编码不匹配"是最阴险的 bug——双方都认为自己是对的，只是字节含义不同。排查只能靠对照官方规范逐字节核对。

### Bug 4：DNS 污染（里程碑 4，最戏剧性）

```
现象：同一家机场，Clash Verge 能用，我们连不上
```

**根因**：机场对节点域名做了防污染——公共 DNS 给探测者发假 IP（国内 CDN），真实 IP 只有专属 DoH 能查到。

**教训**：排查"别人能用我不能用"时，先对比配置差异（Verge 的 nameserver-policy 暴露了答案），再用工具验证假设（dohquery 查到真实 IP）。假设-验证-修复，三步闭环。

---

## 概念延伸：系统代理、TUN 与加速器

### 系统代理 vs TUN 虚拟网卡

```
系统代理（HTTP/SOCKS）：
  应用 ──► 代理协议(HTTP/SOCKS) ──► Clash ──► 节点
   ↑ 应用必须"主动认识"代理，自己把请求包装成代理格式

虚拟网卡（TUN）：
  应用 ──► 系统网络栈 ──► 虚拟网卡 ──► Clash ──► 节点
   ↑ 应用完全无感知，它以为自己在正常上网
```

| | 系统代理 | TUN |
|---|---|---|
| 应用配合 | 必须认代理 | 完全无感知 |
| UDP 支持 | 差 | 完整 |
| 覆盖范围 | 部分应用 | 所有流量 |
| 域名分流 | 天生精确 | 需 fake-ip 反查 |
| 实现复杂度 | 简单 | 路由表 + 虚拟网卡 + IP 包解析 |

### 游戏加速器原理

**抓流量手法和 TUN 一样**（虚拟网卡拦包），但目的和核心网络完全不同：

```
Clash 代理   = 秘密隧道：加密后从别的地方出去（换身份）
游戏加速器   = 专用快车道：流量导上专线骨干网（换路径）
```

三层结构：

1. **抓流量**：TUN 虚拟网卡 / 进程级钩子 / WFP 驱动
2. **识别游戏流量**：进程名匹配（VALORANT.exe）+ 目标 IP 段匹配，其他流量放行
3. **走专线**：就近接入 → 买断的国际专线骨干网 → 游戏区节点 → 游戏服务器

**为什么机场的"游戏节点"常常没用**：机场节点是给"访问"设计的（要过墙），多一跳加密+中转，延迟反而更高。**为什么加速器不能翻墙**：出口节点只对游戏服务器开放，流量不加密。

### 三者能同时开吗？

- **系统代理 + 加速器**：✅ 兼容。各管各的，不抢路由
- **TUN + 加速器**：⚠️ 冲突。默认路由只有一条，两个 TUN 必有一方被架空，还可能 TUN 死循环（自己抓自己的流量）

---

## 最终成果与可扩展方向

### 完整能力清单

```
✅ HTTP 入站 / SOCKS5 入站
✅ fake-ip DNS 服务器
✅ 规则引擎 + 出站组 Selector（运行时切换）
✅ 六种出站协议：DIRECT / REJECT / SOCKS5 / SS / Trojan / Hysteria2
✅ DoH 防污染解析
✅ 真实机场订阅可用（hysteria2 节点实测连通）
✅ 浏览器日常翻墙（系统代理模式）
```

### 使用方式

```powershell
# 1. 前台启动
.\mini-clash.exe

# 2. 浏览器设代理：127.0.0.1:7891

# 3. 控制台切换节点（毫秒级生效）
set 节点组 HK-hy2-1
set 节点组 SG-hy2-1
set 节点组 DIRECT
```

### 可扩展方向

1. **VLESS 出站**：订阅里还有 45 个 vless 节点（REALITY+Vision，复杂度高）
2. **订阅自动拉取**：subscribe 包已写好，接进启动流程即可
3. **TUN 模式**：虚拟网卡接管系统流量（Wintun 驱动 + 路由表 + IP 包解析）
4. **URL-Test 组**：自动测速选最快节点
5. **更多入站**：TProxy、Redir（Linux 下）

### 学习方法总结

整个过程遵循一个模式：**协议样板我来写，架构代码你手写**。协议编解码（DNS 报文、SOCKS5 地址、QUIC varint）是查规范的事，不该背；而数据流设计（入站→路由→出站→转发）必须亲手写一遍才会懂。

最有价值的三个认知：

1. **接口即架构**：Metadata/Adapter/Transport 三个抽象划清了所有边界
2. **二进制协议靠"长度自描述"**：变长字段必须自带长度信息（ATYP、长度前缀、varint 都是这个道理）
3. **排查要闭环**：假设 → 验证（工具/日志/对端）→ 修复 → 回归测试

---

*全文完。项目代码位于 `MyClash/` 目录，所有里程碑均有对应 commit 和测试记录。*
