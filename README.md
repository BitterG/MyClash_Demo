# mini-clash

一个从零手写的 Clash 内核教学实现（Go）。跟随 Clash Verge / mihomo 的真实架构分层，
从"Clash 是什么"开始，逐步实现完整的代理链路，最终支持真实机场订阅（hysteria2 节点实测连通）。

完整学习过程见 [LEARNING_SUMMARY.md](LEARNING_SUMMARY.md)。

## 功能

```
✅ HTTP 入站（CONNECT 隧道 + 明文转发）
✅ SOCKS5 入站（完整三阶段握手）
✅ fake-ip DNS 服务器（UDP，假 IP 分配/反查/分流）
✅ 规则引擎（DOMAIN-SUFFIX / DOMAIN-KEYWORD / IP-CIDR / MATCH）
✅ 出站组 Selector（运行时切换节点，毫秒级生效）
✅ 出站协议：DIRECT / REJECT / SOCKS5 / Shadowsocks / Trojan / Hysteria2
✅ DoH 防污染解析（per-node 专属 DNS）
✅ Hysteria2 完整支持：端口跳变、Salamander 混淆、HTTP/3 伪装认证
```

## 架构

```
main.go
└─ hub  (装配车间：配置 → 运行时对象树)
   ├─ config         YAML 加载 + 规则行解析
   ├─ router         规则引擎（逐条匹配，首条命中即返回）
   ├─ tunnel         内核调度：入站 → 反查 → 选路 → 出站拨号
   ├─ inbound        HTTP 代理 / SOCKS5 代理（只负责"听懂客户端"）
   ├─ outbound       DIRECT / REJECT / SOCKS5 / SS / Trojan / Hysteria2
   ├─ outboundgroup  Selector（出站组，节点切换）
   ├─ dns            fake-ip 池 / UDP 服务器 / DoH 客户端
   ├─ socks5         SOCKS5 地址编解码（ATYP 三种编码）
   └─ netutil        双向转发（relay）
cmd/
   ├─ minidig        迷你 dig：测试 DNS 服务器
   ├─ minisocks      迷你 SOCKS5 服务器：本地测试节点
   └─ dohquery       DoH 查询工具：诊断 DNS 防污染
```

**核心抽象**（扩展性的根源）：

- `Metadata`：一条连接的"目的地描述"，全链路传递
- `Adapter`：`Dial(ctx, m)` —— 加协议 = 加一个实现，其余零改动
- `Transport`：`Conn(ctx, m, conn)` —— 入站解析完交给内核，拨号是内核的事

## 快速开始

```bash
# 1. 准备配置（复制脱敏模板，填入你的节点信息）
cp config.yaml.example config.yaml

# 2. 编译运行
go build -o mini-clash.exe .
.\mini-clash.exe            # 默认读 config.yaml

# 3. 浏览器设置代理：HTTP 127.0.0.1:7891
# 4. 控制台切换节点（毫秒级生效）：
set 节点组 节点名
set 节点组 DIRECT
```

## 配置示例

```yaml
port: 7891              # HTTP 代理端口
socks-port: 7892        # SOCKS5 代理端口

dns:
  enable: true
  listen: 127.0.0.1:15353
  fake-ip-range: 198.18.0.1/16

proxies:
  - name: DIRECT
    type: direct
  - name: HY2
    type: hysteria2
    server: your-node.example.com
    port: 443
    ports: 45000-55000              # 端口跳变范围（可选）
    doh: https://your-doh/xxx       # 专属 DoH 防污染（可选）
    password: YOUR_PASSWORD
    sni: your-sni.example.com

proxy-groups:
  - name: 节点组
    type: select
    proxies: [HY2, DIRECT]

rules:
  - MATCH,节点组
```

完整脱敏模板见 [config.yaml.example](config.yaml.example)。

## 测试

```bash
# HTTP 代理（CONNECT 隧道 + 明文转发）
curl -x http://127.0.0.1:7891 https://www.baidu.com -I
curl -x http://127.0.0.1:7891 http://example.com -I

# SOCKS5 入站
curl --socks5-hostname 127.0.0.1:7892 https://example.com -I

# fake-ip DNS
go run ./cmd/minidig 127.0.0.1:15353 example.com    # 198.18.0.1
go run ./cmd/minidig 127.0.0.1:15353 example.com    # 198.18.0.1（复用映射）

# 本地 SOCKS5 节点联调
go run ./cmd/minisocks 127.0.0.1:1080

# DoH 诊断（查节点真实 IP，验证防污染）
go run ./cmd/dohquery "https://your-doh/dns-query/xxx" your-node.example.com
```

## 里程碑

- [x] **里程碑 0**：工程骨架（constant/metadata/adapter 三契约）
- [x] **里程碑 1**：HTTP 代理全链路（CONNECT + 规则引擎 + DIRECT + 转发）
- [x] **里程碑 2**：DNS + fake-ip（假 IP 分配/反查/分流，UDP DNS 服务器）
- [x] **里程碑 3**：SOCKS5 入站 + 出站 + 出站组（节点切换）
- [x] **里程碑 4**：加密协议（SS/Trojan/Hysteria2）+ DoH 防污染 + 真实订阅

## 与真实 Clash 的对照

本项目每一层都能在 mihomo 源码里找到对应物：

| 本项目 | mihomo |
|---|---|
| `internal/constant/metadata.go` | `C.Metadata` |
| `internal/adapter` | `adapter.Adapter` / `adapter.Transport` |
| `internal/router` | `router.go` 的规则树 |
| `internal/tunnel` | `tunnel.go` 的 pipeline |
| `internal/outbound/hysteria2.go` | sing-quic hysteria2 客户端 |
| `internal/dns/doh.go` | `nameserver-policy` 的 DoH 解析 |

> `clash-verge-rev` 是 Tauri 壳，内核在它侧载的 verge-mihomo 二进制里。

## 踩坑记录

学习过程中踩了四个真实 bug（详见 LEARNING_SUMMARY.md）：

1. **nil 指针崩溃**：hub 忘了装 resolver，DNS 查询进来就 panic
2. **ATYP 读两次**：协议字段归属权错误，握手成功被读成失败
3. **varint 编码错**：QUIC varint 误用 protobuf varint，服务器静默丢弃
4. **DNS 污染**：机场节点域名公共 DNS 给假 IP，需专属 DoH 拿真 IP
