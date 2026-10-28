# mini-clash

一个从零手写的 Clash 内核教学实现（Go）。跟着 Clash Verge / mihomo 的真实架构分层，用最少的代码跑通完整代理链路。

## 架构

```
main.go
└─ hub  (装配车间：配置 → 运行时对象树)
   ├─ config      YAML 加载 + 规则行解析
   ├─ router      规则引擎（DOMAIN-SUFFIX / IP-CIDR / MATCH ...）
   ├─ tunnel      内核调度：入站 → 选路 → 出站拨号 → 回连
   ├─ inbound     HTTP 代理入站（CONNECT 隧道 + 普通 HTTP 转发）
   ├─ outbound    出站实现（DIRECT / REJECT）
   └─ outboundgroup 出站组（Selector，里程碑 3 启用）
```

## 运行

```bash
go build -o mini-clash.exe .
.\mini-clash.exe            # 默认读 config.yaml
.\mini-clash.exe my.yaml    # 指定配置
```

测试（另开一个终端）：

```bash
curl -x http://127.0.0.1:7891 https://www.baidu.com -I
curl -x http://127.0.0.1:7891 http://example.com -I
# fake-ip DNS 验收（端口在 config.yaml 的 dns.listen，默认 15353）
go run ./cmd/minidig 127.0.0.1:15353 example.com
```

里程碑 3 本地节点测试：

```bash
go run ./cmd/minisocks 127.0.0.1:1080   # 先起一个本地 SOCKS5 节点
curl -x http://127.0.0.1:7891 https://example.com -I   # 命中规则走 NODE
```

## 里程碑

- [x] 里程碑 0：工程骨架（constant/metadata/outbound 接口）
- [x] 里程碑 1：HTTP 代理全链路（CONNECT + 规则 + DIRECT + 转发）
- [x] 里程碑 2：DNS + fake-ip（假IP分配/反查/分流，UDP DNS 服务器）
- [ ] 里程碑 3：SOCKS5 入站 + SOCKS5 出站 + 出站组（节点切换）
- [ ] 里程碑 4：进阶（TUN、分流优化、日志）

对照真实源码：`clash-verge-rev` 是壳（Tauri），内核在
[tauri-plugin-mihomo](https://github.com/clash-verge-rev/tauri-plugin-mihomo)
引用的 verge-mihomo 侧载二进制里。我们手写的每一层都能在 mihomo 源码里找到对应物。
