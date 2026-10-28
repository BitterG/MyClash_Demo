// Package adapter 是规则匹配与流量分发的公共抽象层。
//
// 真实 Clash 中，adapter 包被 inbound / outbound 两层共享：
//   - outbound 包实现 adapter.Adapter（DIRECT、SOCKS5 节点……）
//   - outboundgroup 包实现 adapter.Adapter（Selector 等分组）
//   - inbound 包只依赖 Transport（把解析好的连接交给内核）
//
// 我们保留同样的分包结构，方便你之后直接对照 mihomo 源码阅读。
package adapter

import (
	"context"
	"net"

	"mini-clash/internal/constant"
)

// Adapter 是一个出站适配器（或出站组）。
// 核心只有一件事：给出站名字，能按 Metadata 拨一条连接出来。
// 所有出站协议最终都归结为这一个接口——这是 Clash 扩展性的根源。
type Adapter interface {
	Name() string
	Dial(ctx context.Context, m *constant.Metadata) (net.Conn, error)
}

// Transport 是内核对入站暴露的接口。
//
// 入站处理器（HTTP/SOCKS 监听器）解析出 Metadata 后，
// 把客户端连接和元数据一起交给内核；内核负责选路 + 出站拨号，
// 返回一条"已经接通的目标连接"。
// 之后由入站侧负责协议收尾（如回 200 Connection Established）和双向转发。
type Transport interface {
	Conn(ctx context.Context, m *constant.Metadata, conn net.Conn) (net.Conn, error)
}
