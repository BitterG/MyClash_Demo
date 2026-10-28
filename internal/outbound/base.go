package outbound

import (
	"context"
	"net"

	"mini-clash/internal/adapter"
	"mini-clash/internal/constant"
)

// DialContext 是出站拨号器的统一签名：
// "给我目标地址 + 元数据，我还你一条已经接通的连接"。
//
// 任何出站协议（DIRECT / SOCKS5 / VMess / Trojan ...）最终都要实现
// 这同一个签名——这就是 Clash 的出站插件体系。
type DialContext func(ctx context.Context, network string, address string) (net.Conn, error)

// DialerFunc 把函数适配成 adapter.Adapter 的便捷构造（Clash 同款习惯）。
type DialerFunc func(ctx context.Context, m *constant.Metadata) (net.Conn, error)

func (f DialerFunc) Name() string { return "FUNC" }

func (f DialerFunc) Dial(ctx context.Context, m *constant.Metadata) (net.Conn, error) {
	return f(ctx, m)
}

var _ adapter.Adapter = DialerFunc(nil)
