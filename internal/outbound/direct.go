// Package outbound 的具体实现之一：DIRECT（直连）。
//
// 这是最简单的出站协议：不包装任何东西，直接拨目标地址。
// 但它也示范了 Clash 出站实现的标准形态：
//   type Direct struct { dialer DialContext }
//   func (d *Direct) Dial(...) -> d.dialer(...)
//
// 所有其它协议（SOCKS5/VMess/Trojan...）都是同一个壳，
// 只是把 d.dialer 换成"先和代理服务器握手/加密，再把目标地址交给它"。
package outbound

import (
	"context"
	"errors"
	"net"

	"mini-clash/internal/constant"
)

// Direct 直连出站。
type Direct struct {
	dialer DialContext
}

// NewDirect 创建直连出站。
// base 是系统默认拨号器（可被自定义 DNS 拨号器替换，教学版忽略）。
func NewDirect(base DialContext) *Direct {
	if base == nil {
		base = func(ctx context.Context, network, address string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, address)
		}
	}
	return &Direct{dialer: base}
}

func (d *Direct) Name() string { return "DIRECT" }

// Dial 直连拨号：目标地址从 Metadata 里来。
// 注意：直接用 net.JoinHostPort(host, port) 会触发系统 DNS 解析——
// 这就是"直连模式域名由本地解析"的原因，后面 DNS 里程碑会替换这一步。
func (d *Direct) Dial(ctx context.Context, m *constant.Metadata) (net.Conn, error) {
	if m == nil {
		return nil, errors.New("nil metadata")
	}
	return d.dialer(ctx, "tcp", net.JoinHostPort(m.Host, m.DstPort))
}
