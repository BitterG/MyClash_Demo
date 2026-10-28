// Package tunnel 是内核的"总调度室"：入站解析完的请求都到这里。
//
// 职责（对应真实 mihomo 的 tunnel.go 核心路径）：
//  1. 收下入站解析好的 Metadata + 客户端连接
//  2. 交给 router 匹配规则，得到目标出站名
//  3. 解析出站名 → adapter → Dial 拨通目标
//  4. 把拨通的连接交回给入站侧（入站负责回 200 和双向转发）
//
// 真实 mihomo 在这条路上还串了 sniff（协议嗅探）、DNS 解析、
// 连接池、认证等十几道工序，但主链就是这四步。
package tunnel

import (
	"context"
	"errors"
	"mini-clash/internal/dns"
	"net"
	"net/netip"

	"mini-clash/internal/adapter"
	"mini-clash/internal/constant"
	"mini-clash/internal/log"
	"mini-clash/internal/router"
)

// Tunnel 实现 adapter.Transport：入站 → 内核 → 出站的总入口。
type Tunnel struct {
	router   *router.Router
	resolver *dns.Resolver
}

func New(r *router.Router, resolver *dns.Resolver) *Tunnel {
	return &Tunnel{router: r, resolver: resolver}
}

// Conn 处理一条已解析的连接。
//
// conn 是客户端连接（入站劫持出来的原始 TCP），
// 返回的是已经拨通的目标连接。
// 入站侧拿到返回的 target 后自己回协议头（200）并双向转发。
func (t *Tunnel) Conn(ctx context.Context, m *constant.Metadata, conn net.Conn) (net.Conn, error) {
	if m == nil {
		return nil, errors.New("nil metadata")
	}

	// 新增：fake-ip 反查。
	// 如果 m.Host 是个 IP（不是域名），且是我们的假 IP → 反查回真域名。
	// 注意 Clash 的铁律：不修改原 m，用 Pure() 副本改。
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

// ensure it satisfies the interface
var _ adapter.Transport = (*Tunnel)(nil)
