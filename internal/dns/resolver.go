package dns

import (
	"encoding/binary"
	"fmt"
	"mini-clash/internal/config"
	"net"
	"net/netip"
)

type Resolver struct {
	pool   *Pool
	hosts  *Hosts
	fakeIP bool // 是否启用 fake-ip （配置里 dns.enable=false 时走真实解析）
}

// Next 分配下一个假 IP。
// 实现思路：
//  1. 加锁
//  2. 拿 prefix.Addr()（网段第一个地址），把它转成 4 字节数组
//  3. 把 next 编号加到这个地址上（先转 uint32 再算回去）
//  4. next++
//  5. 解锁，返回算好的 netip.Addr

// Next 解释 "198.18.0.1" 只是这个数字的书写格式
// 分配 IP 就是数数，而数数就要先把"好看的字"变回"能算的数"
// 198.18.0.1 这个 IP，拆成 4 个字节（每段一个）
// 198.18.0.1  →  字节: [0xC6, 0x12, 0x00, 0x01]  →  拼成一个数: 0xC6120001
// 这个数 0xC6120001 就是 IP 的真身。你加 1：
// 0xC6120001 + 1 = 0xC6120002  →  拆回字节: [0xC6, 0x12, 0x00, 0x02]  →  198.18.0.2
// "分配下一个 IP" = "数字加 1"，就这么简单。
// 你的池子要发 IP，发 198.18.0.1、198.18.0.2、198.18.0.3……就是在数数：1、2、3……
func (p *Pool) Next() netip.Addr {
	p.mu.Lock()
	defer p.mu.Unlock()
	// 你的实现...
	base := p.prefix.Addr()
	ip := base.As4()
	// [4]byte 转 uint32（大端序，即网络字节序）
	n := binary.BigEndian.Uint32(ip[:])
	// 加编号
	n += p.next
	// uint32 转回 [4]byte
	var out [4]byte
	binary.BigEndian.PutUint32(out[:], n)
	// 转成 netip.Addr 并让编号自增
	addr := netip.AddrFrom4(out)
	p.next++
	return addr
}

// IsFake 判断一个 IP 是不是这个池网段里的（我们发出去的）假 IP。
// netip.Prefix.Contains 帮算好了子网数学，不用自己动手。
func (p *Pool) IsFake(ip netip.Addr) bool {
	return p.prefix.Contains(ip)
}

// NewResolver 按配置构造。
// 关键判断：enable=false 或没配 fake-ip-range → 退化成"真实解析"模式。
func NewResolver(cfg config.DnsConfig) (*Resolver, error) {
	if !cfg.Enable || cfg.FakeIPRange == "" {
		return &Resolver{fakeIP: false}, nil
	}
	pool, err := NewPool(cfg.FakeIPRange)
	if err != nil {
		return nil, err
	}
	return &Resolver{pool: pool, hosts: NewHosts(), fakeIP: true}, nil
}

// Resolve 要一个 IP。
//
// fake-ip 模式三步：
//  1. hosts.Lookup(host) 有 → 复用（保证同一域名永远同一个假 IP）
//  2. 没有 → pool.Next() 分配新假 IP
//  3. hosts.Add 记账
//
// 真实解析模式：net.LookupIP 查系统 DNS，取第一个 IPv4。
func (r *Resolver) Resolve(host string) (netip.Addr, error) {
	if !r.fakeIP {
		return realResolve(host)
	}
	if ip, ok := r.hosts.Lookup(host); ok {
		return ip, nil
	}
	ip := r.pool.Next()
	r.hosts.Add(ip, host)
	return ip, nil
}

// LookBack 已映射 → 返回已有假 IP；新域名 → 分配假 IP；非 fake-ip 模式 → 真实解析
func (r *Resolver) LookBack(ip netip.Addr) (string, bool) {
	if !r.fakeIP || !r.pool.IsFake(ip) {
		return "", false
	}
	return r.hosts.LookBack(ip)
}

// realResolve 真实解析（非 fake-ip 模式的兜底）。
func realResolve(host string) (netip.Addr, error) {
	ips, err := net.LookupIP(host)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return netip.AddrFrom4([4]byte(v4)), nil
		}
	}
	return netip.Addr{}, fmt.Errorf("no A record: %s", host)
}
