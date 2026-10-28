package constant

import (
	"net"
	"strconv"
)

// Metadata 是"流量元数据"：描述"这一条连接/请求想要做什么"。
//
// 它在整个代理链路上被到处传递，是 Clash 架构的血液：
//   入站解析器填充它 → 规则引擎读它 → 出站拨号器消费它
//
// 真实 Clash 的 C.Metadata 字段比这里多得多（源地址、用户、DNS 模式、
// 连接数统计……），教学版只保留跑通全链路最少要用的几个。
type Metadata struct {
	NetWork string `json:"network"` // 四层协议："tcp" / "udp"
	Type    string `json:"type"`    // 出站协议类型："HTTP" / "SOCKS" ...
	Host    string `json:"host"`    // 目标主机名（可能是 IP）
	DstIP   net.IP `json:"dstIP"`   // 目标 IP（规则用，教学版暂未填充）
	DstPort string `json:"dstPort"` // 目标端口（字符串，Clash 惯例）
	SrcIP   net.IP `json:"srcIP"`   // 客户端 IP（教学版暂未填充）
	SrcPort string `json:"srcPort"` // 客户端端口（教学版暂未填充）

	// 下面两个是 Clash 风格 metadata 的灵魂：
	// 规则命中时不是"修改" Metadata，而是"换一条新的 Metadata"继续往后走，
	// 保证原始信息在任何阶段都还能拿得到（真实 Clash 叫 Pure）。
	RawSrcAddr *net.TCPAddr `json:"-"`
	RawDstAddr *net.TCPAddr `json:"-"`
}

// Pure 返回一份"去敏后"的副本。
// Clash 约定：Metadata 一旦被规则改写，改写前的信息保存在 Pure 字段，
// 这样 trace 日志能看到完整链路。我们简化：直接返回浅拷贝。
func (m *Metadata) Pure() *Metadata {
	if m == nil {
		return nil
	}
	cpy := *m
	return &cpy
}

// RemoteAddress 返回入站侧看到的客户端地址。
func (m *Metadata) RemoteAddress() string {
	if m == nil {
		return ""
	}
	if m.RawSrcAddr != nil {
		return m.RawSrcAddr.String()
	}
	return net.JoinHostPort(StringIP(m.SrcIP), m.SrcPort)
}

// DestinationAddress 返回目标地址，优先真实原始地址；
// 没有原始地址时用元数据里的 Host:Port 拼。
func (m *Metadata) DestinationAddress() string {
	if m == nil {
		return ""
	}
	if m.RawDstAddr != nil {
		return m.RawDstAddr.String()
	}
	return net.JoinHostPort(m.Host, m.DstPort)
}

// StringIP 把 net.IP 转成字符串；IPv6 补方括号（JoinHostPort 需要）。
func StringIP(ip net.IP) string {
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return "[" + ip.String() + "]"
}

// PortInt 把字符串端口转 int（出站拨号用）。
func (m *Metadata) PortInt() int {
	p, _ := strconv.Atoi(m.DstPort)
	return p
}
