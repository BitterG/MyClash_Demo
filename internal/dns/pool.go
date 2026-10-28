package dns

import (
	"net/netip"
	"sync"
)

// Pool 时刻 1：浏览器要解析域名（DNS 查询阶段）
// 浏览器 ──"example.com 的 IP 是啥？"──► mini-clash DNS服务器
//
//	│
//	└─► 调 Resolve("example.com")
//	    → 分配 198.18.0.1，记账
//	    → 回答浏览器 "198.18.0.1"
//
// 时刻 2：浏览器发起真实连接（流量阶段，可能几分钟后、完全另一条连接）
// 浏览器 ──"CONNECT 198.18.0.1:443"──► mini-clash HTTP代理
//
//	│
//	└─► 内核只看到 IP：198.18.0.1
//	    域名从报文里消失了！
//	    → 调 LookBack("198.18.0.1")
//	    → 反查回 "example.com"
//	    → 才能按域名走规则、用真域名拨号
type Pool struct {
	prefix netip.Prefix
	next   uint32
	mu     sync.Mutex
}

func NewPool(cidr string) (*Pool, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, err
	}
	return &Pool{prefix: prefix.Masked(), next: 1}, nil
}
