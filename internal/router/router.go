// Package router 实现规则引擎：拿 Metadata 匹配规则，决定出站。
//
// 这是 Clash 的心脏。真实 mihomo 的 router.go 有三千多行
// （规则树、geosite/geoip、DNS 联动……），但核心模型和我们这个完全一致：
//
//	规则 = 类型 + 匹配参数 + 目标出站
//	匹配成功后把 Metadata 里的 ProxyName 改成目标出站名
//	最后取名为 ProxyName 的 adapter 拨号
package router

import (
	"context"
	"net"
	"strings"

	"mini-clash/internal/adapter"
	"mini-clash/internal/constant"
)

// Rule 一条规则。
type Rule struct {
	Type     string // 规则类型：DOMAIN-SUFFIX / DOMAIN-KEYWORD / IP-CIDR / MATCH
	Payload  string // 匹配参数
	Target   string // 命中的目标出站名
	comment  string // 展示用
}

// Router 规则引擎。
type Router struct {
	adapterByName map[string]adapter.Adapter
	rules         []Rule
	defaultProxy  string // 没有任何规则命中时的兜底出站
}

// New 构造 Router。
// proxies：所有出站（含 DIRECT、REJECT、分组等）。
func New(proxies []adapter.Adapter, rules []Rule, defaultProxy string) *Router {
	r := &Router{
		adapterByName: make(map[string]adapter.Adapter),
		rules:         rules,
		defaultProxy:  defaultProxy,
	}
	for _, p := range proxies {
		r.adapterByName[p.Name()] = p
	}
	return r
}

// Match 按顺序匹配规则，返回命中的目标出站名。
//
// 规则顺序就是用户配置文件里的顺序：
// 第一条命中即返回（这就是"规则优先级"的全部含义）。
func (r *Router) Match(m *constant.Metadata) string {
	for _, rule := range r.rules {
		if matchRule(rule, m) {
			return rule.Target
		}
	}
	return r.defaultProxy
}

// matchRule 单条规则匹配。
func matchRule(rule Rule, m *constant.Metadata) bool {
	host := strings.ToLower(m.Host)
	payload := strings.ToLower(rule.Payload)

	switch rule.Type {
	case "MATCH":
		// 兜底规则，永远命中
		return true

	case "DOMAIN-SUFFIX":
		// 域名后缀匹配：example.com 命中 "com" / "example.com" / "ple.com"
		return host == payload || strings.HasSuffix(host, "."+payload)

	case "DOMAIN-KEYWORD":
		// 域名包含关键字
		return strings.Contains(host, payload)

	case "DOMAIN":
		// 完整域名精确匹配
		return host == payload

	case "IP-CIDR":
		// CIDR 匹配：需要目标 IP。
		// 教学版：如果 Host 本身就是 IP 就直接匹配；
		// 域名暂时跳过（DNS 里程碑会先解析再重试）。
		ip := net.ParseIP(m.Host)
		if ip == nil {
			return false
		}
		_, ipNet, err := net.ParseCIDR(rule.Payload)
		if err != nil {
			return false
		}
		return ipNet.Contains(ip)

	case "GEOSITE":
		// 教学版：不做 geosite 数据库，直接不命中（保留类型占位）
		return false

	case "GEOIP":
		return false
	}
	return false
}

// Resolve 把命中的出站名解析成 adapter。
// 找不到对应 adapter 时兜底 defaultProxy（再不行返回 nil）。
func (r *Router) Resolve(name string) adapter.Adapter {
	if a, ok := r.adapterByName[name]; ok {
		return a
	}
	if a, ok := r.adapterByName[r.defaultProxy]; ok {
		return a
	}
	return nil
}

// Adapter 直接查 adapter（供外部 Set/查询用）。
func (r *Router) Adapter(name string) adapter.Adapter {
	return r.adapterByName[name]
}

// RuleCount 规则条数（调试用）。
func (r *Router) RuleCount() int { return len(r.rules) }

// DialContext 占位：保留真实 Clash 的调用习惯，教学版暂不用。
func (r *Router) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return nil, constant.ErrUnsupported
}
