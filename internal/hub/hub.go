// Package hub 是"装配车间"：把静态配置组装成运行时对象树。
//
// 真实 mihomo 的 hub 包负责：解析配置 → 创建所有 adapter →
// 建立依赖关系（出站组引用出站）→ 构建 Router → 启动各入站监听。
// 它对应的就是"内核实例"。我们这里做同样的工作，只是规模小得多。
package hub

import (
	"fmt"
	"mini-clash/internal/dns"

	"mini-clash/internal/adapter"
	"mini-clash/internal/config"
	"mini-clash/internal/constant"
	"mini-clash/internal/inbound"
	"mini-clash/internal/log"
	"mini-clash/internal/outbound"
	"mini-clash/internal/outboundgroup"
	"mini-clash/internal/router"
	"mini-clash/internal/tunnel"
)

// Hub 是一个运行中的内核实例。
type Hub struct {
	Router    *router.Router
	Listener  *inbound.HttpListener
	dnsServer *dns.Server   // ← 加
	resolver  *dns.Resolver // ← 加（以后做 DNS 上游会用到）
	socksLn   *inbound.SocksListener
	cfg       *config.RawConfig
}

// New 从配置构建内核（adapter 树 + Router）。
func New(cfg *config.RawConfig) (*Hub, error) {
	// 1) 创建基础出站（直连/拒绝），同时登记到 adapter 列表
	var proxies []adapter.Adapter
	byName := map[string]adapter.Adapter{}

	for _, p := range cfg.Proxies {
		var a adapter.Adapter
		switch p.Type {
		case "direct", "":
			a = outbound.NewDirect(nil)
		case "reject":
			a = outbound.NewReject()
		case "socks5":
			a = outbound.NewSocks5(p.Name, p.Server, p.Port)
		case "ss":
			a = outbound.NewShadowsocks(p.Name, p.Server, p.Port, p.Cipher, p.Password)
		case "trojan":
			a = outbound.NewTrojan(p.Name, p.Server, p.Port, p.Password, p.Sni, true)
		case "hysteria2":
			a = outbound.NewHysteria2(p.Name, p.Server, p.Port, p.Ports, p.Doh, p.Password, p.Sni, p.Obfs, p.ObfsPassword)

		default:
			return nil, fmt.Errorf("unsupported proxy type: %s", p.Type)
		}
		// 出站组/自定义名字：让 Name() 返回配置里的名字
		if p.Name != "" && p.Type != "direct" && p.Type != "reject" {
			a = outbound.NewNamed(p.Name, a)
		}
		proxies = append(proxies, a)
		byName[a.Name()] = a
	}

	// 2) 解析规则
	rules, err := cfg.ParseRules()
	if err != nil {
		return nil, err
	}

	// 创建出站组
	for _, g := range cfg.ProxyGroups {
		var members []adapter.Adapter
		for _, name := range g.Proxies {
			if a, ok := byName[name]; ok {
				members = append(members, a)
			}
		}
		sel := outboundgroup.NewSelector(g.Name, members)
		proxies = append(proxies, sel)
		byName[sel.Name()] = sel
	}

	// 3) 构建 Router
	defaultProxy := cfg.DefaultProxy
	if defaultProxy == "" {
		defaultProxy = "DIRECT"
	}
	r := router.New(proxies, rules, defaultProxy)

	resolver, err := dns.NewResolver(cfg.Dns)
	if err != nil {
		return nil, err
	}
	// 4) 内核（tunnel）
	t := tunnel.New(r, resolver)

	// 5) 入站 HTTP 代理
	port := cfg.Port
	if port == 0 {
		port = 7890
	}
	h := inbound.NewHttp(t)
	listener := inbound.NewHttpListener(fmt.Sprintf("127.0.0.1:%d", port), h)

	// 6) 入站 SOCKS5 代理
	var socksListener *inbound.SocksListener
	if cfg.SocksPort > 0 {
		socksListener = inbound.NewSocksListener(
			fmt.Sprintf("127.0.0.1:%d", cfg.SocksPort), t) // t 就是内核 tunnel，实现 Transport
	}

	_ = byName
	_ = outboundgroup.NewSelector // 教学版占位：分组在里程碑 3 用
	_ = constant.ErrBlocked

	return &Hub{
		Router:   r,
		Listener: listener,
		socksLn:  socksListener,
		resolver: resolver, // ← 关键：把 resolver 装进 Hub，否则 Start 里拿到的是 nil
		cfg:      cfg,
	}, nil
}

// Start 启动入站监听。
func (h *Hub) Start() error {
	if h.cfg.Dns.Enable {
		listen := h.cfg.Dns.Listen
		if listen == "" {
			listen = "127.0.0.1:5353"
		}
		h.dnsServer = dns.NewServer(listen, h.resolver)
		go func() {
			if err := h.dnsServer.Serve(); err != nil {
				log.Warnln("[dns] server stopped:", err)
			}
		}()
	}
	if h.socksLn != nil {
		if err := h.socksLn.Start(); err != nil {
			return err
		}
	}
	return h.Listener.Start()
}

// Close 关闭内核。
func (h *Hub) Close() error {
	if h.dnsServer != nil {
		_ = h.dnsServer.Close()
	}
	if h.socksLn != nil {
		_ = h.socksLn.Close()
	}
	return h.Listener.Close()
}

// LogConfig 打印启动摘要（对应 Clash 启动时的那串日志）。
func (h *Hub) LogConfig() {
	log.Infoln("[hub] mini-clash started")
	log.Infoln("[hub] listening port:", h.cfg.Port)
	log.Infoln("[hub] rules loaded:", h.Router.RuleCount())
	log.Infoln("[hub] default proxy:", h.cfg.DefaultProxy)
}
