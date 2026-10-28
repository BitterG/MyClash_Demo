// Package config 负责加载和解析 YAML 配置。
//
// 教学版只支持最小字段集：
//
//	port: 7891            # HTTP 代理监听端口
//	rules:                # 按顺序匹配
//	  - DOMAIN-SUFFIX,example.com,DIRECT
//	  - MATCH,PROXY
//	proxies:              # 出站列表（教学版只支持直连/拒绝占位）
//	  - name: DIRECT
//	    type: direct
//
// 真实 Clash 的 config 解析远比这复杂：RawConfig（YAML 原文）→
// Config（语义化后的完整配置）→ 运行时对象（adapter 树）。
// 我们保持同样的"三层"思路：RawConfig 只负责把 YAML 读进来。
package config

import (
	"os"

	"gopkg.in/yaml.v3"

	"mini-clash/internal/router"
)

// RawConfig 直接对应 YAML 结构。
type RawConfig struct {
	Port         int           `yaml:"port"`
	SocksPort    int           `yaml:"socks-port"` // 里程碑 3：SOCKS5 入站监听端口
	DefaultProxy string        `yaml:"default-proxy"`
	Dns          DnsConfig     `yaml:"dns"`
	Proxies      []Proxy       `yaml:"proxies"`
	Rules        []string      `yaml:"rules"`
	ProxyGroups  []ProxyGroup  `yaml:"proxy-groups"` // 里程碑 3：出站组
}

// DnsConfig DNS 配置段（里程碑 2 新增）。
//   - Enable：是否启动 fake-ip DNS 服务器
//   - Listen：DNS 服务器监听地址（教学版默认 127.0.0.1:5353）
//   - FakeIPRange：假 IP 池网段（默认 198.18.0.1/16）
type DnsConfig struct {
	Enable      bool   `yaml:"enable"`
	Listen      string `yaml:"listen"`
	FakeIPRange string `yaml:"fake-ip-range"`
}

// Proxy 出站配置。里程碑 3 扩展：支持 socks5 节点。
//   - type: direct / reject / socks5 / ss / trojan
//   - socks5 节点需要 server / port（username/password 可选，教学版忽略认证）
type Proxy struct {
	Name         string `yaml:"name"`
	Type         string `yaml:"type"`
	Server       string `yaml:"server"`   // 节点地址
	Port         int    `yaml:"port"`     // 节点端口
	Ports        string `yaml:"ports"`    // hysteria2 端口跳变范围，如 "43334-45000"
	Doh          string `yaml:"doh"`      // 专属 DoH URL（节点域名防污染时用）
	Username     string `yaml:"username"` // 教学版保留字段，暂不实现认证
	Password     string `yaml:"password"` // ss / trojan / hysteria2 用
	Cipher       string `yaml:"cipher"`   // ss 用，如 aes-256-gcm
	Sni          string `yaml:"sni"`      // trojan / hysteria2 用
	Obfs         string `yaml:"obfs"`     // hysteria2 用：salamander
	ObfsPassword string `yaml:"obfs-password"` // hysteria2 salamander 混淆密钥
}

// ProxyGroup 出站组配置
type ProxyGroup struct {
	Name    string   `yaml:"name"`    // 组名，如 "PROXY-GROUP"
	Type    string   `yaml:"type"`    // 教学版只支持 select
	Proxies []string `yaml:"proxies"` // 候选出站名列表，如 [DIRECT, NODE]
}

// Load 从文件加载配置。
func Load(path string) (*RawConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg RawConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// ParseRules 把 "TYPE,payload,target" 格式的规则行解析成 router.Rule。
//
// 真实 Clash 的规则行有几十种类型（GEOSITE、PROCESS-NAME、
// AND/OR/NOT 组合……），我们只支持四种 + MATCH，但解析框架一致。
func (c *RawConfig) ParseRules() ([]router.Rule, error) {
	var rules []router.Rule
	for _, line := range c.Rules {
		r, err := parseRuleLine(line)
		if err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, nil
}

// parseRuleLine 解析单条规则行。
// 支持三种形态：
//   - "TYPE,payload,target"  如 DOMAIN-SUFFIX,example.com,DIRECT
//   - "TYPE,target"          如 MATCH,DIRECT（无 payload 的类型）
//   - 注释行（# 开头）直接跳过
func parseRuleLine(line string) (router.Rule, error) {
	if line == "" || line[0] == '#' {
		return router.Rule{}, nil
	}
	parts := splitTrim(line, ',')
	switch {
	case len(parts) == 3:
		return router.Rule{
			Type:    parts[0],
			Payload: parts[1],
			Target:  parts[2],
		}, nil
	case len(parts) == 2:
		// 无 payload 类型（MATCH）
		return router.Rule{
			Type:   parts[0],
			Target: parts[1],
		}, nil
	}
	return router.Rule{}, errBadRule(line)
}

// splitTrim 按分隔符切分并去除首尾空白。
func splitTrim(s string, sep byte) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			parts = append(parts, trimSpace(s[start:i]))
			start = i + 1
		}
	}
	parts = append(parts, trimSpace(s[start:]))
	return parts
}

func trimSpace(s string) string {
	i, j := 0, len(s)
	for i < j && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	for j > i && (s[j-1] == ' ' || s[j-1] == '\t') {
		j--
	}
	return s[i:j]
}

type ruleError string

func (e ruleError) Error() string { return "bad rule line: " + string(e) }

func errBadRule(line string) error { return ruleError(line) }
