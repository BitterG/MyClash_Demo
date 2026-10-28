// Package subscribe 解析订阅内容：base64 URI 列表 或 Clash YAML。
//
// 真实订阅（机场）返回两种格式之一：
//   1. base64 编码的节点 URI 列表（每行一个，如 trojan://pass@host:port?sni=...）
//   2. 直接是 Clash 配置 YAML（含 proxies: 列表）
//
// 我们只提取 trojan 和 socks5 节点（demo 支持这两种出站）。
// 其他类型（vmess/ss/hysteria2 等）跳过——它们需要各自的协议实现。
package subscribe

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Node 一个解析出来的节点。
type Node struct {
	Type     string // trojan / socks5
	Name     string
	Server   string
	Port     int
	Password string // trojan 用
	Sni      string // trojan 用，可能为空
	Username string // socks5 用
}

// Parse 解析订阅原始文本，返回支持的节点列表。
// 自动识别 base64 URI 列表和 YAML 两种格式。
func Parse(raw string) ([]Node, error) {
	raw = strings.TrimSpace(raw)

	// 格式 1：Clash YAML（含 proxies: 字段）
	if strings.Contains(raw, "proxies:") {
		return parseYAML(raw)
	}

	// 格式 2：base64 URI 列表
	return parseBase64URI(raw)
}

// parseBase64URI 解析 base64 编码的节点 URI 列表。
func parseBase64URI(raw string) ([]Node, error) {
	// 订阅可能是纯 base64，也可能带换行
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil {
		// 可能是未编码的明文 URI 列表，直接按行处理
		decoded = []byte(raw)
	}

	var nodes []Node
	for _, line := range strings.Split(string(decoded), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if n, ok := parseURI(line); ok {
			nodes = append(nodes, n)
		}
	}
	return nodes, nil
}

// parseURI 解析单个节点 URI。
// 例：trojan://password@example.com:443?sni=example.com#MyNode
func parseURI(uri string) (Node, bool) {
	u, err := url.Parse(uri)
	if err != nil {
		return Node{}, false
	}

	var n Node
	switch u.Scheme {
	case "trojan":
		n.Type = "trojan"
		n.Password = u.User.Username()
		if u.User != nil {
			if pw, ok := u.User.Password(); ok {
				n.Password = pw
			}
		}
		n.Sni = u.Query().Get("sni")
	case "socks5", "socks":
		n.Type = "socks5"
		n.Username = u.User.Username()
		if u.User != nil {
			if pw, ok := u.User.Password(); ok {
				n.Username = n.Username + ":" + pw // 教学版简单拼接
			}
		}
	default:
		return Node{}, false // 不支持的协议
	}

	n.Server = u.Hostname()
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return Node{}, false
	}
	n.Port = port
	n.Name = u.Fragment
	if n.Name == "" {
		n.Name = fmt.Sprintf("%s-%s:%d", n.Type, n.Server, n.Port)
	}
	return n, true
}

// parseYAML 解析 Clash YAML 格式的订阅。
func parseYAML(raw string) ([]Node, error) {
	var cfg struct {
		Proxies []struct {
			Name     string `yaml:"name"`
			Type     string `yaml:"type"`
			Server   string `yaml:"server"`
			Port     int    `yaml:"port"`
			Password string `yaml:"password"`
			Sni      string `yaml:"sni"`
			Username string `yaml:"username"`
			SkipCertVerify bool `yaml:"skip-cert-verify"`
		} `yaml:"proxies"`
	}
	if err := yaml.Unmarshal([]byte(raw), &cfg); err != nil {
		return nil, err
	}

	var nodes []Node
	for _, p := range cfg.Proxies {
		switch p.Type {
		case "trojan":
			nodes = append(nodes, Node{
				Type: "trojan", Name: p.Name, Server: p.Server, Port: p.Port,
				Password: p.Password, Sni: p.Sni,
			})
		case "socks5":
			nodes = append(nodes, Node{
				Type: "socks5", Name: p.Name, Server: p.Server, Port: p.Port,
				Username: p.Username,
			})
		}
	}
	return nodes, nil
}
