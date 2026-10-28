// Package outboundgroup 提供出站组适配器。
// 教学版只实现一个"Selector"：从若干候选出站里挑一个用。
// 真实 Clash 还有 url-test（自动测速）、fallback、load-balance 等，
// 但它们最终都是"挑出一个 adapter 然后转交拨号"。
package outboundgroup

import (
	"context"
	"net"
	"sync"

	"mini-clash/internal/adapter"
	"mini-clash/internal/constant"
)

// Selector 出站组：名字 + 候选出站列表 + 当前选中项。
type Selector struct {
	name    string
	proxies []adapter.Adapter // 候选出站
	mu      sync.RWMutex
	current string // 当前选中的出站名字
}

// NewSelector 创建出站组。默认选中第一个候选。
func NewSelector(name string, proxies []adapter.Adapter) *Selector {
	current := ""
	if len(proxies) > 0 {
		current = proxies[0].Name()
	}
	return &Selector{
		name:    name,
		proxies: proxies,
		current: current,
	}
}

func (s *Selector) Name() string { return s.name }

// Set 切换当前选中的出站（对应 Clash 界面上点一下节点）。
func (s *Selector) Set(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.proxies {
		if p.Name() == name {
			s.current = name
			return true
		}
	}
	return false
}

// Selected 返回当前选中的出站（查找失败时兜底第一个）。
func (s *Selector) Selected() adapter.Adapter {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.proxies {
		if p.Name() == s.current {
			return p
		}
	}
	if len(s.proxies) > 0 {
		return s.proxies[0]
	}
	return nil
}

// Dial 把拨号请求转交给当前选中的出站。
func (s *Selector) Dial(ctx context.Context, m *constant.Metadata) (net.Conn, error) {
	p := s.Selected()
	if p == nil {
		return nil, constant.ErrNoRoute
	}
	return p.Dial(ctx, m)
}
