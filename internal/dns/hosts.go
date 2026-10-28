package dns

import (
	"net/netip"
	"sync"
)

type Hosts struct {
	mu     sync.Mutex
	byHost map[string]netip.Addr
	byIP   map[netip.Addr]string
}

func NewHosts() *Hosts {
	return &Hosts{
		byHost: make(map[string]netip.Addr),
		byIP:   make(map[netip.Addr]string),
	}
}

func (h *Hosts) Add(ip netip.Addr, host string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.byHost[host] = ip
	h.byIP[ip] = host
}

func (h *Hosts) Lookup(host string) (netip.Addr, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	ip, ok := h.byHost[host]
	return ip, ok
}

func (h *Hosts) LookBack(ip netip.Addr) (string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	host, ok := h.byIP[ip]
	return host, ok
}
