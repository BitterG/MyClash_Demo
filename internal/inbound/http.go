// Package inbound 实现入站协议：HTTP 代理。
//
// 一个入站处理器要做的事只有一件：
//   解析客户端请求 → 填充 Metadata → 通过 Transport 交给内核。
// 它不关心规则、不关心出站——只负责"听懂客户端"，以及协议收尾
// （CONNECT 成功回 200、失败回 502/403）。
//
// HTTP 代理两种工作模式：
//   - CONNECT 隧道（https://... 走这里）：
//     客户端发 "CONNECT host:port HTTP/1.1"，代理拨通目标后回
//     "200 Connection Established"，之后双向转发原始字节流。
//     所以 https 域名对代理完全透明——TLS 加密在客户端和真实目标之间。
//   - 普通 HTTP 转发（http://... 明文走这里）：
//     客户端发绝对 URI "GET http://host/path HTTP/1.1"，
//     代理重建请求（origin-form）发到目标，把响应抄回客户端。
package inbound

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"mini-clash/internal/adapter"
	"mini-clash/internal/constant"
	"mini-clash/internal/log"
	"mini-clash/internal/netutil"
)

// Http 是 HTTP 入站处理器。它本身是 http.Handler。
type Http struct {
	transport adapter.Transport // 内核：负责选路 + 出站拨号
}

func NewHttp(transport adapter.Transport) *Http {
	return &Http{transport: transport}
}

// ServeHTTP 处理一条 HTTP 代理请求。
func (h *Http) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		h.handleConnect(w, r)
		return
	}
	h.handlePlain(w, r)
}

// handleConnect 处理 CONNECT 隧道。
func (h *Http) handleConnect(w http.ResponseWriter, r *http.Request) {
	// CONNECT 时 r.Host 是 "example.com:443"
	host := r.Host
	if !strings.Contains(host, ":") {
		host = net.JoinHostPort(host, "443")
	}
	hostname, port, err := net.SplitHostPort(host)
	if err != nil {
		http.Error(w, "bad target: "+err.Error(), http.StatusBadRequest)
		return
	}

	meta := &constant.Metadata{
		NetWork: "tcp",
		Type:    constant.HTTP,
		Host:    hostname,
		DstPort: port,
	}

	clientConn, err := hijackConn(w)
	if err != nil {
		return
	}

	// 交给内核：选路 + 出站拨号
	target, err := h.transport.Conn(r.Context(), meta, clientConn)
	if err != nil {
		code := "502 Bad Gateway"
		if errors.Is(err, constant.ErrBlocked) {
			code = "403 Forbidden"
		}
		_, _ = fmt.Fprintf(clientConn, "HTTP/1.1 %s\r\n\r\n", code)
		_ = clientConn.Close()
		return
	}

	// 拨号成功 → 先回 200，再双向转发
	if _, err := fmt.Fprintf(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		_ = clientConn.Close()
		_ = target.Close()
		return
	}
	log.Infof("[http] CONNECT %s -> %s", host, target.RemoteAddr())
	go netutil.Relay(clientConn, target)
}

// handlePlain 处理普通 HTTP 转发（绝对 URI 形式）。
//
// 教学版实现为"一请求一连接"：
// 重建请求发到目标，解析响应抄回客户端，然后关闭。
// 真实 Clash 会把普通 HTTP 也包装成出站走完整规则链，并做连接池复用，
// 但报文流转的本质和我们这里完全一样。
func (h *Http) handlePlain(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Host
	if host == "" {
		host = r.Host
	}
	if !strings.Contains(host, ":") {
		host = net.JoinHostPort(host, "80")
	}
	hostname, port, err := net.SplitHostPort(host)
	if err != nil {
		http.Error(w, "bad target: "+err.Error(), http.StatusBadRequest)
		return
	}

	meta := &constant.Metadata{
		NetWork: "tcp",
		Type:    constant.HTTP,
		Host:    hostname,
		DstPort: port,
	}

	clientConn, err := hijackConn(w)
	if err != nil {
		return
	}

	// 内核选路 + 拨号
	target, err := h.transport.Conn(r.Context(), meta, clientConn)
	if err != nil {
		_ = clientConn.Close()
		return
	}

	// 把请求以 origin-form（/path 形式）转发给目标
	r.RequestURI = ""
	r.URL.Scheme = ""
	r.URL.Host = ""
	if err := r.Write(target); err != nil {
		log.Warnln("[http] forward request:", err)
		_ = clientConn.Close()
		_ = target.Close()
		return
	}

	// 读目标的响应，原样抄回客户端
	resp, err := http.ReadResponse(bufio.NewReader(target), r)
	if err != nil {
		log.Warnln("[http] read response:", err)
		_ = clientConn.Close()
		_ = target.Close()
		return
	}
	log.Infof("[http] %s http://%s -> %s", r.Method, host, target.RemoteAddr())
	_ = resp.Write(clientConn)
	_ = resp.Body.Close()
	_ = clientConn.Close()
	_ = target.Close()
}

// hijackConn 从 http 层"劫持"底层 TCP 连接。
//
// 关键细节：http.Server 用带缓冲的 reader 读请求头，
// 可能已经把请求后面的几个字节也读进了缓冲区（Body 或后续字节）。
// 劫持后必须把这些字节"放回"读流，否则数据会凭空消失。
func hijackConn(w http.ResponseWriter) (net.Conn, error) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return nil, errors.New("hijacking not supported")
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return nil, err
	}
	if n := rw.Reader.Buffered(); n > 0 {
		peeked, _ := rw.Reader.Peek(n)
		conn = &bufferedConn{
			Conn:   conn,
			reader: io.MultiReader(bytes.NewReader(peeked), conn),
		}
	}
	return conn, nil
}

// bufferedConn 把劫持时多读的字节拼回读流。
type bufferedConn struct {
	net.Conn
	reader io.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.reader.Read(b) }

var _ http.Handler = (*Http)(nil)
var _ = adapter.Transport(nil)
