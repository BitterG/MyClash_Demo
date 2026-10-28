package outbound

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"time"

	"mini-clash/internal/constant"
	"mini-clash/internal/socks5"
)

// Trojan 出站：真实 TLS 隧道 + SHA224(密码) 认证 + SOCKS5 风格地址。
//
// 协议（RFC 无正式文档，以 trojan-gfw 的 protocol.md 为准）：
//
//	客户端先做【真实 TLS 握手】，然后发：
//	    hex(SHA224(password)) + CRLF + [CMD] + [ATYP+地址+端口] + CRLF
//
// 与 SOCKS5 最大的不同：【没有应答字节】。
// 服务器验证通过就直接开始双向转发；验证失败则按"其他协议"处理
// （发来 fallback 网页的 HTTP 内容），客户端无法从协议层区分——
// 这正是 Trojan 伪装成 HTTPS 站点的设计。
type Trojan struct {
	name       string
	server     string
	port       int
	password   string
	sni        string // TLS SNI（伪装域名），空则用 server
	skipVerify bool   // 教学版默认跳过证书校验（真实客户端一般会校验）
}

// NewTrojan 创建 Trojan 出站。
func NewTrojan(name, server string, port int, password, sni string, skipVerify bool) *Trojan {
	return &Trojan{
		name:       name,
		server:     server,
		port:       port,
		password:   password,
		sni:        sni,
		skipVerify: skipVerify,
	}
}

func (t *Trojan) Name() string { return t.name }

// Dial 四步：TCP 拨节点 → TLS 握手 → 发认证头+请求 → 返回隧道。
func (t *Trojan) Dial(ctx context.Context, m *constant.Metadata) (net.Conn, error) {
	// ── 第 1 步：TCP 拨到节点 ────────────────────────────
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp",
		net.JoinHostPort(t.server, strconv.Itoa(t.port)))
	if err != nil {
		return nil, fmt.Errorf("dial trojan node %s:%d: %w", t.server, t.port, err)
	}
	success := false
	defer func() {
		if !success {
			_ = raw.Close()
		}
	}()
	_ = raw.SetDeadline(time.Now().Add(15 * time.Second)) // 握手限时

	// ── 第 2 步：真实 TLS 握手 ───────────────────────────
	// SNI 是伪装的关键：对网络观察者来说，这就是在访问 sni 那个网站。
	sni := t.sni
	if sni == "" {
		sni = t.server
	}
	tlsConn := tls.Client(raw, &tls.Config{
		ServerName:         sni, // 必须设：决定 ClientHello 里的 SNI
		InsecureSkipVerify: t.skipVerify,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("trojan tls handshake: %w", err)
	}

	// ── 第 3 步：发认证头 + 连接请求 ─────────────────────
	// 认证头 = hex(SHA224(password))，56 个 ASCII 字符
	hash := sha256.Sum224([]byte(t.password))
	key := hex.EncodeToString(hash[:])

	// 协议格式：key + CRLF + CMD + 地址 + CRLF
	// CMD=0x01（CONNECT），地址字段复用 SOCKS5 的编码（ATYP 三种编码完全一致）
	if _, err := tlsConn.Write([]byte(key + "\r\n")); err != nil {
		return nil, err
	}
	if _, err := tlsConn.Write([]byte{0x01}); err != nil {
		return nil, err
	}
	if err := socks5.NewAddr(m.Host, uint16(m.PortInt())).WriteTo(tlsConn); err != nil {
		return nil, err
	}
	if _, err := tlsConn.Write([]byte("\r\n")); err != nil {
		return nil, err
	}

	// ── 第 4 步：无应答，直接进入隧道 ─────────────────────
	_ = tlsConn.SetDeadline(time.Time{})
	success = true
	return tlsConn, nil
}
