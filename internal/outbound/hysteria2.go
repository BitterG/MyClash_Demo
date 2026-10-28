// Package outbound 的 Hysteria2 客户端（基于 QUIC + Salamander 混淆）。
//
// Hysteria2 与之前所有出站的最大区别：底层是 QUIC（UDP），不是 TCP。
// 协议链路（按官方规范 https://hysteria.network/docs/developers/Protocol/）：
//
//   1. UDP 包套 Salamander 混淆（BLAKE2b-256(key+salt) 逐字节 XOR）
//   2. QUIC 握手（0-RTT 可选）
//   3. HTTP/3 伪装认证：POST /auth 到 host "hysteria"
//      带 Hysteria-Auth 头，服务器回 status 233 = 成功
//   4. 之后这个 QUIC 连接就是代理通道：
//      每个 TCP 连接 = 一个 QUIC 双向流，先发 TCPRequest 帧
//
// TCPRequest 帧格式（varint 编码）：
//   [varint 0x401] [varint addrLen] [bytes addr(host:port)] [varint padLen] [bytes padding]
// 服务器回 TCPResponse：
//   [uint8 status(0=OK,1=Error)] [varint msgLen] [bytes msg] [varint padLen] [bytes padding]
package outbound

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"golang.org/x/crypto/blake2b"

	"mini-clash/internal/constant"
	"mini-clash/internal/dns"
)

// Hysteria2 出站节点。
type Hysteria2 struct {
	name     string
	server   string
	port     int
	ports    string // 端口跳变范围（"a-b" 或 "a,b,c"），优先于 port
	doh      string // 专属 DoH URL（节点域名防污染时用）
	password string // 认证密码
	sni      string // TLS SNI
	obfs     string // "salamander" 或空（不支持时忽略）
	obfsKey  string // salamander 混淆密钥
}

// NewHysteria2 创建节点。
func NewHysteria2(name, server string, port int, ports, doh, password, sni, obfs, obfsKey string) *Hysteria2 {
	return &Hysteria2{
		name: name, server: server, port: port, ports: ports, doh: doh,
		password: password, sni: sni, obfs: obfs, obfsKey: obfsKey,
	}
}

func (h *Hysteria2) Name() string { return h.name }

// resolveServer 解析节点服务器地址。
// 如果配置了专属 DoH，用它解析（防污染）；否则走系统 DNS。
// 返回 IP 和完整地址。注意：SNI 仍用原始域名，解析出的 IP 只用于拨号。
func (h *Hysteria2) resolveServer(port int) (string, error) {
	if h.doh == "" {
		return net.JoinHostPort(h.server, strconv.Itoa(port)), nil
	}
	ips, err := dns.ResolveDOH(h.server, h.doh)
	if err != nil {
		return "", fmt.Errorf("hysteria2 doh resolve %s: %w", h.server, err)
	}
	// 用第一个真实 IP 拨号（可扩展为多 IP 重试）
	return net.JoinHostPort(ips[0].String(), strconv.Itoa(port)), nil
}

// pickPort 选择连接端口：优先从跳变范围随机选，否则用主端口。
func (h *Hysteria2) pickPort() int {
	ports := parsePorts(h.ports)
	if len(ports) > 0 {
		return ports[randInt(len(ports))]
	}
	return h.port
}

// parsePorts 解析 "43334-45000" 或 "1,2,3" 或混合形式。
func parsePorts(s string) []int {
	if s == "" {
		return nil
	}
	var out []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			a, err1 := strconv.Atoi(strings.TrimSpace(lo))
			b, err2 := strconv.Atoi(strings.TrimSpace(hi))
			if err1 == nil && err2 == nil && a <= b {
				for p := a; p <= b; p++ {
					out = append(out, p)
				}
			}
		} else if p, err := strconv.Atoi(part); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// randInt 返回 [0,n) 随机数（教学版用时间纳秒做种子，真实用 crypto/rand）。
func randInt(n int) int {
	return int(time.Now().UnixNano() % int64(n))
}

// Dial 建立 hysteria2 会话：解析节点 IP → QUIC 拨号 → HTTP/3 认证 → 开 TCP 流 → 返回。
func (h *Hysteria2) Dial(ctx context.Context, m *constant.Metadata) (net.Conn, error) {
	port := h.pickPort() // 端口跳变：每次连接随机选

	// 解析节点地址（DoH 防污染 → 真实 IP）
	addr, err := h.resolveServer(port)
	if err != nil {
		return nil, err
	}
	sni := h.sni
	if sni == "" {
		sni = h.server // SNI 用原始域名，不是解析出的 IP
	}

	tlsCfg := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // 教学版：跳过证书校验
		NextProtos:         []string{"h3"},
	}
	quicCfg := &quic.Config{
		KeepAlivePeriod: 15 * time.Second,
		// 关键：强制只用 QUIC v1。
		// quic-go 0.64 默认同时发 v1+v2 的多版本 Initial，
		// 部分 CDN 中转/服务端只认 v1，多版本首包会被静默丢弃。
		Versions: []quic.Version{quic.Version1},
	}

	// ── 第 1 步：建立 QUIC 连接（可选 Salamander 混淆） ────
	udpConn, err := net.ListenUDP("udp", nil) // 系统分配本地端口
	if err != nil {
		return nil, err
	}

	var pconn net.PacketConn = udpConn
	if h.obfs == "salamander" && h.obfsKey != "" {
		pconn = &salamanderConn{
			UDPConn: udpConn,
			key:     []byte(h.obfsKey),
			remote:  mustUDPAddr(addr),
		}
	}

	conn, err := quic.Dial(ctx, pconn, mustUDPAddr(addr), tlsCfg, quicCfg)
	if err != nil {
		_ = udpConn.Close()
		return nil, fmt.Errorf("hysteria2 quic dial: %w", err)
	}
	success := false
	defer func() {
		if !success {
			_ = conn.CloseWithError(0, "")
			_ = udpConn.Close()
		}
	}()

	// ── 第 2 步：HTTP/3 伪装认证 ───────────────────────────
	if err := h.auth(ctx, conn, sni); err != nil {
		return nil, err
	}

	// ── 第 3 步：开 TCP 流，发 TCPRequest 帧 ───────────────
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("hysteria2 open stream: %w", err)
	}

	reqFrame := buildTCPRequest(net.JoinHostPort(m.Host, m.DstPort))
	if _, err := stream.Write(reqFrame); err != nil {
		return nil, fmt.Errorf("hysteria2 write tcp request: %w", err)
	}

	// 读 TCPResponse：status 字节 + varint msgLen + msg + varint padLen + padding
	var statusByte [1]byte
	if _, err := io.ReadFull(stream, statusByte[:]); err != nil {
		return nil, fmt.Errorf("hysteria2 read response: %w", err)
	}

	// 无论 OK 还是 Error，格式都是：
	// [uint8 status] [varint msgLen] [bytes msg] [varint padLen] [bytes padding]
	msgLen, err := readVarint(stream)
	if err != nil {
		return nil, fmt.Errorf("hysteria2 read msg len: %w", err)
	}
	msg := make([]byte, msgLen)
	if _, err := io.ReadFull(stream, msg); err != nil {
		return nil, fmt.Errorf("hysteria2 read msg: %w", err)
	}
	padLen, err := readVarint(stream)
	if err != nil {
		return nil, fmt.Errorf("hysteria2 read pad len: %w", err)
	}
	if _, err := io.CopyN(io.Discard, stream, int64(padLen)); err != nil {
		return nil, fmt.Errorf("hysteria2 read padding: %w", err)
	}

	if statusByte[0] != 0x00 {
		return nil, fmt.Errorf("hysteria2 connect failed: status 0x%02x: %s", statusByte[0], string(msg))
	}

	success = true
	// 包装流为 net.Conn（QUIC 流实现了 net.Conn 需要的接口）
	return &hysteriaConn{
		Stream: stream,
		conn:   conn,
		udp:    udpConn,
	}, nil
}

// auth 执行 HTTP/3 认证：POST /auth 到 host "hysteria"。
func (h *Hysteria2) auth(ctx context.Context, conn *quic.Conn, sni string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://hysteria/auth", nil)
	if err != nil {
		return err
	}
	req.Host = "hysteria"
	req.Header.Set("Hysteria-Auth", h.password)
	req.Header.Set("Hysteria-CC-RX", "0")
	req.Header.Set("Hysteria-Padding", strconv.Itoa(64+int(time.Now().UnixNano()%64)))

	// 关键：http3.Transport 会自己拨新连接，所以用 Dial 钩子
	// 强制复用我们已经建立的 QUIC 连接。
	return h.authOnExistingConn(ctx, conn, req)
}

// authOnExistingConn 在已有 QUIC 连接上做认证（手动构造 HTTP/3 请求帧太复杂，
// 这里用 http3.Transport 的 Dial 钩子复用连接）。
// 关键：不能 defer tr.Close()——它会连我们复用的 QUIC 连接一起关掉，
// 认证后我们还要用这个连接开 TCP 流。
func (h *Hysteria2) authOnExistingConn(ctx context.Context, conn *quic.Conn, req *http.Request) error {
	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{
			ServerName:         req.URL.Hostname(),
			InsecureSkipVerify: true,
			NextProtos:         []string{"h3"},
		},
		// 关键：Dial 钩子直接返回已建立的 QUIC 连接
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			return conn, nil
		},
	}

	resp, err := tr.RoundTrip(req)
	if err != nil {
		return fmt.Errorf("hysteria2 auth: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != 233 {
		return fmt.Errorf("hysteria2 auth failed: status %d", resp.StatusCode)
	}
	return nil
}

// ─── QUIC 流包装为 net.Conn ──────────────────────────────

// hysteriaConn 把 QUIC stream 包装成 net.Conn。
// 教学版只转发 TCP，UDP 关联不做。
type hysteriaConn struct {
	*quic.Stream
	conn *quic.Conn
	udp  *net.UDPConn
}

func (c *hysteriaConn) Close() error {
	c.Stream.CancelRead(0)
	c.Stream.CancelWrite(0)
	_ = c.conn.CloseWithError(0, "")
	_ = c.udp.Close()
	return nil
}

func (c *hysteriaConn) LocalAddr() net.Addr  { return c.conn.LocalAddr() }
func (c *hysteriaConn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

// ─── 协议帧编码（QUIC varint，RFC 9000）─────────────────
//
// 注意：QUIC varint 不是 protobuf varint！
// QUIC varint 最高 2 位编码长度：
//   00 → 1 字节（低 6 位是值）
//   01 → 2 字节（低 14 位是值）
//   10 → 4 字节（低 30 位是值）
//   11 → 8 字节（低 62 位是值）
// 之前用 binary.PutUvarint（protobuf 风格）导致帧被服务器静默丢弃。

// appendQuicVarint 追加 QUIC varint 编码。
func appendQuicVarint(dst []byte, v uint64) []byte {
	switch {
	case v < 1<<6:
		return append(dst, byte(v))
	case v < 1<<14:
		return append(dst, byte(0x40|v>>8), byte(v))
	case v < 1<<30:
		return append(dst, byte(0x80|v>>24), byte(v>>16), byte(v>>8), byte(v))
	default:
		return append(dst, byte(0xC0|v>>56), byte(v>>48), byte(v>>40), byte(v>>32),
			byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
}

// readQuicVarint 从 reader 读 QUIC varint。
func readQuicVarint(r io.Reader) (uint64, error) {
	var first [1]byte
	if _, err := io.ReadFull(r, first[:]); err != nil {
		return 0, err
	}
	b0 := first[0]
	switch b0 >> 6 {
	case 0: // 1 字节
		return uint64(b0), nil
	case 1: // 2 字节
		var rest [1]byte
		if _, err := io.ReadFull(r, rest[:]); err != nil {
			return 0, err
		}
		return uint64(b0&0x3F)<<8 | uint64(rest[0]), nil
	case 2: // 4 字节
		var rest [3]byte
		if _, err := io.ReadFull(r, rest[:]); err != nil {
			return 0, err
		}
		return uint64(b0&0x3F)<<24 | uint64(rest[0])<<16 | uint64(rest[1])<<8 | uint64(rest[2]), nil
	default: // 8 字节
		var rest [7]byte
		if _, err := io.ReadFull(r, rest[:]); err != nil {
			return 0, err
		}
		return uint64(b0&0x3F)<<56 | uint64(rest[0])<<48 | uint64(rest[1])<<40 | uint64(rest[2])<<32 |
			uint64(rest[3])<<24 | uint64(rest[4])<<16 | uint64(rest[5])<<8 | uint64(rest[6]), nil
	}
}

// buildTCPRequest 构造 TCPRequest 帧。
// [varint 0x401] [varint addrLen] [addr bytes] [varint padLen=0]
func buildTCPRequest(addr string) []byte {
	buf := appendQuicVarint(nil, 0x401)
	buf = appendQuicVarint(buf, uint64(len(addr)))
	buf = append(buf, addr...)
	buf = appendQuicVarint(buf, 0) // padding length 0
	return buf
}

// readVarint 是 readQuicVarint 的兼容别名（历史调用点）。
func readVarint(r io.Reader) (uint64, error) {
	return readQuicVarint(r)
}

// ─── Salamander 混淆层 ───────────────────────────────────

// salamanderConn 把每个 UDP 包按 Salamander 规范混淆：
// [8B salt] [payload XOR blake2b-256(key+salt)循环]
type salamanderConn struct {
	*net.UDPConn
	key    []byte
	remote net.Addr
}

func (s *salamanderConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := s.UDPConn.ReadFrom(p)
	if err != nil {
		return n, addr, err
	}
	// 去混淆
	if n < 8 {
		return 0, addr, errors.New("salamander: short packet")
	}
	salt := p[:8]
	payload := p[8:n]
	hash := blake2b.Sum256(append(append([]byte{}, s.key...), salt...))
	for i := range payload {
		payload[i] ^= hash[i%32]
	}
	copy(p, payload)
	return len(payload), addr, nil
}

func (s *salamanderConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	salt := make([]byte, 8)
	_, _ = rand.Read(salt) // 加密级随机 salt
	hash := blake2b.Sum256(append(append([]byte{}, s.key...), salt...))

	payload := make([]byte, 8+len(p))
	copy(payload[:8], salt)
	for i, b := range p {
		payload[8+i] = b ^ hash[i%32]
	}
	// 发送到存储的目标（UDP 无连接，WriteTo 的 addr 参数可能不是我们的目标）
	_, err := s.UDPConn.WriteTo(payload, s.remote)
	return len(p), err
}

// mustUDPAddr 解析 UDP 地址，失败返回空。
func mustUDPAddr(addr string) *net.UDPAddr {
	u, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return &net.UDPAddr{}
	}
	return u
}

var _ = constant.HTTP
