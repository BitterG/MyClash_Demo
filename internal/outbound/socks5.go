package outbound

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mini-clash/internal/constant"
	"mini-clash/internal/socks5"
	"net"
	"strconv"
	"time"
)

type Socks5 struct {
	name   string // 节点名（"NODE"）
	server string // 节点地址
	port   int
	dialer DialContext // 拨到节点的拨号器
}

// NewSocks5 创建节点出站。
func NewSocks5(name, server string, port int) *Socks5 {
	return &Socks5{
		name:   name,
		server: server,
		port:   port,
		dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, address)
		},
	}
}

func (s *Socks5) Name() string { return s.name }

// Dial 三步：拨节点 → SOCKS5 握手 → 返回已接通的隧道。
func (s *Socks5) Dial(ctx context.Context, m *constant.Metadata) (net.Conn, error) {
	// ── 第 1 步：拨到节点服务器 ──────────────────────────
	// 注意：此时 TCP 三次握手已经完成（net.Dial 内部干的）。
	// 我们拿到的是"和节点之间的裸 TCP 连接"，还没说任何业务。
	node, err := s.dialer(ctx, "tcp", net.JoinHostPort(s.server, strconv.Itoa(s.port)))
	if err != nil {
		return nil, fmt.Errorf("dial socks5 node %s:%d: %w", s.server, s.port, err)
	}
	// 后面任何一步失败都要关掉这条连接，不能泄露
	success := false
	defer func() {
		if !success {
			_ = node.Close()
		}
	}()
	_ = node.SetDeadline(time.Now().Add(15 * time.Second)) // 握手限时，防挂死

	// ── 第 2 步：方法协商 ────────────────────────────────
	// 发：VER=0x05, NMETHODS=1, METHODS=[0x00(no-auth)]
	// 意思："我是 SOCKS5，只支持无密码认证，你选一个"
	if _, err := node.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return nil, err
	}

	// 读：2 字节应答 [VER, METHOD]
	var methodResp [2]byte
	if _, err := io.ReadFull(node, methodResp[:]); err != nil {
		return nil, err
	}
	if methodResp[0] != 0x05 {
		return nil, errors.New("socks5: bad version in method response")
	}
	if methodResp[1] == 0xFF {
		return nil, errors.New("socks5: no acceptable auth method")
	}
	if methodResp[1] != 0x00 {
		// 节点要求用户名密码认证——教学版不支持，直接报错
		return nil, fmt.Errorf("socks5: unsupported auth method 0x%02x", methodResp[1])
	}

	// ── 第 3 步：连接请求 ────────────────────────────────
	// 发：VER=0x05, CMD=0x01(CONNECT), RSV=0x00，然后地址字段
	// 地址字段里如果 m.Host 是域名，就发域名（ATYP=0x03），
	// 节点会替我们解析——这就是"远端解析"(remote DNS)。
	if _, err := node.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return nil, err
	}
	target := socks5.NewAddr(m.Host, uint16(m.PortInt()))
	if err := target.WriteTo(node); err != nil {
		return nil, err
	}

	// ── 第 4 步：读应答 ──────────────────────────────────
	// 应答头固定 3 字节：[VER, REP, RSV]。
	// 注意：ATYP 不能在这里读！socks5.ReadFrom 开头会自己读 ATYP，
	// 所以这里只读 3 字节，把 ATYP 及后面的绑定地址整个交给 ReadFrom。
	var respHdr [3]byte
	if _, err := io.ReadFull(node, respHdr[:]); err != nil {
		return nil, err
	}
	if respHdr[0] != 0x05 {
		return nil, errors.New("socks5: bad version in connect response")
	}
	if respHdr[1] != 0x00 {
		// REP 非 0 = 失败。常见值：1=一般失败 2=规则拒绝
		// 3=网络不可达 4=主机不可达 5=连接被拒 6=TTL过期 7=命令不支持 8=地址类型不支持
		return nil, fmt.Errorf("socks5: connect failed, REP=0x%02x", respHdr[1])
	}

	// 读掉绑定地址字段（ATYP + 地址 + 端口）。socks5.ReadFrom 自己
	// 会先读 ATYP 再按类型读地址，所以必须把 ATYP 留给它——
	// 在头里多读 1 字节就会让它读到错误的字节，把成功握手判成失败。
	if _, err := socks5.ReadFrom(node); err != nil {
		return nil, err
	}

	// ── 第 5 步：握手完成，交还隧道 ──────────────────────
	_ = node.SetDeadline(time.Time{}) // 取消握手限时，进入自由转发
	success = true
	return node, nil
}
