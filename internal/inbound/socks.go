// Package inbound 的 SOCKS5 入站：让客户端用 socks5:// 协议连 mini-clash。
//
// 它和 cmd/minisocks 是同一份逻辑的两种命运：
//   - minisocks：独立进程，握手后【自己拨号】连目标
//   - 本文件：内核的一部分，握手后【交给内核】连目标（走规则链、走出站）
//
// 所以代码骨架几乎一样，唯一区别在"握手成功后谁来拨号"。
// 这就是 Clash 入站层设计的本质：入站只负责"听懂客户端"，拨号是内核的事。
package inbound

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"mini-clash/internal/adapter"
	"mini-clash/internal/constant"
	"mini-clash/internal/log"
	"mini-clash/internal/netutil"
	"mini-clash/internal/socks5"
)

// SocksListener 是 SOCKS5 入站监听器（服务器侧）。
type SocksListener struct {
	addr      string
	transport adapter.Transport // 内核：把解析好的连接交给它
	ln        net.Listener
}

func NewSocksListener(addr string, transport adapter.Transport) *SocksListener {
	return &SocksListener{addr: addr, transport: transport}
}

// Start 监听 TCP 端口并进入 accept 循环（每个连接一个 goroutine）。
// 对应 HTTP 入站的 http.Server.Serve；这里没有现成框架，自己写循环。
func (l *SocksListener) Start() error {
	ln, err := net.Listen("tcp", l.addr)
	if err != nil {
		return err
	}
	l.ln = ln
	log.Infoln("[listener] socks5 proxy listening at", ln.Addr())

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // 端口关了（Close），退出循环
			}
			go l.handle(conn) // 一个客户端一个 goroutine，互不阻塞
		}
	}()
	return nil
}

// Close 关闭监听端口。
func (l *SocksListener) Close() error {
	if l.ln != nil {
		return l.ln.Close()
	}
	return nil
}

// handle 处理一个客户端连接：完整 SOCKS5 服务器侧握手。
func (l *SocksListener) handle(client net.Conn) {
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(15 * time.Second)) // 握手限时

	// ═══ 阶段 1：方法协商 ═══════════════════════════════════
	// 客户端发：[VER=5, NMETHODS, 方法列表...]
	// 例：[05 02 00 02] = "我是SOCKS5，我支持2种方法：no-auth 和 用户名密码"
	var greeting [2]byte
	if _, err := io.ReadFull(client, greeting[:]); err != nil {
		return
	}
	if greeting[0] != 0x05 {
		return // 不是 SOCKS5，断开
	}
	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(client, methods); err != nil {
		return
	}

	// 在客户端提供的方法里挑 no-auth（0x00）
	supportsNoAuth := false
	for _, m := range methods {
		if m == 0x00 {
			supportsNoAuth = true
			break
		}
	}
	if !supportsNoAuth {
		_, _ = client.Write([]byte{0x05, 0xFF}) // 0xFF = 没有可用的方法
		return
	}
	// 回：[05 00] = "就用 no-auth"
	if _, err := client.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// ═══ 阶段 2：连接请求 ═══════════════════════════════════
	// 客户端发：[VER=5, CMD, RSV] + 地址字段
	var reqHdr [3]byte
	if _, err := io.ReadFull(client, reqHdr[:]); err != nil {
		return
	}
	if reqHdr[0] != 0x05 {
		return
	}
	if reqHdr[1] != 0x01 {
		// CMD 不是 CONNECT（教学版不支持 BIND/UDP ASSOCIATE）
		// REP=0x07 = 命令不支持
		_, _ = client.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// 读地址字段（ATYP + 地址 + 端口），socks5.ReadFrom 会自己处理三种编码
	target, err := socks5.ReadFrom(client)
	if err != nil {
		return
	}

	// ═══ 交给内核：填 Metadata → 内核选路 + 出站拨号 ═══════
	// 注意：这一步是 socks 入站和 HTTP 入站唯一"本质相同"的地方——
	// 无论什么协议，最终都变成 Metadata + Transport.Conn。
	meta := &constant.Metadata{
		NetWork: "tcp",
		Type:    constant.SOCKS,
		Host:    target.Host,
		DstPort: fmt.Sprintf("%d", target.Port),
	}

	targetConn, err := l.transport.Conn(context.Background(), meta, client)
	if err != nil {
		// 拨号失败：区分两种失败给客户端更准确的 REP 码
		rep := byte(0x05) // 0x05 = 连接被拒（默认）
		if errors.Is(err, constant.ErrBlocked) {
			rep = 0x02 // 0x02 = 规则不允许（对应 HTTP 入站的 403）
		}
		_, _ = client.Write([]byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		log.Warnf("[socks] CONNECT %s failed: %v", target.String(), err)
		return
	}
	defer targetConn.Close()

	// ═══ 回成功应答：REP=0 + 绑定地址（惯例全零）═══════
	// 字节：[05 00 00 | 01 00 00 00 00 | 00 00]
	//        └VER REP RSV  └IPv4 0.0.0.0    └端口0
	// 客户端只关心 REP=0，绑定地址填什么都行。
	if _, err := client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	// ═══ 握手完成，进入隧道 ═══════════════════════════════
	_ = client.SetDeadline(time.Time{}) // 清掉握手限时，隧道阶段不能有超时
	log.Infof("[socks] CONNECT %s -> %s", target.String(), targetConn.RemoteAddr())
	netutil.Relay(client, targetConn) // 双向转发，直到一方断开
}

var _ = adapter.Transport(nil)
