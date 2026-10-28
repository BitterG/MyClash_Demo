package dns

import (
	"mini-clash/internal/log"
	"net"
)

//server.go：管"收包、拆包、回包"（协议层，跟网络对话）
//resolver.go：管"域名换 IP"（业务层，只管换，不管网络）

//1. UDP 监听 127.0.0.1:5353
//2. 收一个包  ── 字节流，什么都看不懂
//3. 拆包     ── 用 dns.ParseQuery 拆出：域名 / 查询类型 / 事务ID / 问题段
//4. 换 IP    ── 调 resolver.Resolve(域名) 拿 IP
//5. 打包回信 ── 用 dns.BuildAResponse 拼应答，WriteTo 发回给客户端
//6. 回到 2

type Server struct {
	addr     string
	resolver *Resolver
	conn     net.PacketConn // 启动后持有，Close 用
}

func NewServer(addr string, resolver *Resolver) *Server {
	return &Server{addr: addr, resolver: resolver}
}

func (s *Server) Serve() error {
	// 为什么用 UDP 不是 TCP：DNS 查询默认 UDP
	conn, err := net.ListenPacket("udp", s.addr)
	if err != nil {
		return err
	}
	// 启动后赋值回去让Server对象持有连接句柄
	s.conn = conn
	log.Infoln("[dns] fake-ip server listening on", s.addr)

	buf := make([]byte, 512) // 标准 DNS over UDP 单包上限

	for {
		// 一个请求包一个应答包，没有"连接"概念，所以代码里没有 Accept()，
		// 只有 ReadFrom（同时告诉你"谁发的"）和 WriteTo（回给"刚才那个谁"）
		n, clientAddr, err := s.conn.ReadFrom(buf)
		if err != nil {
			return err // 端口关了就是这里退出
		}
		// 拆包
		host, qtype, id, question, ok := ParseQuery(buf[:n])
		if !ok || qtype != 1 {
			continue
		}
		ip, err := s.resolver.Resolve(host)
		if err != nil {
			log.Warnln("[dns] resolve failed:", host, err)
			continue
		}
		resp := BuildAResponse(id, question, net.IP(ip.AsSlice()))

		// 回给刚才那个客户端
		if _, err := s.conn.WriteTo(resp, clientAddr); err != nil {
			log.Warnln("[dns] write response:", err)
		}
	}
}

// Close 关闭 UDP 端口，让 Start 的 ReadFrom 返回错误退出。
func (s *Server) Close() error {
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}
