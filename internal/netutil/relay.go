// Package netutil 提供网络工具：优雅关闭连接（closeWrite）、
// 双向拷贝等。真实 Clash 用 relay 包干这些事。
package netutil

import "net"

// Relay 双向转发：把 left 和 right 背靠背对接，
// 任一方向读不到数据（EOF）就优雅关闭另一方向的写端，
// 等两个方向都结束再返回。这是 Clash 隧道转发的最小实现。
//
// 真实 Clash 的 relay.Relay 还支持：
//   - 双向流量统计（Traffic 接口）
//   - 读超时后的 keepalive 探测
//   - 对 QUIC/UDP 的 packet relay
// 教学版只保留 TCP 语义。
func Relay(left, right net.Conn) {
	done := make(chan struct{}, 2)

	go func() {
		copyOne(left, right)
		done <- struct{}{}
	}()
	go func() {
		copyOne(right, left)
		done <- struct{}{}
	}()

	<-done
	closeWrite(left)  // 一个方向结束 → 优雅关闭对方写端（发 FIN）
	closeWrite(right) // 让对方能读到 EOF 而不是一直挂着
	<-done
}

// copyOne 单向拷贝 + 错误容忍：EOF 是正常结束，不算错误。
func copyOne(dst, src net.Conn) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// closeWrite 优雅关闭写方向：只发 FIN，不丢对端还没读完的数据。
func closeWrite(c net.Conn) {
	type closeWriter interface{ CloseWrite() error }
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}
