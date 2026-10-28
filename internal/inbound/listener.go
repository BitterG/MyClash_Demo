package inbound

import (
	"errors"
	"net"
	"net/http"
	"time"

	"mini-clash/internal/log"
)

// HttpListener 把 Http 处理器包成一个真正的 TCP 监听器。
// 对应真实 Clash 里 listener 包 + tunnel 包共同承担的角色：
// 监听端口 → http.Server 解析协议 → 交给处理器。
type HttpListener struct {
	addr   string
	server *http.Server
}

func NewHttpListener(addr string, handler http.Handler) *HttpListener {
	return &HttpListener{
		addr: addr,
		server: &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: 15 * time.Second,
			IdleTimeout:       90 * time.Second,
			// 注意：不能设置 WriteTimeout。
			// 劫持后的长连接（CONNECT 隧道）写方向的空闲时间远超普通请求，
			// 设了 WriteTimeout 会把正在正常工作的隧道误杀。
		},
	}
}

// Start 监听端口并在后台服务。成功返回 nil，失败返回错误。
func (l *HttpListener) Start() error {
	ln, err := net.Listen("tcp", l.addr)
	if err != nil {
		return err
	}
	log.Infoln("[listener] http proxy listening at", ln.Addr())
	go func() {
		if err := l.server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Errorln("[listener] http server:", err)
		}
	}()
	return nil
}

// Close 优雅关闭监听器。
func (l *HttpListener) Close() error {
	return l.server.Close()
}
