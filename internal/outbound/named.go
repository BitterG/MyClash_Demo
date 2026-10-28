package outbound

import (
	"context"
	"net"

	"mini-clash/internal/adapter"
	"mini-clash/internal/constant"
)

// Named 给任意 adapter 套一层自定义名字。
// 真实 Clash 的出站是"类型即实现"，名字来自配置字段；
// 教学版用这个包装器模拟"同一个 direct 类型可以叫多个名字"。
type Named struct {
	name   string
	inner  adapter.Adapter
}

func NewNamed(name string, inner adapter.Adapter) *Named {
	return &Named{name: name, inner: inner}
}

func (n *Named) Name() string { return n.name }

func (n *Named) Dial(ctx context.Context, m *constant.Metadata) (net.Conn, error) {
	return n.inner.Dial(ctx, m)
}
