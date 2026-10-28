package outbound

import (
	"context"
	"net"

	"mini-clash/internal/constant"
)

// Reject 拒绝出站：任何拨号都直接失败。
// 对应 Clash 的 REJECT 规则动作——命中后连接立即断开。
type Reject struct{}

func NewReject() *Reject { return &Reject{} }

func (r *Reject) Name() string { return "REJECT" }

func (r *Reject) Dial(ctx context.Context, m *constant.Metadata) (net.Conn, error) {
	return nil, constant.ErrBlocked
}
