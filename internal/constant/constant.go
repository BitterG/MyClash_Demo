// Package constant 定义整个内核共享的基础类型与常量。
//
// 在真实 Clash (mihomo) 里，constant 包承担同样的角色：
//   - Stage：定义拨号流水线的各个阶段（连接建立会依次经过这些"链"，
//     这让 Clash 能做协议嗅探、规则预处理、隧道嵌套等高级功能）
//   - Metadata 相关约定：元数据如何放进 context、如何在链路上传递
//   - 标准错误：dial 到一半返回这些错误表示"不用建立真实连接"
package constant

import "errors"

// Stage 表示一次连接建立过程中的流水线阶段。
// 教学版只列出不真正使用，目的是让你认识这个词——
// 读 mihomo 源码时 tunnel.go 里的 pipeline 就是按这些阶段组织的。
type Stage int

//go:generate stringer -type=Stage
const (
	StageMain Stage = iota
	StageSniff    // 协议嗅探（识别出 TLS/HTTP/SSH...）
	StageDetect   // 出站协议探测
	StageResolve  // DNS 解析
	StageRedirect // 重定向
	StageRule     // 规则匹配
	StageProxy    // 出站拨号
	StageDNS      // DNS 链
	StageTransport
	StageTunnel
)

// ctxKey 是 context 中存储元数据的键类型。
// 真实 Clash 用同样的方式把 Metadata 挂在 context 上，
// 任何深层的组件都能随时取出来。
type ctxKey int

const (
	CtxKeyMetadata ctxKey = iota
	CtxKeyProxyName
	CtxKeyProxyAdapter
	CtxKeyListener
	CtxKeyHijack
)

// 协议类型常量（字符串，方便日志打印）。真实 Clash 也这么写。
const (
	HTTP  = "HTTP"
	SOCKS = "SOCKS"
)

// 转发上下文中使用的字段名（Socks5 出站等场景会用到）
const (
	FieldDstHost = "dst_host"
	FieldDstPort = "dst_port"
)

// 标准错误：adapter 层约定这些错误表示"不建立真实连接"。
//   - ErrNoRoute / ErrUnsupported：该协议不支持，交给上一层降级处理
//   - ErrBlocked：命中拒绝规则
var (
	ErrNoRoute     = errors.New("no route")
	ErrUnsupported = errors.New("protocol unsupported")
	ErrBlocked     = errors.New("connection blocked")
)
