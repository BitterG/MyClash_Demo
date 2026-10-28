// Command minisocks：迷你 SOCKS5 服务器，用作本地测试节点。
//
// 用途：模拟一个真实的 SOCKS5 代理服务器，让 mini-clash 的
// socks5 出站有东西可以连。它只支持 no-auth 认证、CONNECT 命令。
//
// 用法：
//
//	go run ./cmd/minisocks 127.0.0.1:1080
//
// 原理：listen → accept → 握手三阶段 → 双向转发。
// 代码结构与真实 SOCKS5 服务器一致，读它可加深理解。
package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"mini-clash/internal/socks5"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go run ./cmd/minisocks <listen-addr>")
		os.Exit(2)
	}
	ln, err := net.Listen("tcp", os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		os.Exit(1)
	}
	fmt.Println("minisocks listening on", ln.Addr(), "(no-auth, CONNECT only)")

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Fprintln(os.Stderr, "accept:", err)
			continue
		}
		go handle(conn)
	}
}

func handle(client net.Conn) {
	defer client.Close()
	client.SetDeadline(time.Now().Add(30 * time.Second))

	// ── 阶段 1：方法协商 ─────────────────────────────
	var greeting [2]byte
	if _, err := io.ReadFull(client, greeting[:]); err != nil {
		return
	}
	if greeting[0] != 0x05 { // VER 必须是 5
		return
	}
	nmethods := int(greeting[1])
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(client, methods); err != nil {
		return
	}
	// 选 no-auth（0x00）。教学版不实现用户名密码认证。
	supports := false
	for _, m := range methods {
		if m == 0x00 {
			supports = true
			break
		}
	}
	if !supports {
		_, _ = client.Write([]byte{0x05, 0xFF}) // 没有可用的方法
		return
	}
	if _, err := client.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// ── 阶段 2：连接请求 ─────────────────────────────
	var reqHdr [3]byte
	if _, err := io.ReadFull(client, reqHdr[:]); err != nil {
		return
	}
	if reqHdr[0] != 0x05 || reqHdr[1] != 0x01 { // VER=5, CMD=CONNECT
		_, _ = client.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // 命令不支持
		return
	}
	target, err := socks5.ReadFrom(client) // 目标地址字段
	if err != nil {
		return
	}

	// ── 阶段 3：拨号目标并回成功应答 ─────────────────
	upstream, err := net.DialTimeout("tcp", target.String(), 10*time.Second)
	if err != nil {
		_, _ = client.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // 连接失败
		fmt.Println("dial", target.String(), "failed:", err)
		return
	}
	defer upstream.Close()

	// 成功应答：REP=0，绑定地址按惯例填全零
	_, _ = client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	fmt.Println("CONNECT", target.String(), "ok")
	client.SetDeadline(time.Time{}) // 进入隧道，取消超时

	// ── 双向转发 ─────────────────────────────────────
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, client)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, upstream)
		done <- struct{}{}
	}()
	<-done
}
