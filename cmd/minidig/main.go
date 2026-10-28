// Command minidig：向指定 DNS 服务器查 A 记录的最小工具（迷你版 dig）。
//
// 用法：
//
//	go run ./cmd/minidig 127.0.0.1:5353 example.com
//
// 原理：net.Resolver 的 Dial 字段可以把 DNS 请求指向任意服务器——
// 我们把它指向自己写的 fake-ip DNS 服务器来验收。
// 这里只查 A（ip4）记录。
package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: go run ./cmd/minidig <dns-server> <host>")
		os.Exit(2)
	}
	server, host := os.Args[1], os.Args[2]

	ips, err := lookup(server, host)
	if err != nil {
		fmt.Fprintln(os.Stderr, "lookup failed:", err)
		os.Exit(1)
	}
	for _, ip := range ips {
		fmt.Printf("%s. 300 IN A %s\n", host, ip)
	}
}

// lookup 用自定义拨号器把查询发到指定 DNS 服务器。
// 注意：这也是 SystemResolver 可以用的同款技巧——
// 换个 Dial 就能把"系统 DNS"换成"走代理隧道的 DNS"。
func lookup(server, host string) ([]net.IP, error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", server)
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return r.LookupIP(ctx, "ip4", host)
}
