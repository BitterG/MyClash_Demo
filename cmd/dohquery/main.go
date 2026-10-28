// Command dohquery：查询指定 DoH 服务器（支持自签证书），打印 A 记录。
// 用法：go run ./cmd/dohquery <doh-url> <host>
package main

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"strings"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: go run ./cmd/dohquery <doh-url> <host>")
		os.Exit(2)
	}
	url, host := os.Args[1], os.Args[2]

	// 构造 DNS 查询报文
	q := make([]byte, 12)
	binary.BigEndian.PutUint16(q[0:2], 0x1234)
	binary.BigEndian.PutUint16(q[2:4], 0x0100)
	binary.BigEndian.PutUint16(q[4:6], 1)
	for _, label := range strings.Split(host, ".") {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0, 0, 1, 0, 1) // type A, class IN

	// base64url 编码
	b64 := base64URL(q)

	req, err := http.NewRequest(http.MethodGet, url+"?dns="+b64, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "request:", err)
		os.Exit(1)
	}
	req.Header.Set("Accept", "application/dns-message")

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			ForceAttemptHTTP2: true,
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "query:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read:", err)
		os.Exit(1)
	}
	fmt.Printf("HTTP %d, %d bytes\n", resp.StatusCode, len(body))
	if resp.StatusCode != 200 || len(body) < 12 {
		fmt.Printf("body: %s\n", string(body[:min(len(body), 200)]))
		os.Exit(1)
	}

	// 解析 DNS 应答：跳过 header + question
	off := 12
	for off < len(body) && body[off] != 0 {
		off += int(body[off]) + 1
	}
	off += 1 + 4 // 结束符 + type + class

	// answer 段
	ancount := binary.BigEndian.Uint16(body[6:8])
	for i := 0; i < int(ancount) && off+12 <= len(body); i++ {
		if body[off]&0xC0 == 0xC0 {
			off += 2 // 压缩指针
		} else {
			for off < len(body) && body[off] != 0 {
				off += int(body[off]) + 1
			}
			off++
		}
		if off+10 > len(body) {
			break
		}
		atype := binary.BigEndian.Uint16(body[off : off+2])
		rdlen := int(binary.BigEndian.Uint16(body[off+8 : off+10]))
		off += 10
		if atype == 1 && rdlen == 4 && off+4 <= len(body) {
			ip := netip.AddrFrom4([4]byte(body[off : off+4]))
			fmt.Printf("A %s\n", ip)
		}
		off += rdlen
	}
}

func base64URL(b []byte) string {
	const table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	var sb strings.Builder
	for i := 0; i < len(b); i += 3 {
		var n uint32
		rem := len(b) - i
		n = uint32(b[i]) << 16
		if rem > 1 {
			n |= uint32(b[i+1]) << 8
		}
		if rem > 2 {
			n |= uint32(b[i+2])
		}
		sb.WriteByte(table[(n>>18)&63])
		sb.WriteByte(table[(n>>12)&63])
		if rem > 1 {
			sb.WriteByte(table[(n>>6)&63])
		} else {
			sb.WriteByte('=')
		}
		if rem > 2 {
			sb.WriteByte(table[n&63])
		} else {
			sb.WriteByte('=')
		}
	}
	return strings.TrimRight(sb.String(), "=")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

var _ = errors.New
