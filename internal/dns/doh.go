// Package dns 的 DNS-over-HTTPS 客户端（最小实现）。
//
// 用途：某些机场（如 claudeborder）对节点域名做了防污染——
// 公共 DNS 解析到假 IP，真实 IP 只能通过它们的专属 DoH 获取。
// Clash 配置里的 nameserver-policy 就是干这个的。
//
// 我们实现一个 per-node 版本：出站配置里带 doh 字段，
// 拨号前用 DoH 解析节点域名，拿真实 IP 去连。
package dns

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// ResolveDOH 通过 DoH 服务器解析 A 记录。
// dohURL 形如 "https://host:port/dns-query/xxx"（自签证书跳过校验）。
// 返回全部 A 记录 IP。
func ResolveDOH(host, dohURL string) ([]netip.Addr, error) {
	// 构造 DNS 查询报文
	q := make([]byte, 12)
	binary.BigEndian.PutUint16(q[0:2], 0x1234) // 随机事务 ID
	binary.BigEndian.PutUint16(q[2:4], 0x0100) // 标准查询 + 递归
	binary.BigEndian.PutUint16(q[4:6], 1)      // QDCOUNT=1
	for _, label := range strings.Split(host, ".") {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0, 0, 1, 0, 1) // 结束符, TYPE=A, CLASS=IN

	url := dohURL + "?dns=" + base64URL(q)

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			ForceAttemptHTTP2: true, // RFC 8484 要求 HTTP/2
		},
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("doh status %d: %s", resp.StatusCode, string(body[:min(len(body), 200)]))
	}
	if len(body) < 12 {
		return nil, fmt.Errorf("doh short response: %d bytes", len(body))
	}

	// 跳过 header + question
	off := 12
	for off < len(body) && body[off] != 0 {
		off += int(body[off]) + 1
	}
	off += 1 + 4

	// 解析 answer 段
	var ips []netip.Addr
	ancount := binary.BigEndian.Uint16(body[6:8])
	for i := 0; i < int(ancount) && off+12 <= len(body); i++ {
		if body[off]&0xC0 == 0xC0 {
			off += 2
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
			ips = append(ips, netip.AddrFrom4([4]byte(body[off:off+4])))
		}
		off += rdlen
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no A record for %s", host)
	}
	return ips, nil
}

// base64URL 无填充编码。
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
		}
		if rem > 2 {
			sb.WriteByte(table[n&63])
		}
	}
	return strings.TrimRight(sb.String(), "=")
}
