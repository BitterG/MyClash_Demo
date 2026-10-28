// Package dns 是里程碑 2 的核心：DNS 解析与 fake-ip。
//
// 本文件是 RFC 1035 的协议样板（报文编解码），不属于 Clash 架构知识，
// 你不需要逐行读懂，只需会用两个函数：
//
//	ParseQuery(data) -> (host, qtype, id, question, ok)
//	    把收到的 UDP DNS 查询包拆成：域名、查询类型、事务ID、问题段原文。
//	BuildAResponse(id, question, ip) -> []byte
//	    用问题段原文构造一条 A 记录应答，域名部分用压缩指针指回问题段。
//
// 想深入可以对照 RFC 1035 §4.1 看：DNS 报文 = 12 字节头 + 问题段 + 应答段。
// 域名编码是 "长度+标签" 序列（如 "7example3com0"），应答里域名普遍用
// 0xC0 开头的两字节指针指回报文前面出现过的位置（压缩）。
package dns

import (
	"encoding/binary"
	"errors"
	"net"
	"strings"
)

// ParseQuery 解析一个 DNS 查询报文（UDP 收包后调用）。
// 只接受标准查询（QR=0、QDCOUNT=1）；问题段域名不支持压缩指针
// （真实客户端发出的查询都不会压缩，可以放心）。
// 客户端查 example.com 时，发到 5353 端口的不是文字，是一串字节（十六进制）
// 12 34 | 01 00 | 00 01 | 00 00 | 00 00 | 00 00      ← 12字节头部
// 07 'e' 'x' 'a' 'm' 'p' 'l' 'e' | 03 'c' 'o' 'm' | 00  ← 域名
// 00 01 | 00 01                                     ← 查询类型、类别
func ParseQuery(data []byte) (host string, qtype uint16, id uint16, question []byte, ok bool) {
	if len(data) < 12 {
		return
	}
	id = binary.BigEndian.Uint16(data[0:2])
	flags := binary.BigEndian.Uint16(data[2:4])
	qdcount := binary.BigEndian.Uint16(data[4:6])
	if flags&0x8000 != 0 || qdcount != 1 { // 不是标准查询，丢弃
		return
	}
	name, n, err := parseName(data[12:])
	if err != nil || len(data) < 12+n+4 {
		return
	}
	qtype = binary.BigEndian.Uint16(data[12+n : 12+n+2])
	question = data[12 : 12+n+4] // 问题段原文（域名 + QTYPE + QCLASS）
	return name, qtype, id, question, true
}

// BuildAResponse 构造一条 A 记录应答。
// question 是 ParseQuery 返回的问题段原文，原样带回。
func BuildAResponse(id uint16, question []byte, ip net.IP) []byte {
	resp := make([]byte, 12, 64+len(question))
	binary.BigEndian.PutUint16(resp[0:2], id)
	binary.BigEndian.PutUint16(resp[2:4], 0x8180) // QR=1 RD=1 RA=1 RCODE=0
	binary.BigEndian.PutUint16(resp[4:6], 1)      // QDCOUNT=1
	binary.BigEndian.PutUint16(resp[6:8], 1)      // ANCOUNT=1
	resp = append(resp, question...)

	// 应答记录：域名用压缩指针 0xC00C 指回问题段（报文偏移 12 处）
	resp = append(resp, 0xC0, 0x0C)
	rr := make([]byte, 10)
	binary.BigEndian.PutUint16(rr[0:2], 1)   // TYPE=A
	binary.BigEndian.PutUint16(rr[2:4], 1)   // CLASS=IN
	binary.BigEndian.PutUint32(rr[4:8], 300) // TTL=300s
	binary.BigEndian.PutUint16(rr[8:10], 4)  // RDLENGTH=4
	resp = append(resp, rr...)
	if v4 := ip.To4(); v4 != nil {
		resp = append(resp, v4...)
	} else {
		resp = append(resp, 0, 0, 0, 0)
	}
	return resp
}

// parseName 解出一个未压缩的域名，返回标签序列和消耗的字节数。
func parseName(data []byte) (string, int, error) {
	var labels []string
	off := 0
	for {
		if off >= len(data) {
			return "", 0, errors.New("short packet")
		}
		l := int(data[off])
		if l == 0 {
			return strings.Join(labels, "."), off + 1, nil
		}
		if l&0xC0 == 0xC0 {
			return "", 0, errors.New("compressed name not supported")
		}
		if off+1+l > len(data) {
			return "", 0, errors.New("short label")
		}
		labels = append(labels, string(data[off+1:off+1+l]))
		off += 1 + l
	}
}
