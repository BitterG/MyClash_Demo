// Package socks5 提供 SOCKS5 协议（RFC 1928）的地址编解码。
//
// 本文件是协议样板：地址字段的编码与解析。不属于 Clash 架构知识，
// 但 SOCKS5 出站/入站都要用它，所以独立成包共享。
//
// SOCKS5 地址字段（ATYP）三种编码：
//
//	0x01 IPv4: [01] + 4字节 + 2字节端口   （7 字节定长）
//	0x03 域名: [03] + 1字节长度 + 域名 + 2字节端口 （变长）
//	0x04 IPv6: [04] + 16字节 + 2字节端口  （19 字节定长）
//
// 端口永远是大端序 2 字节。
package socks5

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
)

// Addr 表示一个 SOCKS5 地址（可能是 IP 或域名）。
type Addr struct {
	Host string // 域名或 IP 字符串
	Port uint16
}

// AddrFromMetadata 是我们 mini-clash 的便利函数：
// 把内核的 Metadata 转成 SOCKS5 地址。注意这个函数在本包里
// 没有 Metadata 类型，由 outbound 层转换好后传入 Host/Port。
func NewAddr(host string, port uint16) Addr {
	return Addr{Host: host, Port: port}
}

// WriteTo 按 RFC 1928 编码地址字段写入 w。
//
// 编码规则：
//   - host 是合法 IPv4 → ATYP=0x01 + 4 字节
//   - host 是合法 IPv6 → ATYP=0x04 + 16 字节
//   - 其他（域名）→ ATYP=0x03 + 长度前缀 + 原始字节
func (a Addr) WriteTo(w io.Writer) error {
	// IPv4
	if ip, err := netip.ParseAddr(a.Host); err == nil && ip.Is4() {
		if _, err := w.Write([]byte{0x01}); err != nil {
			return err
		}
		if _, err := w.Write(ip.AsSlice()); err != nil { // As4 是 4 字节
			return err
		}
		return writePort(w, a.Port)
	}
	// IPv6
	if ip, err := netip.ParseAddr(a.Host); err == nil && ip.Is6() {
		if _, err := w.Write([]byte{0x04}); err != nil {
			return err
		}
		if _, err := w.Write(ip.AsSlice()); err != nil {
			return err
		}
		return writePort(w, a.Port)
	}
	// 域名
	if len(a.Host) > 255 {
		return errors.New("domain too long")
	}
	if _, err := w.Write([]byte{0x03, byte(len(a.Host))}); err != nil {
		return err
	}
	if _, err := w.Write([]byte(a.Host)); err != nil {
		return err
	}
	return writePort(w, a.Port)
}

// ReadFrom 从 r 读出一个地址字段（返回 ATYP 开头后的完整地址）。
func ReadFrom(r io.Reader) (Addr, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return Addr{}, err
	}
	switch atyp[0] {
	case 0x01: // IPv4
		var buf [4]byte
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return Addr{}, err
		}
		port, err := readPort(r)
		if err != nil {
			return Addr{}, err
		}
		ip := netip.AddrFrom4(buf)
		return Addr{Host: ip.String(), Port: port}, nil

	case 0x03: // 域名
		var lenb [1]byte
		if _, err := io.ReadFull(r, lenb[:]); err != nil {
			return Addr{}, err
		}
		host := make([]byte, lenb[0])
		if _, err := io.ReadFull(r, host); err != nil {
			return Addr{}, err
		}
		port, err := readPort(r)
		if err != nil {
			return Addr{}, err
		}
		return Addr{Host: string(host), Port: port}, nil

	case 0x04: // IPv6
		var buf [16]byte
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return Addr{}, err
		}
		port, err := readPort(r)
		if err != nil {
			return Addr{}, err
		}
		ip := netip.AddrFrom16(buf)
		return Addr{Host: ip.String(), Port: port}, nil
	}
	return Addr{}, errors.New("unsupported ATYP")
}

// writePort 写大端序端口。
func writePort(w io.Writer, port uint16) error {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], port)
	_, err := w.Write(buf[:])
	return err
}

// readPort 读大端序端口。
func readPort(r io.Reader) (uint16, error) {
	var buf [2]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(buf[:]), nil
}

// String 打印友好形式（日志用）。
func (a Addr) String() string {
	return net.JoinHostPort(a.Host, strconv.Itoa(int(a.Port)))
}
