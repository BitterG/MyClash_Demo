// Package outbound 的 Shadowsocks AEAD-2017 客户端（AES-256-GCM）。
//
// 这是 mini-clash 第一个"加密出站"：与 SOCKS5/Trojan 的本质区别是——
// 返回的连接不再透传裸字节，而是【双向加密隧道】：
//   写方向：明文 → AEAD 分块加密 → 发出
//   读方向：密文 → AEAD 分块解密 → 交给上层
//
// 协议（Shadowsocks AEAD-2017）：
//
//	客户端 → 服务器：
//	  [salt(32B 随机)] 然后所有数据都是 AEAD 分块：
//	  [加密的长度(2B+16B tag)] [加密的负载(≤16383B + 16B tag)] ...
//	  第一个分块的负载 = [ATYP][地址][端口]（和 SOCKS5 地址编码相同）
//	  后续分块的负载 = 纯数据
//
//	密钥派生：
//	  masterKey = EVP_BytesToKey(password, 32)   // MD5 循环哈希
//	  subKey    = HKDF-SHA1(masterKey, salt, "ss-subkey")
//	  客户端→服务器 和 服务器→客户端 各自独立 salt 和 subKey
//
//	Nonce：12 字节全零起步，每加密/解密一块后按小端序 +1。
package outbound

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"mini-clash/internal/constant"
	"mini-clash/internal/socks5"
)

const (
	maxChunkPayload = 0x3FFF // 16383，AEAD 协议规定的最大分块负载
	tagLen          = 16     // GCM tag 长度
)

// Shadowsocks 出站节点。
type Shadowsocks struct {
	name     string
	server   string
	port     int
	cipher   string // 教学版只支持 aes-256-gcm
	password string
}

// NewShadowsocks 创建 SS 节点。
func NewShadowsocks(name, server string, port int, cipherName, password string) *Shadowsocks {
	return &Shadowsocks{
		name: name, server: server, port: port,
		cipher: cipherName, password: password,
	}
}

func (s *Shadowsocks) Name() string { return s.name }

// Dial 建立加密隧道：TCP 拨号 → 发 salt + 地址分块 → 读对端 salt → 返回加密连接。
func (s *Shadowsocks) Dial(ctx context.Context, m *constant.Metadata) (net.Conn, error) {
	if s.cipher != "aes-256-gcm" {
		return nil, fmt.Errorf("ss: unsupported cipher %q (only aes-256-gcm)", s.cipher)
	}

	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp",
		net.JoinHostPort(s.server, strconv.Itoa(s.port)))
	if err != nil {
		return nil, fmt.Errorf("dial ss node %s:%d: %w", s.server, s.port, err)
	}
	success := false
	defer func() {
		if !success {
			_ = raw.Close()
		}
	}()
	_ = raw.SetDeadline(time.Now().Add(15 * time.Second))

	// ── 写方向：随机 salt → 派生写 subKey ────────────────
	masterKey := evpBytesToKey([]byte(s.password), 32)
	writeSalt := make([]byte, 32)
	if _, err := rand.Read(writeSalt); err != nil {
		return nil, err
	}
	wkey := hkdfSHA1(masterKey, writeSalt, []byte("ss-subkey"), 32)
	wc, err := newGCM(wkey)
	if err != nil {
		return nil, err
	}

	// 发送 salt（明文）
	if _, err := raw.Write(writeSalt); err != nil {
		return nil, err
	}

	// 第一个分块：地址（ATYP+地址+端口，复用 socks5 编码）
	addrPayload, err := encodeAddr(m.Host, m.PortInt())
	if err != nil {
		return nil, err
	}
	wnonce := make([]byte, 12)
	if err := writeChunk(raw, wc, wnonce, addrPayload); err != nil {
		return nil, err
	}

	// ── 读方向：读服务器 salt → 派生读 subKey ────────────
	readSalt := make([]byte, 32)
	if _, err := io.ReadFull(raw, readSalt); err != nil {
		return nil, err
	}
	rkey := hkdfSHA1(masterKey, readSalt, []byte("ss-subkey"), 32)
	rc, err := newGCM(rkey)
	if err != nil {
		return nil, err
	}

	_ = raw.SetDeadline(time.Time{})
	success = true
	return &ssConn{
		Conn:   raw,
		wc:     wc,
		rc:     rc,
		wnonce: wnonce,
		rnonce: make([]byte, 12),
	}, nil
}

// ─── 加密连接包装 ─────────────────────────────────────────

// ssConn 把裸连接包装成双向加密隧道。
type ssConn struct {
	net.Conn
	wc            cipher.AEAD
	rc            cipher.AEAD
	wnonce        []byte
	rnonce        []byte
	rbuf          []byte // 已解密、尚未交给上层的明文缓冲
	rbufOff       int
}

// Write 实现：明文 → 分块加密 → 写底层连接。
func (c *ssConn) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > maxChunkPayload {
			n = maxChunkPayload
		}
		if err := writeChunk(c.Conn, c.wc, c.wnonce, p[:n]); err != nil {
			return total, err
		}
		p = p[n:]
		total += n
	}
	return total, nil
}

// Read 实现：密文分块 → 解密 → 交给上层。
func (c *ssConn) Read(p []byte) (int, error) {
	// 缓冲里还有明文就先给
	if c.rbufOff < len(c.rbuf) {
		n := copy(p, c.rbuf[c.rbufOff:])
		c.rbufOff += n
		if c.rbufOff >= len(c.rbuf) {
			c.rbuf = nil
			c.rbufOff = 0
		}
		return n, nil
	}

	// 读加密长度（2B + tag）
	var lbuf [18]byte
	if _, err := io.ReadFull(c.Conn, lbuf[:]); err != nil {
		return 0, err
	}
	plainLen, err := c.rc.Open(nil, c.rnonce, lbuf[:], nil)
	if err != nil {
		return 0, fmt.Errorf("ss decrypt length: %w", err)
	}
	increment(c.rnonce)
	n := int(binary.BigEndian.Uint16(plainLen))

	// 读加密负载（n + tag）
	ebuf := make([]byte, n+tagLen)
	if _, err := io.ReadFull(c.Conn, ebuf); err != nil {
		return 0, err
	}
	plain, err := c.rc.Open(nil, c.rnonce, ebuf, nil)
	if err != nil {
		return 0, fmt.Errorf("ss decrypt payload: %w", err)
	}
	increment(c.rnonce)

	c.rbuf = plain
	c.rbufOff = 0
	return c.Read(p)
}

// ─── 协议工具函数 ─────────────────────────────────────────

// writeChunk 把一个明文负载加密成一个 AEAD 分块并写入。
// 分块格式：[加密的长度(2B)+tag] [加密的负载+tag]
func writeChunk(w io.Writer, aead cipher.AEAD, nonce []byte, payload []byte) error {
	// 长度字段：2 字节大端序
	var lenPlain [2]byte
	binary.BigEndian.PutUint16(lenPlain[:], uint16(len(payload)))

	lenCt := aead.Seal(nil, nonce, lenPlain[:], nil)
	increment(nonce)
	if _, err := w.Write(lenCt); err != nil {
		return err
	}

	ct := aead.Seal(nil, nonce, payload, nil)
	increment(nonce)
	_, err := w.Write(ct)
	return err
}

// encodeAddr 编码 SS 地址字段（与 SOCKS5 相同的 ATYP 编码）。
func encodeAddr(host string, port int) ([]byte, error) {
	buf := &bytesWriter{}
	if err := socks5.NewAddr(host, uint16(port)).WriteTo(buf); err != nil {
		return nil, err
	}
	return buf.b, nil
}

// bytesWriter 是收集编码结果的简单缓冲。
type bytesWriter struct{ b []byte }

func (w *bytesWriter) Write(p []byte) (int, error) {
	w.b = append(w.b, p...)
	return len(p), nil
}

// newGCM 创建 AES-GCM AEAD 实例。
func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// increment 按小端序把 nonce 加 1（SS 协议规定）。
func increment(nonce []byte) {
	for i := range nonce {
		nonce[i]++
		if nonce[i] != 0 {
			break
		}
	}
}

// evpBytesToKey：OpenSSL 老式密钥派生（SS 传统），MD5 循环。
func evpBytesToKey(password []byte, keyLen int) []byte {
	var md5sum []byte
	var data []byte
	for len(data) < keyLen {
		h := md5.New()
		h.Write(md5sum)
		h.Write(password)
		md5sum = h.Sum(nil)
		data = append(data, md5sum...)
	}
	return data[:keyLen]
}

// hkdfSHA1：HKDF-SHA1 密钥扩展（RFC 5869），SS 用它从 masterKey+salt 派生 subKey。
func hkdfSHA1(key, salt, info []byte, outLen int) []byte {
	mac := hmac.New(sha1.New, salt)
	mac.Write(key)
	prk := mac.Sum(nil)

	var result, prev []byte
	for i := 1; len(result) < outLen; i++ {
		mac = hmac.New(sha1.New, prk)
		mac.Write(prev)
		mac.Write(info)
		mac.Write([]byte{byte(i)})
		prev = mac.Sum(nil)
		result = append(result, prev...)
	}
	return result[:outLen]
}
