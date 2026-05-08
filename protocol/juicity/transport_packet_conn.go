package juicity

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/shadowsocks"
	"github.com/olicesx/quic-go"
)

type TransportPacketConn struct {
	*quic.Transport
	proxyAddr *net.UDPAddr
	tgt       netip.AddrPort
	key       *shadowsocks.Key
	firstIv   []byte
	mu        sync.Mutex
}

// SetDeadline implements netproxy.Conn.
func (c *TransportPacketConn) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}

// SetReadDeadline implements netproxy.Conn.
func (c *TransportPacketConn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

// SetWriteDeadline implements netproxy.Conn.
func (c *TransportPacketConn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}

func (c *TransportPacketConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var salt pool.PB
	if c.firstIv != nil {
		salt = c.firstIv
		c.firstIv = nil
	} else {
		salt = pool.Get(c.key.CipherConf.SaltLen)
		defer salt.Put()
		salt[0] = 0
		salt[1] = 0
		_, _ = fastrand.Read(salt[2:])
	}
	toWrite, err := shadowsocks.EncryptUDPFromPool(c.key, b, salt, ciphers.JuicityReusedInfo)
	if err != nil {
		return 0, err
	}
	defer toWrite.Put()
	n, err := c.Transport.WriteTo(toWrite, c.proxyAddr)
	if err != nil {
		return 0, err
	}
	if n != len(toWrite) {
		return 0, io.ErrShortWrite
	}
	return len(b), nil
}

func (c *TransportPacketConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return n, err
}

func (c *TransportPacketConn) ReadFrom(p []byte) (n int, addrPort netip.AddrPort, err error) {
	buf := pool.Get(len(p) + CipherConf.SaltLen + CipherConf.TagLen)
	defer buf.Put()
	n, _, err = c.ReadNonQUICPacket(context.TODO(), buf)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	n, err = shadowsocks.DecryptUDP(p, c.key, buf[:n], ciphers.JuicityReusedInfo)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	return n, c.tgt, nil
}

func (c *TransportPacketConn) WriteTo(p []byte, addr string) (n int, err error) {
	return c.Write(p)
}

func (c *TransportPacketConn) Close() error {
	var err error
	if c.Transport != nil {
		err = c.Transport.Close()
	}
	if c.Conn != nil {
		if closeErr := c.Conn.Close(); err == nil {
			err = closeErr
		}
	}
	return err
}
