package juicity

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/netproxy"
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
	writeMu   sync.Mutex
	readMu    sync.Mutex

	lifeOnce   sync.Once
	lifeCtx    context.Context
	lifeCancel context.CancelFunc

	deadlineMu       sync.Mutex
	readDeadline     time.Time
	deadlineVersion  uint64
	activeReadCancel context.CancelCauseFunc
	activeReadTimer  *time.Timer
	activeReadGen    uint64

	closeOnce sync.Once
	closeErr  error
}

func (c *TransportPacketConn) ensureLifetime() {
	c.lifeOnce.Do(func() {
		c.lifeCtx, c.lifeCancel = context.WithCancel(context.Background())
	})
}

func (c *TransportPacketConn) expireActiveRead(gen, version uint64) {
	c.deadlineMu.Lock()
	if c.activeReadGen != gen || c.deadlineVersion != version || c.activeReadCancel == nil {
		c.deadlineMu.Unlock()
		return
	}
	cancel := c.activeReadCancel
	c.activeReadTimer = nil
	c.deadlineMu.Unlock()
	cancel(os.ErrDeadlineExceeded)
}

func (c *TransportPacketConn) armActiveReadTimerLocked(gen, version uint64) context.CancelCauseFunc {
	if c.activeReadTimer != nil {
		c.activeReadTimer.Stop()
		c.activeReadTimer = nil
	}
	if c.activeReadCancel == nil || c.readDeadline.IsZero() {
		return nil
	}
	delay := time.Until(c.readDeadline)
	if delay <= 0 {
		return c.activeReadCancel
	}
	c.activeReadTimer = time.AfterFunc(delay, func() {
		c.expireActiveRead(gen, version)
	})
	return nil
}

func (c *TransportPacketConn) setStoredReadDeadline(t time.Time) error {
	c.ensureLifetime()
	c.deadlineMu.Lock()
	if c.lifeCtx.Err() != nil {
		c.deadlineMu.Unlock()
		return net.ErrClosed
	}
	c.readDeadline = t
	c.deadlineVersion++
	cancel := c.armActiveReadTimerLocked(c.activeReadGen, c.deadlineVersion)
	c.deadlineMu.Unlock()
	if cancel != nil {
		cancel(os.ErrDeadlineExceeded)
	}
	return nil
}

func (c *TransportPacketConn) startReadContext() (context.Context, context.CancelCauseFunc, uint64) {
	c.ensureLifetime()
	c.deadlineMu.Lock()
	c.activeReadGen++
	gen := c.activeReadGen
	ctx, cancel := context.WithCancelCause(c.lifeCtx)
	c.activeReadCancel = cancel
	version := c.deadlineVersion
	expire := c.armActiveReadTimerLocked(gen, version)
	c.deadlineMu.Unlock()
	if expire != nil {
		expire(os.ErrDeadlineExceeded)
	}
	return ctx, cancel, gen
}

func (c *TransportPacketConn) finishReadContext(ctx context.Context, cancel context.CancelCauseFunc, gen uint64) error {
	c.deadlineMu.Lock()
	if c.activeReadGen == gen {
		if c.activeReadTimer != nil {
			c.activeReadTimer.Stop()
			c.activeReadTimer = nil
		}
		c.activeReadCancel = nil
	}
	c.deadlineMu.Unlock()
	cause := context.Cause(ctx)
	cancel(nil)
	return cause
}

// SetDeadline implements netproxy.Conn.
func (c *TransportPacketConn) SetDeadline(t time.Time) error {
	if err := c.setStoredReadDeadline(t); err != nil {
		return err
	}
	if c.Transport == nil || c.Conn == nil {
		return nil
	}
	return c.Conn.SetWriteDeadline(t)
}

// SetReadDeadline implements netproxy.Conn.
func (c *TransportPacketConn) SetReadDeadline(t time.Time) error {
	return c.setStoredReadDeadline(t)
}

// SetWriteDeadline implements netproxy.Conn.
func (c *TransportPacketConn) SetWriteDeadline(t time.Time) error {
	if c.Transport == nil || c.Conn == nil {
		return nil
	}
	return c.Conn.SetWriteDeadline(t)
}

func (c *TransportPacketConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
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
	c.readMu.Lock()
	defer c.readMu.Unlock()

	buf := pool.Get(len(p) + CipherConf.SaltLen + CipherConf.TagLen)
	defer buf.Put()
	ctx, cancel, gen := c.startReadContext()
	n, _, err = c.ReadNonQUICPacket(ctx, buf)
	cause := c.finishReadContext(ctx, cancel, gen)
	if err != nil {
		if c.lifeCtx.Err() != nil || errors.Is(cause, context.Canceled) {
			return 0, netip.AddrPort{}, net.ErrClosed
		}
		if errors.Is(cause, os.ErrDeadlineExceeded) {
			return 0, netip.AddrPort{}, os.ErrDeadlineExceeded
		}
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
	c.ensureLifetime()
	c.closeOnce.Do(func() {
		if c.lifeCancel != nil {
			c.lifeCancel()
		}
		var err error
		if c.Transport != nil {
			err = c.Transport.Close()
			if c.Conn != nil {
				if closeErr := c.Conn.Close(); err == nil {
					err = closeErr
				}
			}
		}
		c.closeErr = err
	})
	return c.closeErr
}

// TransportDone implements netproxy.TransportLifecycle so dae can skip
// write-deadline arming on this QUIC underlay. Closing the conn cancels
// lifeCtx; the returned channel is that context's Done.
func (c *TransportPacketConn) TransportDone() <-chan struct{} {
	if c == nil {
		return nil
	}
	c.ensureLifetime()
	if c.lifeCtx == nil {
		return nil
	}
	return c.lifeCtx.Done()
}

var _ netproxy.TransportLifecycle = (*TransportPacketConn)(nil)
