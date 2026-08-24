// Modified from https://github.com/nadoo/glider/tree/v0.16.2

package socks5

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/netproxy"

	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/infra/socks"
)

// PktConn .
type PktConn struct {
	netproxy.PacketConn
	ctrlConn  netproxy.Conn // tcp control conn
	target    string
	proxyAddr string
	cancel    context.CancelFunc
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
	addrCache common.LastStringValue[socks.Addr]
}

var _ netproxy.PacketReceiver = (*PktConn)(nil)

func (pc *PktConn) RegisterPacketReceiver(handler netproxy.PacketReceiveHandler) (func(), bool) {
	receiver, ok := pc.PacketConn.(netproxy.PacketReceiver)
	if !ok {
		return nil, false
	}
	return netproxy.RegisterMappedPacketReceiver(receiver, handler, pc.mapReceivedPacket)
}

func (pc *PktConn) mapReceivedPacket(packet *netproxy.ReceivedPacket) (*netproxy.ReceivedPacket, bool) {
	if packet.Err != nil {
		return packet, true
	}
	data := packet.Data
	if len(data) < 3 {
		packet.Err = errors.New("not enough size to get addr")
		packet.Data = nil
		return packet, true
	}
	tgtAddr := socks.SplitAddr(data[3:])
	if tgtAddr == nil {
		packet.Err = errors.New("can not get target addr")
		packet.Data = nil
		return packet, true
	}
	target, err := net.ResolveUDPAddr("udp", tgtAddr.String())
	if err != nil {
		packet.Err = errors.New("wrong target addr")
		packet.Data = nil
		return packet, true
	}
	packet.Data = data[3+len(tgtAddr):]
	packet.From = target.AddrPort()
	return packet, true
}

var parseSocksAddr = socks.ParseAddr

// NewPktConn returns a PktConn, the writeAddr must be *net.UDPAddr or *net.UnixAddr.
func NewPktConn(c netproxy.PacketConn, proxyAddr string, targetAddr string, ctrlConn netproxy.Conn) *PktConn {
	ctx, cancel := context.WithCancel(context.Background())
	pc := &PktConn{
		PacketConn: c,
		target:     targetAddr,
		proxyAddr:  proxyAddr,
		ctrlConn:   ctrlConn,
		cancel:     cancel,
	}
	if ctrlConn != nil {
		pc.done = make(chan struct{})
	}

	if ctrlConn != nil {
		go func() {
			buf := pool.Get(1)
			defer pool.Put(buf)
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				_, err := ctrlConn.Read(buf)
				if err, ok := err.(net.Error); ok && err.Timeout() {
					continue
				}
				_ = pc.Close()
				return
			}
		}()
	}

	return pc
}

// ReadFrom overrides the original function from transport.PacketConn.
func (pc *PktConn) ReadFrom(b []byte) (int, netip.AddrPort, error) {
	n, _, target, err := pc.readFrom(b)
	return n, target, err
}

func (pc *PktConn) readFrom(b []byte) (int, netip.AddrPort, netip.AddrPort, error) {
	buf := pool.Get(len(b))
	defer pool.Put(buf)

	n, raddr, err := pc.PacketConn.ReadFrom(buf)
	if err != nil {
		return n, raddr, netip.AddrPort{}, err
	}

	if n < 3 {
		return n, raddr, netip.AddrPort{}, errors.New("not enough size to get addr")
	}

	// https://www.rfc-editor.org/rfc/rfc1928#section-7
	// +----+------+------+----------+----------+----------+
	// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
	// +----+------+------+----------+----------+----------+
	// | 2  |  1   |  1   | Variable |    2     | Variable |
	// +----+------+------+----------+----------+----------+
	tgtAddr := socks.SplitAddr(buf[3:n])
	if tgtAddr == nil {
		return n, raddr, netip.AddrPort{}, errors.New("can not get target addr")
	}

	target, err := net.ResolveUDPAddr("udp", tgtAddr.String())
	if err != nil {
		return n, raddr, netip.AddrPort{}, errors.New("wrong target addr")
	}

	n = copy(b, buf[3+len(tgtAddr):n])
	return n, raddr, target.AddrPort(), err
}

// WriteTo overrides the original function from transport.PacketConn.
func (pc *PktConn) WriteTo(b []byte, addr string) (int, error) {
	target, err := pc.targetAddr(addr)

	if err != nil {
		return 0, fmt.Errorf("invalid addr: %w", err)
	}

	tgtLen := len(target)
	buf := pool.Get(3 + tgtLen + len(b))
	defer pool.Put(buf)

	copy(buf, []byte{0, 0, 0})
	copy(buf[3:], target)
	copy(buf[3+tgtLen:], b)

	n, err := pc.PacketConn.WriteTo(buf, pc.proxyAddr)
	if n > tgtLen+3 {
		return n - tgtLen - 3, err
	}

	return 0, err
}

// WriteBatch implements netproxy.PacketBatchWriter: encapsulate every
// datagram with its SOCKS5 UDP header (RSV FRAG ATYP DST.ADDR DST.PORT) and
// hand the whole batch to the underlying transport's batched writer in one
// call. The encapsulation copies per item exactly like WriteTo; only the
// syscall is amortized.
func (pc *PktConn) WriteBatch(items []netproxy.BatchItem) (int, error) {
	bw, ok := pc.PacketConn.(netproxy.PacketBatchWriter)
	if !ok {
		// Underlying transport has no batched writer: fall back to per-item
		// synchronous writes, preserving ordering. n is a datagram count,
		// matching PacketBatchWriter / dae's aggregator contract.
		sent := 0
		for _, it := range items {
			if _, err := pc.WriteTo(it.Data, it.Addr); err != nil {
				return sent, err
			}
			sent++
		}
		return sent, nil
	}
	enc := make([]netproxy.BatchItem, len(items))
	releaseEnc := func() {
		for _, it := range enc {
			if it.Data != nil {
				pool.Put(it.Data)
			}
		}
	}
	for i, it := range items {
		target, err := pc.targetAddr(it.Addr)
		if err != nil {
			releaseEnc()
			return 0, fmt.Errorf("invalid addr: %w", err)
		}
		tgtLen := len(target)
		buf := pool.Get(3 + tgtLen + len(it.Data))
		copy(buf, []byte{0, 0, 0})
		copy(buf[3:], target)
		copy(buf[3+tgtLen:], it.Data)
		enc[i] = netproxy.BatchItem{Data: buf, Addr: pc.proxyAddr}
	}
	n, err := bw.WriteBatch(enc)
	releaseEnc()
	return n, err
}

func (pc *PktConn) targetAddr(addr string) (socks.Addr, error) {
	if cached, ok := pc.addrCache.Load(addr); ok {
		return cached, nil
	}
	target, err := parseSocksAddr(addr)
	if err != nil {
		return nil, err
	}
	target = append(socks.Addr(nil), target...)
	pc.addrCache.Store(addr, target)
	return target, nil
}

// TransportDone implements netproxy.TransportLifecycle.
// The returned channel is closed when the SOCKS5 UDP association control
// channel terminates and the UDP relay becomes unusable.
func (pc *PktConn) TransportDone() <-chan struct{} {
	return pc.done
}

// Close .
func (pc *PktConn) Close() error {
	pc.closeOnce.Do(func() {
		if pc.cancel != nil {
			pc.cancel()
		}
		if pc.done != nil {
			close(pc.done)
		}
		if pc.ctrlConn != nil {
			_ = pc.ctrlConn.Close()
		}
		if pc.PacketConn != nil {
			pc.closeErr = pc.PacketConn.Close()
		}
	})
	return pc.closeErr
}

func (c *PktConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return
}

func (c *PktConn) Write(b []byte) (n int, err error) {
	return c.WriteTo(b, c.target)
}

var _ netproxy.TransportLifecycle = (*PktConn)(nil)
