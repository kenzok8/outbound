package anytls

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/infra/socks"
)

var (
	_ netproxy.Conn               = (*stream)(nil)
	_ netproxy.PacketConn         = (*packetStream)(nil)
	_ netproxy.TransportLifecycle = (*packetStream)(nil)
)

type stream struct {
	*session

	inbound chan []byte
	readBuf []byte

	writeMutex sync.Mutex
	readMutex  sync.Mutex

	closed   atomic.Bool
	closeCh  chan struct{}
	closeMu  sync.Mutex
	closeErr error

	readDeadline    atomic.Int64
	writeDeadline   atomic.Int64
	deadlineChanged chan struct{}

	id uint32
}

func newStream(session *session, id uint32) *stream {
	return &stream{
		session:         session,
		inbound:         make(chan []byte, 16),
		closeCh:         make(chan struct{}),
		deadlineChanged: make(chan struct{}, 1),
		id:              id,
	}
}

func (c *stream) enqueue(b []byte) error {
	if c.closed.Load() {
		return io.ErrClosedPipe
	}
	chunk := make([]byte, len(b))
	copy(chunk, b)
	select {
	case c.inbound <- chunk:
		return nil
	case <-c.closeCh:
		return io.ErrClosedPipe
	case <-c.session.done:
		return net.ErrClosed
	}
}

func (c *stream) Write(b []byte) (n int, err error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()

	return writeDataFrames(c.session, c.id, b, unixNanoToTime(c.writeDeadline.Load()))
}

func (c *stream) Read(b []byte) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.readMutex.Lock()
	defer c.readMutex.Unlock()
	return c.readLocked(b)
}

func (c *stream) readLocked(b []byte) (n int, err error) {
	if len(c.readBuf) == 0 {
		chunk, err := c.nextChunkLocked()
		if err != nil {
			return 0, err
		}
		c.readBuf = chunk
	}
	n = copy(b, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *stream) nextChunkLocked() ([]byte, error) {
	for {
		select {
		case chunk := <-c.inbound:
			return chunk, nil
		default:
		}
		if err := c.closedError(); err != nil {
			return nil, err
		}

		deadline := unixNanoToTime(c.readDeadline.Load())
		if !deadline.IsZero() {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return nil, os.ErrDeadlineExceeded
			}
			timer := time.NewTimer(remaining)
			select {
			case chunk := <-c.inbound:
				stopTimer(timer)
				return chunk, nil
			case <-c.closeCh:
				stopTimer(timer)
				select {
				case chunk := <-c.inbound:
					return chunk, nil
				default:
				}
				return nil, c.closedError()
			case <-c.deadlineChanged:
				stopTimer(timer)
				continue
			case <-timer.C:
				return nil, os.ErrDeadlineExceeded
			}
		}

		select {
		case chunk := <-c.inbound:
			return chunk, nil
		case <-c.closeCh:
			return nil, c.closedError()
		case <-c.deadlineChanged:
			continue
		}
	}
}

func stopTimer(timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}

func (c *stream) remoteClose() error {
	return c.closeLocal(false, io.EOF)
}

func (c *stream) Close() error {
	return c.closeLocal(true, net.ErrClosed)
}

func (c *stream) closeLocal(sendFIN bool, err error) error {
	if c.closed.CompareAndSwap(false, true) {
		c.closeMu.Lock()
		c.closeErr = err
		close(c.closeCh)
		c.closeMu.Unlock()
		c.removeStream(c.id)
		if sendFIN && !c.session.closed.Load() {
			frame := newFrame(cmdFIN, c.id)
			_, _ = writeFrame(c.session, frame)
		}
	}
	return nil
}

func (c *stream) closedError() error {
	if !c.closed.Load() {
		return nil
	}
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	if c.closeErr != nil {
		return c.closeErr
	}
	return net.ErrClosed
}

func (c *stream) LocalAddr() net.Addr {
	return c.session.conn.(net.Conn).LocalAddr()
}

func (c *stream) RemoteAddr() net.Addr {
	return c.session.conn.(net.Conn).RemoteAddr()
}

func (c *stream) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

func (c *stream) SetReadDeadline(t time.Time) error {
	c.readDeadline.Store(timeToUnixNano(t))
	select {
	case c.deadlineChanged <- struct{}{}:
	default:
	}
	return nil
}

func (c *stream) SetWriteDeadline(t time.Time) error {
	c.writeDeadline.Store(timeToUnixNano(t))
	return nil
}

type packetStream struct {
	*stream

	addr         string
	udpWriteAddr atomic.Bool
}

func (ps *packetStream) TransportDone() <-chan struct{} {
	return ps.closeCh
}

func (ps *packetStream) Read(p []byte) (n int, err error) {
	n, _, err = ps.ReadFrom(p)
	return n, err
}

func (ps *packetStream) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	ps.readMutex.Lock()
	defer ps.readMutex.Unlock()

	addr, _ := netip.ParseAddrPort(ps.addr)
	var length uint16
	var lengthBuf [2]byte
	if err := ps.readFullLocked(lengthBuf[:]); err != nil {
		return 0, netip.AddrPort{}, err
	}
	length = binary.BigEndian.Uint16(lengthBuf[:])
	if len(p) < int(length) {
		if err := ps.drainLocked(int(length)); err != nil {
			return 0, addr, err
		}
		return 0, addr, io.ErrShortBuffer
	}
	if err := ps.readFullLocked(p[:length]); err != nil {
		return 0, addr, err
	}
	return int(length), addr, nil
}

func (ps *packetStream) readFullLocked(p []byte) error {
	for len(p) > 0 {
		n, err := ps.stream.readLocked(p)
		if err != nil {
			return err
		}
		p = p[n:]
	}
	return nil
}

func (ps *packetStream) drainLocked(n int) error {
	buf := pool.Get(min(n, 2048))
	defer pool.Put(buf)
	for n > 0 {
		chunk := buf
		if len(chunk) > n {
			chunk = chunk[:n]
		}
		if err := ps.readFullLocked(chunk); err != nil {
			return err
		}
		n -= len(chunk)
	}
	return nil
}

func (ps *packetStream) Write(p []byte) (n int, err error) {
	return ps.WriteTo(p, ps.addr)
}

func (ps *packetStream) WriteTo(p []byte, addr string) (n int, err error) {
	if ps.closed.Load() {
		return 0, net.ErrClosed
	}
	if len(p) > maxUDPPayloadSize {
		return 0, fmt.Errorf("anytls udp payload too large: %d > %d", len(p), maxUDPPayloadSize)
	}
	ps.writeMutex.Lock()
	defer ps.writeMutex.Unlock()

	if ps.udpWriteAddr.CompareAndSwap(false, true) {
		tgtAddr, err := socks.ParseAddr(addr)
		if err != nil {
			return 0, err
		}
		data := pool.Get(1 + len(tgtAddr) + 2 + len(p))
		defer pool.Put(data)
		// connected mode
		data[0] = 1
		copy(data[1:], tgtAddr)
		binary.BigEndian.PutUint16(data[1+len(tgtAddr):], uint16(len(p)))
		copy(data[1+len(tgtAddr)+2:], p)

		if _, err := writeDataFrames(ps.session, ps.id, data, unixNanoToTime(ps.writeDeadline.Load())); err != nil {
			return 0, err
		}
		return len(p), nil
	}

	data := pool.Get(2 + len(p))
	defer pool.Put(data)
	binary.BigEndian.PutUint16(data, uint16(len(p)))
	copy(data[2:], p)

	if _, err := writeDataFrames(ps.session, ps.id, data, unixNanoToTime(ps.writeDeadline.Load())); err != nil {
		return 0, err
	}
	return len(p), nil
}

func timeToUnixNano(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}

func unixNanoToTime(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n)
}
