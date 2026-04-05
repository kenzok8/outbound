package client

import (
	"errors"
	"io"
	"net/netip"
	"sync"
	"time"

	rand "github.com/daeuniverse/outbound/pkg/fastrand"

	"github.com/olicesx/quic-go"

	"github.com/daeuniverse/outbound/netproxy"
	coreErrs "github.com/daeuniverse/outbound/protocol/hysteria2/errors"
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/frag"
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/protocol"
)

const (
	// Keep enough headroom for short scheduler stalls and bursty game ticks.
	// dae already backpressures its own reply path, so the remaining drop window
	// is mainly pre-drain bursts before this session goroutine gets CPU time.
	udpMessageChanSize = 2048
)

type udpIO interface {
	ReceiveMessage() (*protocol.UDPMessage, error)
	SendMessage([]byte, *protocol.UDPMessage) error
}

type udpConn struct {
	ID        uint32
	D         *frag.Defragger
	ReceiveCh chan *protocol.UDPMessage
	SendBuf   []byte
	SendFunc  func([]byte, *protocol.UDPMessage) error
	CloseFunc func()
	Closed    bool

	// transportDone is closed when the underlying QUIC transport connection
	// is permanently closed.  Allows upstream consumers (e.g. dae UdpEndpoint)
	// to detect transport death without waiting for ReadFrom/WriteTo errors.
	transportDone <-chan struct{}

	writeMu sync.Mutex
	muTimer sync.Mutex
	timer   *time.Timer
	target  string
}

// TransportDone implements netproxy.TransportLifecycle.
// The returned channel is closed when the QUIC transport backing this
// UDP session is permanently dead.
func (u *udpConn) TransportDone() <-chan struct{} {
	if u.transportDone == nil {
		// Return a never-closed channel for safety.
		return make(chan struct{})
	}
	return u.transportDone
}

func (u *udpConn) Read(b []byte) (n int, err error) {
	msg, _, err := u.ReadFrom(b)
	return msg, err
}

func (u *udpConn) Write(b []byte) (n int, err error) {
	return u.WriteTo(b, u.target)
}

func (u *udpConn) ReadFrom(p []byte) (n int, addr netip.AddrPort, err error) {
	for {
		msg := <-u.ReceiveCh
		if msg == nil {
			// Closed
			return 0, netip.AddrPort{}, io.EOF
		}
		dfMsg := u.D.Feed(msg)
		if dfMsg == nil {
			// Incomplete message, wait for more
			continue
		}
		netipAddr, err := netip.ParseAddrPort(dfMsg.Addr)
		if err != nil {
			return 0, netipAddr, err
		}
		return copy(p, dfMsg.Data), netipAddr, nil
	}
}

func (u *udpConn) WriteTo(b []byte, addr string) (n int, err error) {
	u.writeMu.Lock()
	defer u.writeMu.Unlock()

	// Try no frag first
	msg := &protocol.UDPMessage{
		SessionID: u.ID,
		PacketID:  0,
		FragID:    0,
		FragCount: 1,
		Addr:      addr,
		Data:      b,
	}
	// The session's fixed serialization buffer is smaller than the theoretical
	// UDP payload limit. Treat local buffer exhaustion the same way quic-go
	// reports path MTU exhaustion so we fragment instead of silently dropping.
	if msg.Size() > len(u.SendBuf) {
		err = &quic.DatagramTooLargeError{MaxDataLen: int64(len(u.SendBuf))}
	} else {
		err = u.SendFunc(u.SendBuf, msg)
	}
	var errTooLarge *quic.DatagramTooLargeError
	if errors.As(err, &errTooLarge) {
		// Message too large, try fragmentation
		msg.PacketID = uint16(rand.Intn(0xFFFF)) + 1
		fMsgs := frag.FragUDPMessage(msg, int(errTooLarge.MaxDataLen))
		for _, fMsg := range fMsgs {
			err := u.SendFunc(u.SendBuf, &fMsg)
			if err != nil {
				return 0, err
			}
		}
		return len(b), nil
	} else {
		return len(b), err
	}
}

func (u *udpConn) Close() error {
	u.CloseFunc()
	return nil
}

func (u *udpConn) SetDeadline(t time.Time) error {
	u.muTimer.Lock()
	defer u.muTimer.Unlock()
	dur := time.Until(t)
	if u.timer != nil {
		u.timer.Reset(dur)
	} else {
		u.timer = time.AfterFunc(dur, func() {
			u.muTimer.Lock()
			defer u.muTimer.Unlock()
			_ = u.Close()
			u.timer = nil
		})
	}
	return nil
}

func (u *udpConn) SetReadDeadline(t time.Time) error {
	// FIXME: Single direction.
	return u.SetDeadline(t)
}

func (u *udpConn) SetWriteDeadline(t time.Time) error {
	// FIXME: Single direction.
	return u.SetDeadline(t)
}

type udpSessionManager struct {
	io udpIO

	mutex  sync.RWMutex
	m      map[uint32]*udpConn
	nextID uint32

	closed bool
	done   chan struct{}
}

func newUDPSessionManager(io udpIO) *udpSessionManager {
	m := &udpSessionManager{
		io:     io,
		m:      make(map[uint32]*udpConn),
		nextID: 1,
		done:   make(chan struct{}),
	}
	go func() { _ = m.run() }()
	return m
}

func (m *udpSessionManager) run() error {
	defer m.closeCleanup()
	for {
		msg, err := m.io.ReceiveMessage()
		if err != nil {
			return err
		}
		m.feed(msg)
	}
}

func (m *udpSessionManager) closeCleanup() {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	for _, conn := range m.m {
		m.close(conn)
	}
	m.closed = true
	close(m.done)
}

func (m *udpSessionManager) feed(msg *protocol.UDPMessage) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	conn, ok := m.m[msg.SessionID]
	if !ok {
		// Ignore message from unknown session
		return
	}

	select {
	case conn.ReceiveCh <- msg:
		// OK
	default:
		// Channel full, drop the message
	}
}

// NewUDP creates a new UDP session.
func (m *udpSessionManager) NewUDP(addr string) (netproxy.Conn, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.closed {
		return nil, coreErrs.ClosedError{}
	}

	id := m.nextID
	m.nextID++

	conn := &udpConn{
		ID:            id,
		D:             &frag.Defragger{},
		ReceiveCh:     make(chan *protocol.UDPMessage, udpMessageChanSize),
		SendBuf:       make([]byte, protocol.MaxUDPSize),
		SendFunc:      m.io.SendMessage,
		transportDone: m.done,

		writeMu: sync.Mutex{},
		muTimer: sync.Mutex{},
		target:  addr,
	}
	conn.CloseFunc = func() {
		m.mutex.Lock()
		defer m.mutex.Unlock()
		m.close(conn)
	}
	m.m[id] = conn

	return conn, nil
}

func (m *udpSessionManager) close(conn *udpConn) {
	if !conn.Closed {
		conn.Closed = true
		close(conn.ReceiveCh)
		delete(m.m, conn.ID)
	}
}

func (m *udpSessionManager) Count() int {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return len(m.m)
}
