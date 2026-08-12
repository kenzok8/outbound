package client

import (
	"errors"
	"io"
	"net/netip"
	"runtime"
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
	// udpMessageChanSize bounds the per-session receive queue. 128 slots is
	// enough to absorb bursty game ticks / DNS floods (~512KB of 4KB packets)
	// while keeping the steady-state channel footprint at 1KB per session
	// instead of 16KB. QUIC flow control (window-update suppression) provides
	// backpressure beyond the queue, so no packets are lost.
	udpMessageChanSize = 128
)

// sendBufPool recycles the per-session MaxUDPSize send buffer. Sessions are
// created/closed frequently (game ticks, DNS), so pooling avoids a 4KB
// allocation churn and its GC pressure on each session churn.
var sendBufPool = sync.Pool{
	New: func() any { return make([]byte, protocol.MaxUDPSize) },
}

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

	writeMu    sync.Mutex
	receiveMu  sync.Mutex
	muTimer    sync.Mutex
	timer      *time.Timer
	target     string
	targetAddr netip.AddrPort // parsed once at session creation
	receiverMu sync.Mutex
	receiver   netproxy.PacketReceiveHandler
}

var _ netproxy.PacketReceiver = (*udpConn)(nil)

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
		u.receiveMu.Lock()
		dfMsg := u.D.Feed(msg)
		u.receiveMu.Unlock()
		if dfMsg == nil {
			// Incomplete message, wait for more
			continue
		}
		// The session is bound to a single target address, so the parsed
		// AddrPort cached at creation time applies to every datagram on this
		// session - no per-datagram ParseAddrPort needed.
		n := copy(p, dfMsg.Data)
		if dfMsg.Release != nil {
			dfMsg.Release()
		}
		return n, u.targetAddr, nil
	}
}

// RegisterPacketReceiver lets dae consume packets from the session manager's
// existing transport reader without adding a blocking ReadFrom goroutine for
// this logical UDP session.
func (u *udpConn) RegisterPacketReceiver(handler netproxy.PacketReceiveHandler) (func(), bool) {
	if handler == nil {
		return nil, false
	}
	u.receiverMu.Lock()
	if u.receiver != nil {
		u.receiverMu.Unlock()
		return nil, false
	}
	u.receiver = handler
	u.receiverMu.Unlock()

	var unregisterOnce sync.Once
	unregister := func() {
		unregisterOnce.Do(func() {
			u.receiverMu.Lock()
			u.receiver = nil
			u.receiverMu.Unlock()
		})
	}

	// Preserve messages that arrived between session creation and registration.
	for {
		select {
		case msg, ok := <-u.ReceiveCh:
			if !ok {
				unregister()
				return unregister, true
			}
			u.deliverMessage(msg)
		default:
			return unregister, true
		}
	}
}

func (u *udpConn) deliverMessage(msg *protocol.UDPMessage) bool {
	u.receiverMu.Lock()
	handler := u.receiver
	u.receiverMu.Unlock()
	if handler == nil {
		return false
	}
	u.receiveMu.Lock()
	msg = u.D.Feed(msg)
	u.receiveMu.Unlock()
	if msg == nil {
		return true
	}
	// Session target is constant; use the cached AddrPort instead of
	// re-parsing msg.Addr on every datagram. The release callback (if any)
	// returns the pooled datagram buffer once the consumer is done with it.
	packet := netproxy.NewReceivedPacket(msg.Data, u.targetAddr, nil, msg.Release)
	if handler(packet) {
		return true
	}
	packet.Release()
	return true
}

// queueIfNoReceiver queues a message only while the receiver state is held
// stable. A false result means the caller should retry transport delivery.
func (u *udpConn) queueIfNoReceiver(msg *protocol.UDPMessage) bool {
	u.receiverMu.Lock()
	defer u.receiverMu.Unlock()
	if u.receiver != nil {
		return false
	}
	select {
	case u.ReceiveCh <- msg:
	default:
		// Channel full, drop the message. Return the pooled datagram
		// buffer to quic-go now: nobody will ever consume it.
		if msg.Release != nil {
			msg.Release()
		}
	}
	return true
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
	u.stopDeadlineTimer()
	u.CloseFunc()
	return nil
}

func (u *udpConn) stopDeadlineTimer() {
	u.muTimer.Lock()
	defer u.muTimer.Unlock()
	if u.timer != nil {
		u.timer.Stop()
		u.timer = nil
	}
}

func (u *udpConn) SetDeadline(t time.Time) error {
	u.muTimer.Lock()
	defer u.muTimer.Unlock()
	if u.timer != nil {
		u.timer.Stop()
		u.timer = nil
	}
	if t.IsZero() {
		return nil
	}
	u.timer = time.AfterFunc(time.Until(t), func() {
		u.muTimer.Lock()
		u.timer = nil
		u.muTimer.Unlock()
		_ = u.Close()
	})
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

	closed    bool
	draining  bool
	onIdle    func()
	done      chan struct{}
	closeOnce sync.Once
}

// maxDemuxGoroutines caps how many receive goroutines may drain the shared
// datagram queue. Every goroutine parks on Receive most of the time, so the
// cap only guards against pathological GOMAXPROCS values (e.g. 64-core
// boxes); a handful of goroutines already removes the single-core ceiling.
const maxDemuxGoroutines = 8

func newUDPSessionManager(io udpIO) *udpSessionManager {
	m := &udpSessionManager{
		io:     io,
		m:      make(map[uint32]*udpConn),
		nextID: 1,
		done:   make(chan struct{}),
	}
	// Parallel demux: a single run() goroutine caps aggregate packet rate at
	// one core (parse + session lookup + defrag + consumer callback per
	// datagram). quic-go's datagramQueue.Receive is safe for concurrent use,
	// so run one loop per CPU (capped) and let consumers of different
	// sessions progress in parallel.
	n := runtime.GOMAXPROCS(0)
	if n > maxDemuxGoroutines {
		n = maxDemuxGoroutines
	}
	for range n {
		go func() { _ = m.run() }()
	}
	return m
}

func (m *udpSessionManager) run() error {
	defer m.closeOnce.Do(m.closeCleanup)
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
	var onIdle func()
	for _, conn := range m.m {
		if cb := m.closeLocked(conn); cb != nil {
			onIdle = cb
		}
	}
	if m.onIdle != nil {
		onIdle = m.onIdle
		m.onIdle = nil
	}
	m.closed = true
	close(m.done)
	m.mutex.Unlock()

	if onIdle != nil {
		onIdle()
	}
}

func (m *udpSessionManager) feed(msg *protocol.UDPMessage) {
	m.mutex.RLock()
	conn, ok := m.m[msg.SessionID]
	m.mutex.RUnlock()
	if !ok {
		// Ignore message from unknown session (e.g. arrived after cleanup).
		// Return its pooled datagram buffer to quic-go.
		if msg.Release != nil {
			msg.Release()
		}
		return
	}
	if conn.deliverMessage(msg) {
		return
	}

	for {
		// A receiver may be registered or unregistered concurrently with this
		// lookup. Recheck the session under the manager read lock before
		// touching ReceiveCh so closeLocked cannot race a channel send.
		m.mutex.RLock()
		if current, exists := m.m[msg.SessionID]; !exists || current != conn {
			m.mutex.RUnlock()
			return
		}
		if conn.queueIfNoReceiver(msg) {
			m.mutex.RUnlock()
			return
		}
		m.mutex.RUnlock()
		if conn.deliverMessage(msg) {
			return
		}
	}
}

// NewUDP creates a new UDP session.
func (m *udpSessionManager) NewUDP(addr string) (netproxy.Conn, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.closed || m.draining {
		return nil, coreErrs.ClosedError{}
	}

	id := m.nextID
	m.nextID++

	// Parse the session target once at creation. A hy2 UDP session is bound
	// to a single target address, so the parsed AddrPort is constant for the
	// session lifetime and can be handed to consumers directly, avoiding a
	// per-datagram ParseAddrPort on the receive hot path.
	targetAddr, err := netip.ParseAddrPort(addr)
	if err != nil {
		return nil, err
	}

	conn := &udpConn{
		ID:            id,
		D:             &frag.Defragger{},
		ReceiveCh:     make(chan *protocol.UDPMessage, udpMessageChanSize),
		SendBuf:       sendBufPool.Get().([]byte),
		SendFunc:      m.io.SendMessage,
		transportDone: m.done,

		writeMu:    sync.Mutex{},
		muTimer:    sync.Mutex{},
		target:     addr,
		targetAddr: targetAddr,
	}
	conn.CloseFunc = func() {
		m.close(conn)
	}
	m.m[id] = conn

	return conn, nil
}

func (m *udpSessionManager) close(conn *udpConn) {
	m.mutex.Lock()
	onIdle := m.closeLocked(conn)
	m.mutex.Unlock()

	if onIdle != nil {
		onIdle()
	}
}

func (m *udpSessionManager) closeLocked(conn *udpConn) func() {
	if conn == nil || conn.Closed {
		return nil
	}
	conn.Closed = true
	conn.receiverMu.Lock()
	conn.receiver = nil
	conn.receiverMu.Unlock()
	conn.stopDeadlineTimer()
	// Return any partially-reassembled fragments to the quic-go pool; the
	// session is dead and nobody will complete the reassembly. Take
	// receiveMu: concurrent deliverMessage/ReadFrom hold it around D.Feed,
	// and Defragger's state is not otherwise synchronized.
	conn.receiveMu.Lock()
	conn.D.Close()
	conn.receiveMu.Unlock()
	close(conn.ReceiveCh)
	delete(m.m, conn.ID)
	// Return the per-session send buffer to the pool for reuse by the next
	// session. Buffers are not shared while in use (one per udpConn), so
	// pooling them here is safe.
	sendBufPool.Put(conn.SendBuf)
	if m.draining && len(m.m) == 0 {
		onIdle := m.onIdle
		m.onIdle = nil
		return onIdle
	}
	return nil
}

func (m *udpSessionManager) closeWhenIdle(onIdle func()) bool {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.closed || len(m.m) == 0 {
		return true
	}
	m.draining = true
	m.onIdle = onIdle
	return false
}

func (m *udpSessionManager) Count() int {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return len(m.m)
}
