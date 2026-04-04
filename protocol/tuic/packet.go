package tuic

import (
	"container/list"
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	outboundcommon "github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/tuic/common"
	"github.com/olicesx/quic-go"
)

type Packets struct {
	mu               sync.Mutex
	list             *list.List
	isEmptyState     context.Context
	cancelEmptyState func()
	closed           atomic.Bool
}

func NewPackets() *Packets {
	ctx, cancel := context.WithCancel(context.Background())
	return &Packets{
		mu:               sync.Mutex{},
		list:             list.New().Init(),
		isEmptyState:     ctx,
		cancelEmptyState: cancel,
	}
}

func (p *Packets) PushBack(packet *Packet) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed.Load() {
		return
	}
	p.list.PushBack(packet)
	select {
	case <-p.isEmptyState.Done():
	default:
		p.cancelEmptyState()
	}
}

func (p *Packets) PopFrontBlock() (packet *Packet, closed bool) {
	<-p.isEmptyState.Done()
	if p.closed.Load() {
		return nil, true
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	packet = p.list.Remove(p.list.Front()).(*Packet)
	if p.list.Len() == 0 {
		p.setEmpty()
	}
	return packet, false
}

func (p *Packets) setEmpty() {
	p.isEmptyState, p.cancelEmptyState = context.WithCancel(context.Background())
}

func (p *Packets) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed.Load() {
		return nil
	}
	p.closed.Store(true)
	p.list.Init()
	select {
	case <-p.isEmptyState.Done():
	default:
		p.cancelEmptyState()
	}
	return nil
}

type quicStreamPacketConn struct {
	mu sync.Mutex

	target string
	addr   outboundcommon.LastStringValue[protocol.Metadata]

	connId          uint16
	quicConn        quic.Connection
	incomingPackets *Packets

	udpRelayMode          common.UdpRelayMode
	maxUdpRelayPacketSize int

	deferQuicConnFn func(quicConn quic.Connection, err error)
	closeDeferFn    func()

	closeOnce sync.Once
	closeErr  error
	closed    atomic.Bool

	deFraggers sync.Map

	lastDeFraggerCleanupNano atomic.Int64

	muTimer       sync.Mutex
	deadlineTimer *time.Timer
}

var deFraggerIdleTimeout = 30 * time.Second

var deFraggerCleanupInterval = 5 * time.Second

var parseMetadata = protocol.ParseMetadata

type deFraggerBucket struct {
	mu         sync.Mutex
	deFraggers []*deFragger
}

func (b *deFraggerBucket) len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.deFraggers)
}

func (b *deFraggerBucket) removeAt(index int) {
	if index < 0 || index >= len(b.deFraggers) {
		return
	}
	last := len(b.deFraggers) - 1
	b.deFraggers[index] = b.deFraggers[last]
	b.deFraggers[last] = nil
	b.deFraggers = b.deFraggers[:last]
}

func (b *deFraggerBucket) pruneExpired(nowNano int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if deFraggerIdleTimeout <= 0 {
		return
	}
	dst := b.deFraggers[:0]
	for _, d := range b.deFraggers {
		if d == nil || d.IsExpired(nowNano, deFraggerIdleTimeout) {
			continue
		}
		dst = append(dst, d)
	}
	for i := len(dst); i < len(b.deFraggers); i++ {
		b.deFraggers[i] = nil
	}
	b.deFraggers = dst
}

func (b *deFraggerBucket) feed(packet *Packet, p []byte, nowNano int64) (n int, addr netip.AddrPort, assembled bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	var candidates []int
	for i, d := range b.deFraggers {
		if d != nil && d.matches(packet) {
			candidates = append(candidates, i)
		}
	}

	selectedIndex := -1
	switch len(candidates) {
	case 0:
		b.deFraggers = append(b.deFraggers, newDeFragger(nowNano))
		selectedIndex = len(b.deFraggers) - 1
	case 1:
		selectedIndex = candidates[0]
	default:
		if packet.FRAG_ID == 0 {
			addrPort := packetFragmentAddrPort(packet)
			for _, idx := range candidates {
				if d := b.deFraggers[idx]; d != nil && d.hasFirstFrag && d.firstAddrPort == addrPort {
					selectedIndex = idx
					break
				}
			}
			if selectedIndex == -1 {
				for _, idx := range candidates {
					if d := b.deFraggers[idx]; d != nil && !d.hasFirstFrag {
						selectedIndex = idx
						break
					}
				}
			}
			if selectedIndex == -1 {
				b.deFraggers = append(b.deFraggers, newDeFragger(nowNano))
				selectedIndex = len(b.deFraggers) - 1
			}
		} else {
			// The protocol only carries a 16-bit packet ID on non-first fragments.
			// If multiple in-flight fragment sets remain compatible, routing this
			// fragment is ambiguous. Drop it rather than corrupt another payload.
			for _, idx := range candidates {
				if d := b.deFraggers[idx]; d != nil && d.hasFirstFrag {
					if selectedIndex != -1 {
						return 0, netip.AddrPort{}, false
					}
					selectedIndex = idx
				}
			}
			if selectedIndex == -1 {
				return 0, netip.AddrPort{}, false
			}
		}
	}

	d := b.deFraggers[selectedIndex]
	if d == nil {
		return 0, netip.AddrPort{}, false
	}
	n, addr, assembled = d.Feed(packet, p, nowNano)
	if assembled {
		b.removeAt(selectedIndex)
	}
	return n, addr, assembled
}

func (q *quicStreamPacketConn) Close() error {
	q.closeOnce.Do(func() {
		q.closed.Store(true)
		q.closeErr = q.close()
	})
	return q.closeErr
}

func (q *quicStreamPacketConn) close() (err error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closeDeferFn != nil {
		defer q.closeDeferFn()
	}
	if q.deferQuicConnFn != nil {
		defer func() {
			q.deferQuicConnFn(q.quicConn, err)
		}()
	}
	incomingPackets := q.incomingPackets
	q.incomingPackets = nil
	if incomingPackets != nil {
		_ = incomingPackets.Close()
	}
	q.clearDeFraggers()
	if incomingPackets != nil && q.quicConn != nil {

		buf := pool.GetBuffer()
		defer pool.PutBuffer(buf)
		err = NewDissociate(q.connId, Ver5).WriteTo(buf)
		if err != nil {
			return
		}
		var stream quic.SendStream
		stream, err = q.quicConn.OpenUniStream()
		if err != nil {
			return
		}
		_, err = buf.WriteTo(stream)
		if err != nil {
			return
		}
		err = stream.Close()
		if err != nil {
			return
		}
	}
	return
}

func (q *quicStreamPacketConn) clearDeFraggers() {
	q.deFraggers.Range(func(key, value any) bool {
		q.deFraggers.Delete(key)
		return true
	})
}

func (q *quicStreamPacketConn) maybeCleanupDeFraggers(nowNano int64) {
	if deFraggerIdleTimeout <= 0 {
		return
	}
	lastCleanupNano := q.lastDeFraggerCleanupNano.Load()
	if lastCleanupNano != 0 && nowNano-lastCleanupNano < deFraggerCleanupInterval.Nanoseconds() {
		return
	}
	if !q.lastDeFraggerCleanupNano.CompareAndSwap(lastCleanupNano, nowNano) {
		return
	}
	q.deFraggers.Range(func(key, value any) bool {
		bucket := value.(*deFraggerBucket)
		bucket.pruneExpired(nowNano)
		if bucket.len() == 0 {
			q.deFraggers.CompareAndDelete(key, bucket)
		}
		return true
	})
}

func (q *quicStreamPacketConn) SetDeadline(t time.Time) error {
	q.muTimer.Lock()
	defer q.muTimer.Unlock()
	dur := time.Until(t)
	if q.deadlineTimer != nil {
		q.deadlineTimer.Reset(dur)
	} else {
		q.deadlineTimer = time.AfterFunc(dur, func() {
			q.muTimer.Lock()
			defer q.muTimer.Unlock()
			_ = q.Close()
			q.deadlineTimer = nil
		})
	}
	return nil
}

func (q *quicStreamPacketConn) SetReadDeadline(t time.Time) error {
	// FIXME: Single direction.
	return q.SetDeadline(t)
}

func (q *quicStreamPacketConn) SetWriteDeadline(t time.Time) error {
	// FIXME: Single direction.
	return q.SetDeadline(t)
}

func (q *quicStreamPacketConn) ReadFrom(p []byte) (n int, addr netip.AddrPort, err error) {
	q.mu.Lock()
	incomingPackets := q.incomingPackets
	q.mu.Unlock()

	if incomingPackets == nil {
		return 0, netip.AddrPort{}, net.ErrClosed
	}

	for {
		packet, closed := incomingPackets.PopFrontBlock()
		if closed {
			err = net.ErrClosed
			return
		}
		if packet.FRAG_TOTAL <= 1 {
			return copy(p, packet.DATA), packet.ADDR.UDPAddr().AddrPort(), nil
		}
		nowNano := time.Now().UnixNano()
		q.maybeCleanupDeFraggers(nowNano)
		bucketAny, _ := q.deFraggers.LoadOrStore(packet.PKT_ID, &deFraggerBucket{})
		bucket := bucketAny.(*deFraggerBucket)
		var assembled bool
		if n, addr, assembled = bucket.feed(packet, p, nowNano); assembled {
			if bucket.len() == 0 {
				q.deFraggers.CompareAndDelete(packet.PKT_ID, bucket)
			}
			return
		}
	}
}

func (q *quicStreamPacketConn) WriteTo(p []byte, addr string) (n int, err error) {
	if len(p) > 0xffff { // uint16 max
		return 0, &quic.DatagramTooLargeError{MaxDataLen: 0xffff}
	}
	if q.closed.Load() {
		return 0, net.ErrClosed
	}
	if q.deferQuicConnFn != nil {
		defer func() {
			q.deferQuicConnFn(q.quicConn, err)
		}()
	}
	buf := pool.GetBuffer()
	defer pool.PutBuffer(buf)
	mdata, err := q.metadataForAddr(addr)
	if err != nil {
		return 0, err
	}
	address := NewAddress(&mdata)
	pktId := uint16(fastrand.Uint32())
	packet := NewPacket(q.connId, pktId, 1, 0, uint16(len(p)), address, p, Ver5)
	switch q.udpRelayMode {
	case common.QUIC:
		err = packet.WriteTo(buf)
		if err != nil {
			return
		}
		var stream quic.SendStream
		stream, err = q.quicConn.OpenUniStream()
		if err != nil {
			return
		}
		defer func() { _ = stream.Close() }()
		_, err = buf.WriteTo(stream)
		if err != nil {
			return
		}
	default: // native
		if len(p) > q.maxUdpRelayPacketSize {
			err = fragWriteNative(q.quicConn, packet, buf, q.maxUdpRelayPacketSize)
			if err != nil {
				return
			}
		} else {
			err = packet.WriteTo(buf)
			if err != nil {
				return
			}
			data := buf.Bytes()
			err = q.quicConn.SendDatagram(data)
		}
		var tooLarge *quic.DatagramTooLargeError
		if errors.As(err, &tooLarge) {
			err = fragWriteNative(q.quicConn, packet, buf, int(tooLarge.MaxDataLen)-PacketOverHead)
		}
		if err != nil {
			return
		}
	}
	n = len(p)

	return
}

func (q *quicStreamPacketConn) metadataForAddr(addr string) (protocol.Metadata, error) {
	if cached, ok := q.addr.Load(addr); ok {
		return cached, nil
	}
	mdata, err := parseMetadata(addr)
	if err != nil {
		return protocol.Metadata{}, err
	}
	q.addr.Store(addr, mdata)
	return mdata, nil
}

func (q *quicStreamPacketConn) LocalAddr() net.Addr {
	return q.quicConn.LocalAddr()
}

func (conn *quicStreamPacketConn) Read(b []byte) (n int, err error) {
	n, _, err = conn.ReadFrom(b)
	return n, err
}

func (conn *quicStreamPacketConn) Write(b []byte) (n int, err error) {
	return conn.WriteTo(b, conn.target)
}

var _ netproxy.PacketConn = (*quicStreamPacketConn)(nil)

// TransportDone implements netproxy.TransportLifecycle.
// The returned channel is closed when the QUIC transport backing this
// UDP session is permanently dead.
func (q *quicStreamPacketConn) TransportDone() <-chan struct{} {
	if q.quicConn == nil {
		return make(chan struct{})
	}
	return q.quicConn.Context().Done()
}
