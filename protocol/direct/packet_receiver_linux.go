//go:build linux

package direct

import (
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"golang.org/x/sys/unix"
)

const (
	directPacketReceiverBufferSize = 65535
	// Small tier matching dae-side ingress buffers (the EthernetMtu / 2 KiB
	// bucket): the overwhelming majority of proxy replies fit well under
	// 2 KiB, and a 256-deep reply queue of 64 KiB buffers can pin ~16 MiB.
	directPacketReceiverSmallBufferSize = 2048
	directPacketReceiverBatchSize       = 64
)

// packetReceiverRegistry multiplexes direct UDP sockets through one Linux
// epoll reader. The socket itself remains owned by its logical PacketConn;
// only packet readiness and delivery are shared.
type packetReceiverRegistry struct {
	mu      sync.RWMutex
	started bool
	epollFD int
	entries map[int]*directPacketReceiverEntry
}

type directPacketReceiverEntry struct {
	fd      int
	handler netproxy.PacketReceiveHandler
	active  atomic.Bool
	// needBigBuffers flips on the first datagram that exceeded the small
	// tier (observed via MSG_TRUNC) and switches the entry to full-size
	// buffers from then on.
	needBigBuffers atomic.Bool
}

var defaultPacketReceiverRegistry = &packetReceiverRegistry{}

func newPacketReceiverRegistry() *packetReceiverRegistry {
	return defaultPacketReceiverRegistry
}

// RegisterPacketReceiver delivers direct UDP datagrams through the shared
// Linux epoll reader instead of starting one blocking reader per socket.
func (c *directPacketConn) RegisterPacketReceiver(handler netproxy.PacketReceiveHandler) (func(), bool) {
	if c == nil || c.receiver == nil || handler == nil || c.UDPConn == nil {
		return nil, false
	}

	c.receiverMu.Lock()
	if c.receiverStop != nil {
		c.receiverMu.Unlock()
		return nil, false
	}
	c.receiverGeneration++
	generation := c.receiverGeneration
	entry := &directPacketReceiverEntry{handler: handler}
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			entry.active.Store(false)
			c.receiver.unregister(entry)
			c.receiverMu.Lock()
			if c.receiverGeneration == generation {
				c.receiverStop = nil
			}
			c.receiverMu.Unlock()
		})
	}
	c.receiverStop = stop
	if !c.receiver.register(c, entry) {
		c.receiverStop = nil
		c.receiverMu.Unlock()
		return nil, false
	}
	c.receiverMu.Unlock()
	return stop, true
}

func (r *packetReceiverRegistry) register(conn *directPacketConn, entry *directPacketReceiverEntry) bool {
	if conn == nil || entry == nil || entry.handler == nil {
		return false
	}
	fd, err := directPacketReceiverFD(conn)
	if err != nil {
		return false
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.ensureStartedLocked() {
		return false
	}
	if _, exists := r.entries[fd]; exists {
		return false
	}
	entry.fd = fd
	entry.active.Store(true)
	r.entries[fd] = entry
	event := &unix.EpollEvent{
		Events: unix.EPOLLIN | unix.EPOLLERR | unix.EPOLLHUP,
		Fd:     int32(fd),
	}
	if err := unix.EpollCtl(r.epollFD, unix.EPOLL_CTL_ADD, fd, event); err != nil {
		delete(r.entries, fd)
		entry.active.Store(false)
		return false
	}
	return true
}

func (r *packetReceiverRegistry) unregister(entry *directPacketReceiverEntry) {
	if r == nil || entry == nil {
		return
	}
	entry.active.Store(false)
	r.mu.Lock()
	if current, ok := r.entries[entry.fd]; ok && current == entry {
		delete(r.entries, entry.fd)
		if r.started {
			_ = unix.EpollCtl(r.epollFD, unix.EPOLL_CTL_DEL, entry.fd, nil)
		}
	}
	r.mu.Unlock()
}

func (r *packetReceiverRegistry) ensureStartedLocked() bool {
	if r.started {
		return r.epollFD >= 0
	}
	epollFD, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return false
	}
	r.started = true
	r.epollFD = epollFD
	r.entries = make(map[int]*directPacketReceiverEntry)
	go r.loop(epollFD)
	return true
}

func (r *packetReceiverRegistry) loop(epollFD int) {
	events := make([]unix.EpollEvent, 64)
	for {
		n, err := unix.EpollWait(epollFD, events, -1)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return
		}
		for i := 0; i < n; i++ {
			fd := int(events[i].Fd)
			r.mu.RLock()
			entry := r.entries[fd]
			r.mu.RUnlock()
			if entry != nil {
				r.drain(entry)
			}
		}
	}
}

func (r *packetReceiverRegistry) drain(entry *directPacketReceiverEntry) {
	for range directPacketReceiverBatchSize {
		if !entry.active.Load() {
			return
		}
		bufSize := directPacketReceiverSmallBufferSize
		if entry.needBigBuffers.Load() {
			bufSize = directPacketReceiverBufferSize
		}
		buf := pool.GetFullCap(bufSize)
		// MSG_TRUNC makes Recvfrom return the real datagram length even
		// when it exceeded the buffer, which is how oversize traffic is
		// detected on the small tier.
		n, sockaddr, err := unix.Recvfrom(entry.fd, buf, unix.MSG_DONTWAIT|unix.MSG_TRUNC)
		if err != nil {
			pool.Put(buf)
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == unix.EINTR {
				if err == unix.EINTR {
					continue
				}
				return
			}
			r.deliverError(entry, err)
			return
		}
		if n > len(buf) {
			// Real size (via MSG_TRUNC) exceeded the small tier: this one
			// datagram is lost; upgrade the entry so the rest of the burst
			// survives on full-size buffers.
			entry.needBigBuffers.Store(true)
			pool.Put(buf)
			continue
		}

		from, ok := directPacketReceiverAddrPort(sockaddr)
		if !ok {
			pool.Put(buf)
			r.deliverError(entry, fmt.Errorf("unsupported direct UDP peer address %T", sockaddr))
			return
		}
		packet := netproxy.NewReceivedPacket(buf[:n], from, nil, func() {
			pool.Put(buf)
		})
		if !entry.active.Load() || !entry.handler(packet) {
			packet.Release()
		}
	}
}

func (r *packetReceiverRegistry) deliverError(entry *directPacketReceiverEntry, err error) {
	if !entry.active.Load() {
		return
	}
	packet := netproxy.NewReceivedPacket(nil, netip.AddrPort{}, err, nil)
	if !entry.handler(packet) {
		packet.Release()
	}
}

func directPacketReceiverFD(conn *directPacketConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return -1, err
	}
	fd := -1
	if err := raw.Control(func(rawFD uintptr) {
		fd = int(rawFD)
	}); err != nil {
		return -1, err
	}
	if fd < 0 {
		return -1, fmt.Errorf("invalid direct UDP socket descriptor")
	}
	return fd, nil
}

func directPacketReceiverAddrPort(sockaddr unix.Sockaddr) (netip.AddrPort, bool) {
	switch addr := sockaddr.(type) {
	case *unix.SockaddrInet4:
		return netip.AddrPortFrom(netip.AddrFrom4(addr.Addr), uint16(addr.Port)), true
	case *unix.SockaddrInet6:
		return netip.AddrPortFrom(netip.AddrFrom16(addr.Addr), uint16(addr.Port)), true
	default:
		return netip.AddrPort{}, false
	}
}
