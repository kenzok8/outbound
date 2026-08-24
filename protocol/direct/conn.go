package direct

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/netproxy"
)

var resolveUDPAddr = common.ResolveUDPAddr

type directPacketConn struct {
	*net.UDPConn
	FullCone           bool
	dialTgt            string
	receiver           *packetReceiverRegistry
	receiverMu         sync.Mutex
	receiverStop       func()
	receiverGeneration uint64
	cachedDialTgt      atomic.Value // stores netip.AddrPort
	writeTgtCache      common.LastStringValue[netip.AddrPort]
	cacheOnce          sync.Once
	cacheMu            sync.Mutex // protects cacheErr
	cacheErr           error
	resolver           *net.Resolver
}

// Close unregisters the socket from the shared packet receiver before closing
// its underlying UDP descriptor.
func (c *directPacketConn) Close() error {
	c.stopPacketReceiver()
	if c.UDPConn == nil {
		return nil
	}
	return c.UDPConn.Close()
}

func (c *directPacketConn) stopPacketReceiver() {
	c.receiverMu.Lock()
	stop := c.receiverStop
	c.receiverStop = nil
	c.receiverMu.Unlock()
	if stop != nil {
		stop()
	}
}

func (c *directPacketConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	return c.ReadFromUDPAddrPort(p)
}

func (c *directPacketConn) WriteTo(b []byte, addr string) (int, error) {
	if !c.FullCone {
		// FIXME: check the addr
		return c.Write(b)
	}

	target, err := c.writeTargetAddrPort(addr)
	if err != nil {
		return 0, err
	}

	return c.WriteToUDPAddrPort(b, target)
}

func (c *directPacketConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error) {
	if !c.FullCone {
		n, err = c.Write(b)
		return n, 0, err
	}

	return c.UDPConn.WriteMsgUDP(b, oob, addr)
}

func (c *directPacketConn) WriteToUDP(b []byte, addr *net.UDPAddr) (int, error) {
	if !c.FullCone {
		return c.Write(b)
	}

	return c.UDPConn.WriteToUDP(b, addr)
}

// directBatchScratch holds reusable per-batch scratch storage for
// WriteBatch. Pooled because hot relays flush many batches per second and
// the msgs array plus the per-message iovec slice would otherwise be two
// heap allocations per datagram (the iovec literal escapes).
type directBatchScratch struct {
	msgs []ipv6.Message
	iovs [][]byte
}

var directBatchScratchPool = sync.Pool{
	New: func() any {
		return &directBatchScratch{
			msgs: make([]ipv6.Message, udpBatchScratchCapacity),
			iovs: make([][]byte, udpBatchScratchCapacity),
		}
	},
}

const udpBatchScratchCapacity = 32

// WriteBatch implements netproxy.PacketBatchWriter: several datagrams in one
// sendmmsg syscall. On a connected (non-FullCone) socket every datagram goes
// to the connected peer (Addr left nil); on a FullCone socket each item
// carries its own destination. Data slices must stay valid until return.
func (c *directPacketConn) WriteBatch(items []netproxy.BatchItem) (int, error) {
	if len(items) == 0 {
		return 0, nil
	}
	if len(items) > udpBatchScratchCapacity {
		// Oversized batch: allocate directly (rare).
		return c.writeBatchAlloc(items)
	}
	scratch := directBatchScratchPool.Get().(*directBatchScratch)
	defer directBatchScratchPool.Put(scratch)
	msgs := scratch.msgs[:len(items)]
	iovs := scratch.iovs[:len(items)]
	for i, it := range items {
		var addr net.Addr
		if c.FullCone {
			target, err := c.writeTargetAddrPort(it.Addr)
			if err != nil {
				// Nothing has been handed to sendmmsg yet, so n=0.
				return 0, err
			}
			addr = net.UDPAddrFromAddrPort(target)
		}
		iovs[i] = it.Data
		// Sub-slicing the pooled iovs array avoids the escaping literal.
		msgs[i] = ipv6.Message{Buffers: iovs[i : i+1], Addr: addr}
	}
	la := c.UDPConn.LocalAddr()
	if ua, ok := la.(*net.UDPAddr); ok && ua.IP.To4() != nil {
		return ipv4.NewPacketConn(c.UDPConn).WriteBatch(msgs, 0)
	}
	return ipv6.NewPacketConn(c.UDPConn).WriteBatch(msgs, 0)
}

func (c *directPacketConn) writeBatchAlloc(items []netproxy.BatchItem) (int, error) {
	msgs := make([]ipv6.Message, len(items))
	for i, it := range items {
		var addr net.Addr
		if c.FullCone {
			target, err := c.writeTargetAddrPort(it.Addr)
			if err != nil {
				// Nothing has been handed to sendmmsg yet, so n=0.
				return 0, err
			}
			addr = net.UDPAddrFromAddrPort(target)
		}
		msgs[i] = ipv6.Message{Buffers: [][]byte{it.Data}, Addr: addr}
	}
	la := c.UDPConn.LocalAddr()
	if ua, ok := la.(*net.UDPAddr); ok && ua.IP.To4() != nil {
		return ipv4.NewPacketConn(c.UDPConn).WriteBatch(msgs, 0)
	}
	return ipv6.NewPacketConn(c.UDPConn).WriteBatch(msgs, 0)
}

func (c *directPacketConn) resolveTarget() error {
	c.cacheOnce.Do(func() {
		ua, err := resolveUDPAddr(c.resolver, c.dialTgt)
		c.cacheMu.Lock()
		if err != nil {
			c.cacheErr = err
			c.cacheMu.Unlock()
			return
		}
		// Store the value directly, not a pointer to a stack variable.
		// atomic.Value stores the value on heap, ensuring memory safety.
		ap := ua.AddrPort()
		c.cachedDialTgt.Store(ap)
		c.cacheMu.Unlock()
	})
	c.cacheMu.Lock()
	err := c.cacheErr
	c.cacheMu.Unlock()
	return err
}

func (c *directPacketConn) writeTargetAddrPort(addr string) (netip.AddrPort, error) {
	if addr == c.dialTgt {
		if c.cachedDialTgt.Load() == nil {
			if err := c.resolveTarget(); err != nil {
				return netip.AddrPort{}, err
			}
		}
		return c.cachedDialTgt.Load().(netip.AddrPort), nil
	}
	if cached, ok := c.writeTgtCache.Load(addr); ok {
		return cached, nil
	}
	uAddr, err := resolveUDPAddr(c.resolver, addr)
	if err != nil {
		return netip.AddrPort{}, err
	}
	target := uAddr.AddrPort()
	c.writeTgtCache.Store(addr, target)
	return target, nil
}

func (c *directPacketConn) Write(b []byte) (int, error) {
	if !c.FullCone {
		return c.UDPConn.Write(b)
	}

	// Lazy target resolution with thread-safe initialization.
	// Thread-safety guarantees:
	// 1. sync.Once in resolveTarget() provides happens-before relationship
	// 2. atomic.Value.Load/Store provides atomic access to the cached value
	// 3. The netip.AddrPort value is stored directly in atomic.Value (heap-allocated)
	if c.cachedDialTgt.Load() == nil {
		if err := c.resolveTarget(); err != nil {
			return 0, err
		}
	}

	// No lock needed: Go's net.UDPConn.WriteToUDPAddrPort() is thread-safe.
	// From Go's net package documentation:
	// "Multiple goroutines may invoke methods on a PacketConn simultaneously."
	cached := c.cachedDialTgt.Load().(netip.AddrPort)
	return c.WriteToUDPAddrPort(b, cached)
}

func (c *directPacketConn) Read(b []byte) (int, error) {
	if !c.FullCone {
		return c.UDPConn.Read(b)
	}
	n, _, err := c.UDPConn.ReadFrom(b)
	return n, err
}

var _ interface {
	SyscallConn() (syscall.RawConn, error)
	SetReadBuffer(int) error
	ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error)
	WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error)
} = &directPacketConn{}
