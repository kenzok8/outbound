package client

import (
	"net/netip"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/frag"
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/protocol"
)

// BenchmarkNewUDP measures session creation cost, including default target
// validation and reuse of the pooled send buffer.
func BenchmarkNewUDP(b *testing.B) {
	m := &udpSessionManager{
		io:     noopUDPTestIO{},
		m:      make(map[uint32]*udpConn),
		nextID: 1,
		done:   make(chan struct{}),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn, err := m.NewUDP("203.0.113.10:443")
		if err != nil {
			b.Fatal(err)
		}
		// simulate session teardown returning the buffer to the pool
		m.close(conn.(*udpConn))
	}
}

// BenchmarkDeliverMessage measures delivery through the cached default-target
// address path.
func BenchmarkDeliverMessage(b *testing.B) {
	benchmarkDeliverMessage(b, "203.0.113.10:443")
}

// BenchmarkDeliverMessageAlternateTarget measures delivery through the
// per-datagram address parsing path used by multi-target sessions.
func BenchmarkDeliverMessageAlternateTarget(b *testing.B) {
	benchmarkDeliverMessage(b, "198.51.100.20:8443")
}

func benchmarkDeliverMessage(b *testing.B, messageAddr string) {
	target := "203.0.113.10:443"
	u := &udpConn{
		ID:                1,
		D:                 &frag.Defragger{},
		ReceiveCh:         make(chan *protocol.UDPMessage, udpMessageChanSize),
		SendBuf:           sendBufPool.Get().([]byte),
		target:            target,
		defaultTargetAddr: netip.MustParseAddrPort(target),
	}
	defer sendBufPool.Put(u.SendBuf)

	msg := &protocol.UDPMessage{
		SessionID: 1,
		FragCount: 1,
		Addr:      messageAddr,
		Data:      make([]byte, 1200),
	}

	var handlerFn netproxy.PacketReceiveHandler = func(*netproxy.ReceivedPacket) bool {
		return true // accept and immediately release
	}
	u.RegisterPacketReceiver(handlerFn)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !u.deliverMessage(msg) {
			b.Fatal("deliverMessage should accept")
		}
	}
}
