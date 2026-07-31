package client

import (
	"net/netip"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/frag"
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/protocol"
)

func mustAddrPort(s string) netip.AddrPort {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		panic(err)
	}
	return ap
}

// BenchmarkNewUDP measures session creation cost (SendBuf pool + AddrPort
// parse-once). Compared against the pre-change make([]byte) per session.
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

// BenchmarkDeliverMessage measures the hot path: datagram -> session -> handler.
// Covers targetAddr caching (no ParseAddrPort) and Release callback wiring.
func BenchmarkDeliverMessage(b *testing.B) {
	target := "203.0.113.10:443"
	u := &udpConn{
		ID:         1,
		D:          &frag.Defragger{},
		ReceiveCh:  make(chan *protocol.UDPMessage, udpMessageChanSize),
		SendBuf:    sendBufPool.Get().([]byte),
		target:     target,
		targetAddr: mustAddrPort(target),
	}
	defer sendBufPool.Put(u.SendBuf)

	msg := &protocol.UDPMessage{
		SessionID: 1,
		FragCount: 1,
		Addr:      target,
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
