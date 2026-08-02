package tuic

import (
	"bytes"
	"net/netip"
	"runtime"
	"testing"
)

// TestTuicUnfragmentedDataPooled guards the DATA pool optimization: for
// unfragmented packets, B/op must stay flat across payload sizes because DATA
// is recycled via releaseData. If the pool path regresses (make per packet),
// large-payload B/op grows roughly with the payload.
func TestTuicUnfragmentedDataPooled(t *testing.T) {
	bop := func(dataSize int) int {
		addr := NewAddressAddrPort(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 8080))
		data := make([]byte, dataSize)
		pkt := NewPacket(1, 1, 1, 0, uint16(len(data)), addr, data, Ver5)
		var buf bytes.Buffer
		if err := pkt.WriteTo(&buf); err != nil {
			t.Fatalf("WriteTo: %v", err)
		}
		msg := buf.Bytes()

		const runs = 200
		var m1, m2 runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&m1)
		for i := 0; i < runs; i++ {
			p, err := readPacketFromMessage(msg)
			if err != nil {
				t.Fatalf("readPacketFromMessage: %v", err)
			}
			p.releaseData()
		}
		runtime.ReadMemStats(&m2)
		return int(m2.TotalAlloc-m1.TotalAlloc) / runs
	}

	small := bop(64)
	large := bop(4096)
	// Flat (~144 B/op) when pooled; large scales with payload (~4 KB+) when not.
	if large > small*4 {
		t.Fatalf("tuic unfragmented DATA not pooled: small=%d large=%d B/op "+
			"(large should stay flat, not scale with payload)", small, large)
	}
}
