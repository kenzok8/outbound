package frag

import (
	"sync/atomic"
	"testing"

	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/protocol"
)

// releaseTrackingMessage wraps a UDPMessage with a release counter so tests
// can verify pooled buffers are returned exactly once per lifecycle.
func releaseTrackingMessage(m *protocol.UDPMessage, counter *atomic.Int32) *protocol.UDPMessage {
	m.Release = func() { counter.Add(1) }
	return m
}

// TestDefraggerReleaseExactlyOnce verifies that reassembling a fragmented
// message releases every fragment buffer exactly once, and that the returned
// message carries no stale Release (its payload was freshly allocated, not
// pooled). Without the Release=nil fix, the caller's own Release call would
// return the same buffer a second time, handing one pooled buffer to two
// consumers.
func TestDefraggerReleaseExactlyOnce(t *testing.T) {
	var released atomic.Int32
	d := &Defragger{}

	frag0 := releaseTrackingMessage(&protocol.UDPMessage{
		SessionID: 7, PacketID: 42, FragID: 0, FragCount: 2,
		Addr: "1.2.3.4:5", Data: []byte("hello "),
	}, &released)
	frag1 := releaseTrackingMessage(&protocol.UDPMessage{
		SessionID: 7, PacketID: 42, FragID: 1, FragCount: 2,
		Addr: "1.2.3.4:5", Data: []byte("world"),
	}, &released)

	if got := d.Feed(frag0); got != nil {
		t.Fatalf("Feed(0/2) = %v, want nil", got)
	}
	if released.Load() != 0 {
		t.Fatalf("releases after partial feed = %d, want 0", released.Load())
	}

	got := d.Feed(frag1)
	if got == nil {
		t.Fatal("Feed(1/2) = nil, want assembled message")
	}
	// All three buffer lifecycles closed: frag0, frag1 (releaseAll covers
	// both), and the returned message must NOT carry a Release that would
	// release frag1 a second time.
	if released.Load() != 2 {
		t.Fatalf("releases after reassembly = %d, want 2 (frag0+frag1)", released.Load())
	}
	if got.Release != nil {
		t.Fatal("assembled message still carries a Release: double-release would corrupt the pool")
	}
	if string(got.Data) != "hello world" {
		t.Fatalf("assembled data = %q, want %q", got.Data, "hello world")
	}

	// Caller-side pattern (`if dfMsg.Release != nil { dfMsg.Release() }`):
	// with the fix the assembled message carries no Release, so this is a
	// no-op; if a stale Release survived, it would double-return frag1's
	// buffer and bump the counter to 3.
	if got.Release != nil {
		got.Release()
	}
	if released.Load() != 2 {
		t.Fatalf("caller release bumped counter to %d, want 2 (stale Release leaked)", released.Load())
	}
}

// TestDefraggerReleaseOnSupercede verifies that when a new fragmented message
// arrives before the previous one is complete, the superseded fragments are
// released (not leaked).
func TestDefraggerReleaseOnSupercede(t *testing.T) {
	var released atomic.Int32
	d := &Defragger{}

	old1 := releaseTrackingMessage(&protocol.UDPMessage{
		SessionID: 7, PacketID: 1, FragID: 0, FragCount: 3,
		Addr: "1.2.3.4:5", Data: []byte("aaa"),
	}, &released)
	old2 := releaseTrackingMessage(&protocol.UDPMessage{
		SessionID: 7, PacketID: 1, FragID: 1, FragCount: 3,
		Addr: "1.2.3.4:5", Data: []byte("bbb"),
	}, &released)

	d.Feed(old1)
	d.Feed(old2)
	if released.Load() != 0 {
		t.Fatalf("releases before supercede = %d, want 0", released.Load())
	}

	// New packet ID supersedes the incomplete message: old fragments released.
	new1 := releaseTrackingMessage(&protocol.UDPMessage{
		SessionID: 7, PacketID: 2, FragID: 0, FragCount: 2,
		Addr: "1.2.3.4:5", Data: []byte("xx"),
	}, &released)
	d.Feed(new1)
	if released.Load() != 2 {
		t.Fatalf("releases after supercede = %d, want 2 (old1+old2)", released.Load())
	}
}

// TestDefraggerReleaseOnClose verifies Close() returns incomplete fragments.
func TestDefraggerReleaseOnClose(t *testing.T) {
	var released atomic.Int32
	d := &Defragger{}

	frag := releaseTrackingMessage(&protocol.UDPMessage{
		SessionID: 7, PacketID: 9, FragID: 0, FragCount: 4,
		Addr: "1.2.3.4:5", Data: []byte("partial"),
	}, &released)
	d.Feed(frag)
	if released.Load() != 0 {
		t.Fatalf("releases before close = %d, want 0", released.Load())
	}

	d.Close()
	if released.Load() != 1 {
		t.Fatalf("releases after close = %d, want 1", released.Load())
	}
}

// TestDefraggerReleaseInvalidFragment verifies the invalid-fragment path
// releases immediately.
func TestDefraggerReleaseInvalidFragment(t *testing.T) {
	var released atomic.Int32
	d := &Defragger{}

	frag := releaseTrackingMessage(&protocol.UDPMessage{
		SessionID: 7, PacketID: 9, FragID: 88, FragCount: 2,
		Addr: "1.2.3.4:5", Data: []byte("garbage"),
	}, &released)
	if got := d.Feed(frag); got != nil {
		t.Fatalf("Feed(invalid) = %v, want nil", got)
	}
	if released.Load() != 1 {
		t.Fatalf("releases after invalid frag = %d, want 1", released.Load())
	}
}
