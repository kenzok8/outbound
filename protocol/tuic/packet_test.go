package tuic

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func countDeFraggers(q *quicStreamPacketConn) int {
	count := 0
	q.deFraggers.Range(func(_, value any) bool {
		count += value.(*deFraggerBucket).len()
		return true
	})
	return count
}

func TestReadFromNoDeadlock(t *testing.T) {
	packets := NewPackets()
	q := &quicStreamPacketConn{
		incomingPackets: packets,
	}

	var wg sync.WaitGroup
	wg.Add(2)

	readDone := make(chan struct{})
	go func() {
		defer wg.Done()
		defer close(readDone)
		_, _, _ = q.ReadFrom(make([]byte, 1024))
	}()

	time.Sleep(100 * time.Millisecond)

	go func() {
		defer wg.Done()
		_ = packets.Close()
	}()

	select {
	case <-readDone:
		t.Log("ReadFrom unblocked successfully - no deadlock")
	case <-time.After(2 * time.Second):
		t.Fatal("ReadFrom deadlocked - Close() could not unblock it")
	}

	wg.Wait()
}

func TestReadFromReturnsNilAfterClose(t *testing.T) {
	packets := NewPackets()
	q := &quicStreamPacketConn{
		incomingPackets: packets,
	}

	_ = packets.Close()

	_, _, err := q.ReadFrom(make([]byte, 1024))
	if err == nil {
		t.Error("expected error after close, got nil")
	}
}

func TestPacketsCloseUnblocksPopFrontBlock(t *testing.T) {
	p := NewPackets()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = p.PopFrontBlock()
	}()

	time.Sleep(50 * time.Millisecond)
	_ = p.Close()

	select {
	case <-done:
		t.Log("PopFrontBlock unblocked after Close")
	case <-time.After(1 * time.Second):
		t.Fatal("PopFrontBlock did not unblock after Close")
	}
}

func TestPacketsPushPop(t *testing.T) {
	p := NewPackets()

	go func() {
		time.Sleep(50 * time.Millisecond)
		p.PushBack(&Packet{
			PKT_ID:     1,
			FRAG_ID:    0,
			FRAG_TOTAL: 1,
			DATA:       []byte("test data"),
			ADDR:       &Address{TYPE: AtypIPv4, ADDR: []byte{127, 0, 0, 1}, PORT: 8080},
		})
	}()

	packet, closed := p.PopFrontBlock()
	if closed {
		t.Fatal("expected packet, got closed")
	}
	if packet == nil {
		t.Fatal("expected non-nil packet")
	}
	if string(packet.DATA) != "test data" {
		t.Errorf("expected 'test data', got '%s'", packet.DATA)
	}
	_ = p.Close()
}

func TestConcurrentPushClose(t *testing.T) {
	p := NewPackets()

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.PushBack(&Packet{DATA: []byte("test")})
		}()
	}

	time.Sleep(10 * time.Millisecond)
	_ = p.Close()

	wg.Wait()
	_, closed := p.PopFrontBlock()
	if !closed {
		t.Error("expected closed after Close")
	}
}

func TestQuicStreamPacketConnWriteToAfterClose(t *testing.T) {
	q := &quicStreamPacketConn{}

	if err := q.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	if _, err := q.WriteTo([]byte("test"), "127.0.0.1:53"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected net.ErrClosed after Close, got %v", err)
	}
}

func TestQuicStreamPacketConnCloseUnblocksReadFrom(t *testing.T) {
	packets := NewPackets()
	closeDone := make(chan struct{})
	q := &quicStreamPacketConn{
		incomingPackets: packets,
		closeDeferFn: func() {
			close(closeDone)
		},
	}

	readErr := make(chan error, 1)
	go func() {
		_, _, err := q.ReadFrom(make([]byte, 1024))
		readErr <- err
	}()

	time.Sleep(50 * time.Millisecond)

	if err := q.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	select {
	case err := <-readErr:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("expected net.ErrClosed from ReadFrom after Close, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReadFrom did not unblock after quicStreamPacketConn.Close")
	}

	select {
	case <-closeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("closeDeferFn was not called")
	}
}

func TestPacketsPushBackAfterCloseIsIgnored(t *testing.T) {
	p := NewPackets()
	if err := p.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	p.PushBack(&Packet{DATA: []byte("test")})

	if got := p.list.Len(); got != 0 {
		t.Fatalf("closed packet queue length = %d, want 0", got)
	}
}

func TestQuicStreamPacketConnPrunesExpiredDeFraggers(t *testing.T) {
	oldIdleTimeout := deFraggerIdleTimeout
	oldCleanupInterval := deFraggerCleanupInterval
	deFraggerIdleTimeout = 10 * time.Millisecond
	deFraggerCleanupInterval = 0
	t.Cleanup(func() {
		deFraggerIdleTimeout = oldIdleTimeout
		deFraggerCleanupInterval = oldCleanupInterval
	})

	q := &quicStreamPacketConn{}
	nowNano := time.Now().UnixNano()
	q.deFraggers.Store(uint16(1), &deFraggerBucket{
		deFraggers: []*deFragger{newDeFragger(nowNano - int64(2*deFraggerIdleTimeout))},
	})
	q.deFraggers.Store(uint16(2), &deFraggerBucket{
		deFraggers: []*deFragger{newDeFragger(nowNano)},
	})

	q.maybeCleanupDeFraggers(nowNano)

	if got := countDeFraggers(q); got != 1 {
		t.Fatalf("deFragger count after cleanup = %d, want 1", got)
	}
	if _, ok := q.deFraggers.Load(uint16(1)); ok {
		t.Fatal("expected stale deFragger to be removed")
	}
	if _, ok := q.deFraggers.Load(uint16(2)); !ok {
		t.Fatal("expected fresh deFragger to remain")
	}
}

func TestQuicStreamPacketConnCloseClearsIncompleteDeFraggers(t *testing.T) {
	packets := NewPackets()
	q := &quicStreamPacketConn{
		incomingPackets: packets,
	}

	readErr := make(chan error, 1)
	go func() {
		_, _, err := q.ReadFrom(make([]byte, 1024))
		readErr <- err
	}()

	packets.PushBack(&Packet{
		PKT_ID:     1,
		FRAG_ID:    0,
		FRAG_TOTAL: 2,
		DATA:       []byte("fragment"),
		ADDR:       &Address{TYPE: AtypIPv4, ADDR: []byte{127, 0, 0, 1}, PORT: 53},
	})

	deadline := time.Now().Add(2 * time.Second)
	for countDeFraggers(q) != 1 {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for incomplete deFragger to be created")
		}
		time.Sleep(10 * time.Millisecond)
	}

	if err := q.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	select {
	case err := <-readErr:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("ReadFrom error = %v, want net.ErrClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReadFrom did not unblock after Close")
	}

	if got := countDeFraggers(q); got != 0 {
		t.Fatalf("deFragger count after Close = %d, want 0", got)
	}
}

func TestQuicStreamPacketConnReadFromAssemblesCompleteFragments(t *testing.T) {
	packets := NewPackets()
	q := &quicStreamPacketConn{
		incomingPackets: packets,
	}

	packets.PushBack(&Packet{
		PKT_ID:     1,
		FRAG_ID:    0,
		FRAG_TOTAL: 2,
		DATA:       []byte("hello "),
		ADDR:       &Address{TYPE: AtypIPv4, ADDR: []byte{127, 0, 0, 1}, PORT: 53},
	})
	packets.PushBack(&Packet{
		PKT_ID:     1,
		FRAG_ID:    1,
		FRAG_TOTAL: 2,
		DATA:       []byte("world"),
		ADDR:       &Address{TYPE: AtypNone},
	})

	buf := make([]byte, 64)
	n, addr, err := q.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom returned error: %v", err)
	}
	if got := string(buf[:n]); got != "hello world" {
		t.Fatalf("assembled payload = %q, want %q", got, "hello world")
	}
	if addr != netip.MustParseAddrPort("127.0.0.1:53") {
		t.Fatalf("assembled addr = %v, want 127.0.0.1:53", addr)
	}
	if got := countDeFraggers(q); got != 0 {
		t.Fatalf("deFragger count after successful assembly = %d, want 0", got)
	}
}

func TestQuicStreamPacketConnReadFromSeparatesSamePktIDDifferentFragmentSets(t *testing.T) {
	packets := NewPackets()
	q := &quicStreamPacketConn{
		incomingPackets: packets,
	}

	packets.PushBack(&Packet{
		PKT_ID:     7,
		FRAG_ID:    0,
		FRAG_TOTAL: 2,
		DATA:       []byte("hello "),
		ADDR:       &Address{TYPE: AtypIPv4, ADDR: []byte{127, 0, 0, 1}, PORT: 53},
	})
	packets.PushBack(&Packet{
		PKT_ID:     7,
		FRAG_ID:    0,
		FRAG_TOTAL: 3,
		DATA:       []byte("golang "),
		ADDR:       &Address{TYPE: AtypIPv4, ADDR: []byte{127, 0, 0, 2}, PORT: 54},
	})
	packets.PushBack(&Packet{
		PKT_ID:     7,
		FRAG_ID:    1,
		FRAG_TOTAL: 3,
		DATA:       []byte("still "),
		ADDR:       &Address{TYPE: AtypNone},
	})
	packets.PushBack(&Packet{
		PKT_ID:     7,
		FRAG_ID:    1,
		FRAG_TOTAL: 2,
		DATA:       []byte("world"),
		ADDR:       &Address{TYPE: AtypNone},
	})
	packets.PushBack(&Packet{
		PKT_ID:     7,
		FRAG_ID:    2,
		FRAG_TOTAL: 3,
		DATA:       []byte("rocks"),
		ADDR:       &Address{TYPE: AtypNone},
	})

	buf := make([]byte, 64)
	n, addr, err := q.ReadFrom(buf)
	if err != nil {
		t.Fatalf("first ReadFrom returned error: %v", err)
	}
	if got := string(buf[:n]); got != "hello world" {
		t.Fatalf("first assembled payload = %q, want %q", got, "hello world")
	}
	if addr != netip.MustParseAddrPort("127.0.0.1:53") {
		t.Fatalf("first assembled addr = %v, want 127.0.0.1:53", addr)
	}

	n, addr, err = q.ReadFrom(buf)
	if err != nil {
		t.Fatalf("second ReadFrom returned error: %v", err)
	}
	if got := string(buf[:n]); got != "golang still rocks" {
		t.Fatalf("second assembled payload = %q, want %q", got, "golang still rocks")
	}
	if addr != netip.MustParseAddrPort("127.0.0.2:54") {
		t.Fatalf("second assembled addr = %v, want 127.0.0.2:54", addr)
	}

	if got := countDeFraggers(q); got != 0 {
		t.Fatalf("deFragger count after both assemblies = %d, want 0", got)
	}
}
