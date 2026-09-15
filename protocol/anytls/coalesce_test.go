package anytls

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

type coalesceRecConn struct {
	net.Conn
	writes  [][]byte
	failOn  int
	closed  bool
	wdCount int
}

func (r *coalesceRecConn) Write(p []byte) (int, error) {
	if r.failOn > 0 && len(r.writes)+1 == r.failOn {
		return 0, errors.New("injected")
	}
	cp := make([]byte, len(p))
	copy(cp, p)
	r.writes = append(r.writes, cp)
	return len(p), nil
}

func (r *coalesceRecConn) Close() error { r.closed = true; return nil }

func (r *coalesceRecConn) SetWriteDeadline(t time.Time) error { r.wdCount++; return nil }

func TestCoalesceMergesBurstIntoOneWrite(t *testing.T) {
	rec := &coalesceRecConn{}
	c := newCoalesceConn(rec)
	if _, err := c.Write([]byte("record-one--")); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("record-two--")); err != nil {
		t.Fatal(err)
	}
	if n := c.Pending(); n != 24 {
		t.Fatalf("pending = %d, want 24", n)
	}
	if len(rec.writes) != 0 {
		t.Fatalf("premature writes: %d", len(rec.writes))
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(rec.writes) != 1 {
		t.Fatalf("writes = %d, want 1 merged write", len(rec.writes))
	}
	if got := string(rec.writes[0]); got != "record-one--record-two--" {
		t.Fatalf("merged = %q", got)
	}
	if c.Pending() != 0 {
		t.Fatalf("pending after flush = %d", c.Pending())
	}
}

func TestCoalesceFlushEmptyIsNoop(t *testing.T) {
	rec := &coalesceRecConn{}
	c := newCoalesceConn(rec)
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(rec.writes) != 0 {
		t.Fatalf("unexpected writes: %d", len(rec.writes))
	}
}

func TestCoalesceDeadlineExpiredFailsFlush(t *testing.T) {
	rec := &coalesceRecConn{}
	c := newCoalesceConn(rec)
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-time.Second)
	if err := c.SetWriteDeadline(past); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("flush err = %v, want deadline exceeded", err)
	}
	if c.Pending() != 0 {
		t.Fatalf("pending after failed flush = %d", c.Pending())
	}
	if len(rec.writes) != 0 {
		t.Fatalf("should not write past deadline, writes = %d", len(rec.writes))
	}
}

func TestCoalesceFlushPropagatesWriteError(t *testing.T) {
	rec := &coalesceRecConn{failOn: 1}
	c := newCoalesceConn(rec)
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err == nil || err.Error() != "injected" {
		t.Fatalf("flush err = %v, want injected", err)
	}
	if c.Pending() != 0 {
		t.Fatalf("buffer must be dropped after error, pending = %d", c.Pending())
	}
}

func TestCoalesceCloseFlushesFirst(t *testing.T) {
	rec := &coalesceRecConn{}
	c := newCoalesceConn(rec)
	if _, err := c.Write([]byte("close_notify")); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if len(rec.writes) != 1 || string(rec.writes[0]) != "close_notify" {
		t.Fatalf("close_notify not flushed: %+v", rec.writes)
	}
	if !rec.closed {
		t.Fatal("underlying conn not closed")
	}
}

func TestCoalesceHardLimitSelfFlushes(t *testing.T) {
	rec := &coalesceRecConn{}
	c := newCoalesceConn(rec)
	chunk := make([]byte, 40<<10)
	for i := 0; i < 4; i++ { // 160KB total, crosses the 128KB limit
		if _, err := c.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if len(rec.writes) == 0 {
		t.Fatal("hard limit did not trigger a self-flush")
	}
	if c.Pending() >= coalesceBufHardLimit {
		t.Fatalf("pending = %d still above limit", c.Pending())
	}
}
