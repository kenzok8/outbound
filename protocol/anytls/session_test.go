package anytls

import (
	"io"
	"testing"
	"time"
)

type stubConn struct {
	closed bool
}

func (c *stubConn) Read(_ []byte) (int, error)         { return 0, io.EOF }
func (c *stubConn) Write(p []byte) (int, error)        { return len(p), nil }
func (c *stubConn) Close() error                       { c.closed = true; return nil }
func (c *stubConn) SetDeadline(_ time.Time) error      { return nil }
func (c *stubConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *stubConn) SetWriteDeadline(_ time.Time) error { return nil }

func TestSessionCloseClosesActiveStreamsWithoutDeadlock(t *testing.T) {
	conn := &stubConn{}
	s := newSession(conn, 1)
	s.streams[1] = newStream(s, 1)
	s.streams[2] = newStream(s, 2)
	s.streams[3] = newStream(s, 3)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = s.Close()
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Close() timed out with active streams")
	}

	if !conn.closed {
		t.Fatal("expected session connection to be closed")
	}
	if len(s.streams) != 0 {
		t.Fatalf("remaining streams = %d, want 0", len(s.streams))
	}
}

func TestDialerWatchSessionStopsAfterSessionClose(t *testing.T) {
	d := &Dialer{
		idleSessions: make(map[uint64]*session),
	}
	s := newSession(&stubConn{}, 7)

	done := make(chan struct{})
	go func() {
		d.watchSession(s)
		close(done)
	}()

	s.closeStreamChan <- 1

	deadline := time.Now().Add(time.Second)
	for {
		d.idleSessionLock.Lock()
		_, ok := d.idleSessions[s.seq]
		d.idleSessionLock.Unlock()
		if ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("session was not added to idleSessions")
		}
		time.Sleep(10 * time.Millisecond)
	}

	if err := s.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("watchSession did not exit after session close")
	}

	d.idleSessionLock.Lock()
	_, ok := d.idleSessions[s.seq]
	d.idleSessionLock.Unlock()
	if ok {
		t.Fatal("closed session remained in idleSessions")
	}
}
