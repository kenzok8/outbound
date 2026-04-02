package socks5

import (
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/infra/socks"
)

type recordingPacketConn struct {
	mu        sync.Mutex
	writes    []recordedPacketWrite
	closeCh   chan struct{}
	closeOnce sync.Once
}

type recordedPacketWrite struct {
	addr string
	data []byte
}

func (c *recordingPacketConn) Read([]byte) (int, error) { return 0, io.EOF }

func (c *recordingPacketConn) Write(p []byte) (int, error) {
	return c.WriteTo(p, "")
}

func (c *recordingPacketConn) ReadFrom([]byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, io.EOF
}

func (c *recordingPacketConn) WriteTo(p []byte, addr string) (int, error) {
	clone := append([]byte(nil), p...)
	c.mu.Lock()
	c.writes = append(c.writes, recordedPacketWrite{addr: addr, data: clone})
	c.mu.Unlock()
	return len(p), nil
}

func (c *recordingPacketConn) Close() error {
	c.closeOnce.Do(func() {
		if c.closeCh != nil {
			close(c.closeCh)
		}
	})
	return nil
}
func (c *recordingPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *recordingPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordingPacketConn) SetWriteDeadline(time.Time) error { return nil }

type scriptedCtrlConn struct {
	shutdownCh chan struct{}
	closeCh    chan struct{}
	closeOnce  sync.Once
}

func newScriptedCtrlConn() *scriptedCtrlConn {
	return &scriptedCtrlConn{
		shutdownCh: make(chan struct{}),
		closeCh:    make(chan struct{}),
	}
}

func (c *scriptedCtrlConn) shutdown() {
	c.closeOnce.Do(func() {
		close(c.shutdownCh)
	})
}

func (c *scriptedCtrlConn) Read([]byte) (int, error) {
	select {
	case <-c.shutdownCh:
		return 0, io.EOF
	case <-c.closeCh:
		return 0, net.ErrClosed
	}
}

func (c *scriptedCtrlConn) Write(p []byte) (int, error) { return len(p), nil }

func (c *scriptedCtrlConn) Close() error {
	select {
	case <-c.closeCh:
	default:
		close(c.closeCh)
	}
	return nil
}

func (c *scriptedCtrlConn) SetDeadline(time.Time) error      { return nil }
func (c *scriptedCtrlConn) SetReadDeadline(time.Time) error  { return nil }
func (c *scriptedCtrlConn) SetWriteDeadline(time.Time) error { return nil }

func TestPktConnConcurrentWriteTo(t *testing.T) {
	t.Helper()

	recorder := &recordingPacketConn{}
	pc := NewPktConn(recorder, "127.0.0.1:1080", "1.1.1.1:53", nil)

	targets := []string{
		"1.1.1.1:53",
		"8.8.8.8:53",
		"9.9.9.9:53",
		"208.67.222.222:53",
	}

	var wg sync.WaitGroup
	for _, target := range targets {
		target := target
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := pc.WriteTo([]byte("payload-"+target), target); err != nil {
				t.Errorf("WriteTo(%s) failed: %v", target, err)
			}
		}()
	}
	wg.Wait()

	if len(recorder.writes) != len(targets) {
		t.Fatalf("unexpected write count: got %d want %d", len(recorder.writes), len(targets))
	}

	seen := make(map[string]bool, len(targets))
	for _, write := range recorder.writes {
		if write.addr != "127.0.0.1:1080" {
			t.Fatalf("unexpected proxy addr: got %q", write.addr)
		}
		if len(write.data) < 4 {
			t.Fatalf("unexpected short socks5 packet: %d", len(write.data))
		}
		if write.data[0] != 0 || write.data[1] != 0 || write.data[2] != 0 {
			t.Fatalf("unexpected socks5 reserved header: %v", write.data[:3])
		}
		addr := socks.SplitAddr(write.data[3:])
		if addr == nil {
			t.Fatal("failed to parse encoded target address")
		}
		target := addr.String()
		payload := string(write.data[3+len(addr):])
		if payload != "payload-"+target {
			t.Fatalf("payload mismatch for %s: got %q", target, payload)
		}
		seen[target] = true
	}

	for _, target := range targets {
		if !seen[target] {
			t.Fatalf("missing target write for %s", target)
		}
	}
}

func TestPktConnTransportDoneClosesWhenControlConnEnds(t *testing.T) {
	recorder := &recordingPacketConn{closeCh: make(chan struct{})}
	ctrlConn := newScriptedCtrlConn()
	pc := NewPktConn(recorder, "127.0.0.1:1080", "1.1.1.1:53", ctrlConn)

	lifecycle, ok := any(pc).(netproxy.TransportLifecycle)
	if !ok {
		t.Fatalf("expected SOCKS5 packet conn to expose TransportDone, got %T", pc)
	}
	if lifecycle.TransportDone() == nil {
		t.Fatal("expected non-nil transport lifecycle channel when control conn is present")
	}

	ctrlConn.shutdown()

	select {
	case <-lifecycle.TransportDone():
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for SOCKS5 control-channel shutdown to close lifecycle channel")
	}

	select {
	case <-recorder.closeCh:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for SOCKS5 control-channel shutdown to close packet conn")
	}
}
