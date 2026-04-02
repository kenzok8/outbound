package netproxy

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

type fakeConnForUnderlying struct {
	net.Conn
}

func (c *fakeConnForUnderlying) Read(_ []byte) (int, error)         { return 0, nil }
func (c *fakeConnForUnderlying) Write(p []byte) (int, error)        { return len(p), nil }
func (c *fakeConnForUnderlying) Close() error                       { return nil }
func (c *fakeConnForUnderlying) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *fakeConnForUnderlying) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *fakeConnForUnderlying) SetDeadline(_ time.Time) error      { return nil }
func (c *fakeConnForUnderlying) SetReadDeadline(_ time.Time) error  { return nil }
func (c *fakeConnForUnderlying) SetWriteDeadline(_ time.Time) error { return nil }

func TestFakeNetConnUnderlyingConn(t *testing.T) {
	inner := &fakeConnForUnderlying{}
	conn := &FakeNetConn{Conn: inner}
	if got := conn.UnderlyingConn(); got != inner {
		t.Fatalf("unexpected underlying conn: got %T want %T", got, inner)
	}
}

type fakePacketConnForLifecycle struct {
	done <-chan struct{}
}

func (c *fakePacketConnForLifecycle) Read(_ []byte) (int, error)  { return 0, nil }
func (c *fakePacketConnForLifecycle) Write(p []byte) (int, error) { return len(p), nil }
func (c *fakePacketConnForLifecycle) ReadFrom(_ []byte) (int, netip.AddrPort, error) {
	return 0, netip.AddrPort{}, nil
}
func (c *fakePacketConnForLifecycle) WriteTo(p []byte, _ string) (int, error) { return len(p), nil }
func (c *fakePacketConnForLifecycle) Close() error                            { return nil }
func (c *fakePacketConnForLifecycle) SetDeadline(_ time.Time) error           { return nil }
func (c *fakePacketConnForLifecycle) SetReadDeadline(_ time.Time) error       { return nil }
func (c *fakePacketConnForLifecycle) SetWriteDeadline(_ time.Time) error      { return nil }
func (c *fakePacketConnForLifecycle) TransportDone() <-chan struct{}          { return c.done }

func TestFakeNetPacketConnForwardsTransportLifecycle(t *testing.T) {
	done := make(chan struct{})
	conn := NewFakeNetPacketConn(&fakePacketConnForLifecycle{done: done}, nil, nil)

	lifecycle, ok := conn.(interface{ TransportDone() <-chan struct{} })
	if !ok {
		t.Fatalf("expected wrapped fake packet conn to expose TransportDone, got %T", conn)
	}
	if got := lifecycle.TransportDone(); got != done {
		t.Fatal("expected fake packet conn wrapper to forward underlying TransportDone channel")
	}
}
