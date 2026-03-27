package udphop

import (
	"net"
	"testing"
	"time"
)

type stubPacketConn struct {
	lastWriteAddr string
}

func (c *stubPacketConn) ReadFrom(_ []byte) (n int, addr net.Addr, err error) {
	return 0, nil, net.ErrClosed
}

func (c *stubPacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	c.lastWriteAddr = addr.String()
	return len(b), nil
}

func (c *stubPacketConn) Close() error {
	return nil
}

func (c *stubPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{}
}

func (c *stubPacketConn) SetDeadline(_ time.Time) error {
	return nil
}

func (c *stubPacketConn) SetReadDeadline(_ time.Time) error {
	return nil
}

func (c *stubPacketConn) SetWriteDeadline(_ time.Time) error {
	return nil
}

func TestUDPHopPacketConnWritesToCurrentHopAddr(t *testing.T) {
	currentAddr := &hostPortAddr{
		Host: "example.com",
		Port: 8443,
	}
	stubConn := &stubPacketConn{}
	conn := &udpHopPacketConn{
		Addr:        &UDPHopAddr{Host: "example.com", PortStr: "443,8443"},
		currentAddr: currentAddr,
		currentConn: stubConn,
		closeChan:   make(chan struct{}),
	}

	if _, err := conn.WriteTo([]byte("hello"), nil); err != nil {
		t.Fatalf("WriteTo() error = %v", err)
	}
	if got, want := stubConn.lastWriteAddr, "example.com:8443"; got != want {
		t.Fatalf("lastWriteAddr = %q, want %q", got, want)
	}
}
