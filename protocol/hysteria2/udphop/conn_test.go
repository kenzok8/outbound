package udphop

import (
	"net"
	"sync"
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

type timeoutErr struct{}

func (timeoutErr) Error() string {
	return "timeout"
}

func (timeoutErr) Timeout() bool {
	return true
}

func (timeoutErr) Temporary() bool {
	return true
}

type timeoutPacketConn struct{}

func (c *timeoutPacketConn) ReadFrom(_ []byte) (n int, addr net.Addr, err error) {
	return 0, nil, timeoutErr{}
}

func (c *timeoutPacketConn) WriteTo(b []byte, _ net.Addr) (n int, err error) {
	return len(b), nil
}

func (c *timeoutPacketConn) Close() error {
	return nil
}

func (c *timeoutPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{}
}

func (c *timeoutPacketConn) SetDeadline(_ time.Time) error {
	return nil
}

func (c *timeoutPacketConn) SetReadDeadline(_ time.Time) error {
	return nil
}

func (c *timeoutPacketConn) SetWriteDeadline(_ time.Time) error {
	return nil
}

type stubRemotePacketConn struct {
	stubPacketConn
	remoteAddr net.Addr
}

func (c *stubRemotePacketConn) RemoteAddr() net.Addr {
	return c.remoteAddr
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

func TestUDPHopPacketConnRemoteAddrReturnsCurrentIPv6HopAddr(t *testing.T) {
	currentAddr := &net.UDPAddr{
		IP:   net.ParseIP("2001:db8::1"),
		Port: 8443,
	}
	conn := &udpHopPacketConn{
		Addr:        &UDPHopAddr{Host: "2001:db8::1", PortStr: "443,8443"},
		currentAddr: currentAddr,
	}

	addr := conn.RemoteAddr()
	if addr == nil {
		t.Fatal("RemoteAddr() returned nil")
	}
	if got, want := addr.String(), currentAddr.String(); got != want {
		t.Fatalf("RemoteAddr() = %q, want %q", got, want)
	}
}

func TestUDPHopPacketConnReadFromReturnsPacketSourceAddr(t *testing.T) {
	packetAddr := &net.UDPAddr{
		IP:   net.ParseIP("2001:db8::2"),
		Port: 8443,
	}
	conn := &udpHopPacketConn{
		Addr:        &UDPHopAddr{Host: "2001:db8::1", PortStr: "443,8443"},
		currentAddr: &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 443},
		recvQueue:   make(chan *udpPacket, 1),
		closeChan:   make(chan struct{}),
	}
	conn.recvQueue <- &udpPacket{
		Buf:  []byte("hello"),
		N:    len("hello"),
		Addr: packetAddr,
	}

	buf := make([]byte, len("hello"))
	n, addr, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom() error = %v", err)
	}
	if got, want := string(buf[:n]), "hello"; got != want {
		t.Fatalf("ReadFrom() payload = %q, want %q", got, want)
	}
	if addr == nil {
		t.Fatal("ReadFrom() returned nil addr")
	}
	if got, want := addr.String(), packetAddr.String(); got != want {
		t.Fatalf("ReadFrom() addr = %q, want %q", got, want)
	}
}

func TestUDPHopPacketConnRecvLoopDoesNotBlockOnTimeoutWhenQueueFull(t *testing.T) {
	conn := &udpHopPacketConn{
		recvQueue: make(chan *udpPacket, 1),
		closeChan: make(chan struct{}),
		bufPool: sync.Pool{
			New: func() interface{} {
				return make([]byte, udpBufferSize)
			},
		},
	}
	conn.recvQueue <- &udpPacket{Buf: []byte("queued"), N: len("queued")}

	done := make(chan struct{})
	go func() {
		conn.recvLoop(&timeoutPacketConn{})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("recvLoop blocked on timeout delivery while recvQueue was full")
	}
}

func TestFreezeAddrsForResolvedIP(t *testing.T) {
	addr := &UDPHopAddr{
		Host:    "example.com",
		Ports:   []uint16{443, 8443},
		PortStr: "443,8443",
	}
	actualAddr := &net.UDPAddr{
		IP:   net.ParseIP("203.0.113.10"),
		Port: 8443,
	}

	addrs, currentAddr, ok := freezeAddrsForResolvedIP(addr, actualAddr)
	if !ok {
		t.Fatal("freezeAddrsForResolvedIP() = false, want true")
	}
	if len(addrs) != 2 {
		t.Fatalf("len(addrs) = %d, want 2", len(addrs))
	}
	if got, want := addrs[0].String(), "203.0.113.10:443"; got != want {
		t.Fatalf("addrs[0] = %q, want %q", got, want)
	}
	if got, want := addrs[1].String(), "203.0.113.10:8443"; got != want {
		t.Fatalf("addrs[1] = %q, want %q", got, want)
	}
	if got, want := currentAddr.String(), "203.0.113.10:8443"; got != want {
		t.Fatalf("currentAddr = %q, want %q", got, want)
	}
}

func TestUDPHopPacketConnFreezesResolvedIPForSubsequentHops(t *testing.T) {
	addr := &UDPHopAddr{
		Host:    "example.com",
		Ports:   []uint16{443, 8443},
		PortStr: "443,8443",
	}
	var dialed []string
	dialFunc := func(addr net.Addr) (net.PacketConn, error) {
		dialed = append(dialed, addr.String())
		switch addr.String() {
		case "example.com:443", "example.com:8443", "203.0.113.10:443", "203.0.113.10:8443":
		default:
			t.Fatalf("unexpected dial addr %q", addr.String())
		}
		return &stubRemotePacketConn{
			remoteAddr: &net.UDPAddr{
				IP:   net.ParseIP("203.0.113.10"),
				Port: func() int {
					if udpAddr, ok := addr.(*net.UDPAddr); ok {
						return udpAddr.Port
					}
					if hostPort, ok := addr.(*hostPortAddr); ok {
						return int(hostPort.Port)
					}
					return 0
				}(),
			},
		}, nil
	}

	conn, err := NewUDPHopPacketConn(addr, 5*time.Second, dialFunc)
	if err != nil {
		t.Fatalf("NewUDPHopPacketConn() error = %v", err)
	}
	hConn := conn.(*udpHopPacketConn)
	defer func() { _ = hConn.Close() }()

	gotRemoteAddr := hConn.RemoteAddr()
	udpRemoteAddr, ok := gotRemoteAddr.(*net.UDPAddr)
	if !ok {
		t.Fatalf("RemoteAddr() type = %T, want *net.UDPAddr", gotRemoteAddr)
	}
	if got, want := udpRemoteAddr.IP.String(), "203.0.113.10"; got != want {
		t.Fatalf("RemoteAddr().IP = %q, want %q", got, want)
	}
	for i, hopAddr := range hConn.Addrs {
		udpAddr, ok := hopAddr.(*net.UDPAddr)
		if !ok {
			t.Fatalf("Addrs[%d] type = %T, want *net.UDPAddr", i, hopAddr)
		}
		if got, want := udpAddr.IP.String(), "203.0.113.10"; got != want {
			t.Fatalf("Addrs[%d].IP = %q, want %q", i, got, want)
		}
	}

	hConn.hop()
	if len(dialed) < 2 {
		t.Fatalf("dialed count = %d, want at least 2", len(dialed))
	}
	if got := dialed[len(dialed)-1]; got != "203.0.113.10:443" && got != "203.0.113.10:8443" {
		t.Fatalf("last hop dial addr = %q, want resolved IP with hop port", got)
	}
}
