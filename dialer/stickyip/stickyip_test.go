package stickyip

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

func TestSplitHostPortSupportsPortUnion(t *testing.T) {
	host, port, err := SplitHostPort("example.com:443,8443-8450")
	if err != nil {
		t.Fatalf("SplitHostPort() error = %v", err)
	}
	if got, want := host, "example.com"; got != want {
		t.Fatalf("host = %q, want %q", got, want)
	}
	if got, want := port, "443,8443-8450"; got != want {
		t.Fatalf("port = %q, want %q", got, want)
	}
}

func TestSplitHostPortSupportsBracketedIPv6(t *testing.T) {
	host, port, err := SplitHostPort("[2001:db8::1]:443,8443")
	if err != nil {
		t.Fatalf("SplitHostPort() error = %v", err)
	}
	if got, want := host, "2001:db8::1"; got != want {
		t.Fatalf("host = %q, want %q", got, want)
	}
	if got, want := port, "443,8443"; got != want {
		t.Fatalf("port = %q, want %q", got, want)
	}
}

func TestRewriteAddrPortKeepsResolvedHostAndCurrentPort(t *testing.T) {
	if got, want := rewriteAddrPort("203.0.113.10:443", "example.com:8443"), "203.0.113.10:8443"; got != want {
		t.Fatalf("rewriteAddrPort() = %q, want %q", got, want)
	}
}

func TestRewriteAddrPortKeepsIPv6Formatting(t *testing.T) {
	if got, want := rewriteAddrPort("[2001:db8::10]:443", "example.com:8443"), "[2001:db8::10]:8443"; got != want {
		t.Fatalf("rewriteAddrPort() = %q, want %q", got, want)
	}
}

type recordingLookupDialer struct {
	mu sync.Mutex

	lookupCalls   int
	lookupNetwork string
	lookupHost    string
	lookupResult  []net.IPAddr
	lookupErr     error

	dialCalls [][2]string
	conn      netproxy.Conn
	dialErr   error
	dialFunc  func(network, addr string) (netproxy.Conn, error)
}

func (d *recordingLookupDialer) DialContext(_ context.Context, network, addr string) (netproxy.Conn, error) {
	d.mu.Lock()
	d.dialCalls = append(d.dialCalls, [2]string{network, addr})
	d.mu.Unlock()
	if d.dialFunc != nil {
		return d.dialFunc(network, addr)
	}
	if d.dialErr != nil {
		return nil, d.dialErr
	}
	return d.conn, nil
}

func (d *recordingLookupDialer) LookupIPAddr(_ context.Context, network, host string) ([]net.IPAddr, error) {
	d.mu.Lock()
	d.lookupCalls++
	d.lookupNetwork = network
	d.lookupHost = host
	d.mu.Unlock()
	if d.lookupErr != nil {
		return nil, d.lookupErr
	}
	return append([]net.IPAddr(nil), d.lookupResult...), nil
}

type nopConn struct{}

func (nopConn) Read(_ []byte) (int, error)         { return 0, io.EOF }
func (nopConn) Write(p []byte) (int, error)        { return len(p), nil }
func (nopConn) Close() error                       { return nil }
func (nopConn) SetDeadline(_ time.Time) error      { return nil }
func (nopConn) SetReadDeadline(_ time.Time) error  { return nil }
func (nopConn) SetWriteDeadline(_ time.Time) error { return nil }

type trackingPacketConn struct {
	readFromCalls        int
	setReadDeadlineCalls int
	readErr              error
}

func (c *trackingPacketConn) Read(_ []byte) (int, error)    { return 0, io.EOF }
func (c *trackingPacketConn) Write(p []byte) (int, error)   { return len(p), nil }
func (c *trackingPacketConn) Close() error                  { return nil }
func (c *trackingPacketConn) SetDeadline(_ time.Time) error { return nil }
func (c *trackingPacketConn) SetReadDeadline(_ time.Time) error {
	c.setReadDeadlineCalls++
	return nil
}
func (c *trackingPacketConn) SetWriteDeadline(_ time.Time) error { return nil }
func (c *trackingPacketConn) ReadFrom(_ []byte) (int, netip.AddrPort, error) {
	c.readFromCalls++
	return 0, netip.AddrPort{}, c.readErr
}
func (c *trackingPacketConn) WriteTo(p []byte, _ string) (int, error) { return len(p), nil }

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestStickyIpDialerUsesUnderlyingResolverForProxyLookup(t *testing.T) {
	network := netproxy.MagicNetwork{Network: "tcp", Mark: 123}.Encode()
	parent := &recordingLookupDialer{
		lookupResult: []net.IPAddr{{IP: net.ParseIP("203.0.113.10")}},
		conn:         nopConn{},
	}
	dialer := NewStickyIpDialer(parent, "proxy.example:443,8443-8450", NewProxyIpCache())

	conn, err := dialer.DialContext(context.Background(), network, "proxy.example:8443")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	if conn == nil {
		t.Fatal("DialContext() returned nil conn")
	}

	parent.mu.Lock()
	defer parent.mu.Unlock()
	if parent.lookupCalls != 1 {
		t.Fatalf("LookupIPAddr() calls = %d, want 1", parent.lookupCalls)
	}
	if got, want := parent.lookupNetwork, network; got != want {
		t.Fatalf("LookupIPAddr() network = %q, want %q", got, want)
	}
	if got, want := parent.lookupHost, "proxy.example"; got != want {
		t.Fatalf("LookupIPAddr() host = %q, want %q", got, want)
	}
	if len(parent.dialCalls) != 1 {
		t.Fatalf("DialContext() calls = %d, want 1", len(parent.dialCalls))
	}
	if got, want := parent.dialCalls[0][1], "203.0.113.10:8443"; got != want {
		t.Fatalf("DialContext() addr = %q, want %q", got, want)
	}
}

func TestStickyIpDialerDoesNotTreatDifferentFixedPortAsProxyAddress(t *testing.T) {
	parent := &recordingLookupDialer{
		conn: nopConn{},
	}
	dialer := NewStickyIpDialer(parent, "proxy.example:443", NewProxyIpCache())

	conn, err := dialer.DialContext(context.Background(), "tcp", "proxy.example:8443")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	if conn == nil {
		t.Fatal("DialContext() returned nil conn")
	}

	parent.mu.Lock()
	defer parent.mu.Unlock()
	if parent.lookupCalls != 0 {
		t.Fatalf("LookupIPAddr() calls = %d, want 0", parent.lookupCalls)
	}
	if len(parent.dialCalls) != 1 {
		t.Fatalf("DialContext() calls = %d, want 1", len(parent.dialCalls))
	}
	if got, want := parent.dialCalls[0][1], "proxy.example:8443"; got != want {
		t.Fatalf("DialContext() addr = %q, want %q", got, want)
	}
}

func TestStickyIpDialerDoesNotProbeResolvedUDPProxyConnBeforeCaching(t *testing.T) {
	packetConn := &trackingPacketConn{readErr: timeoutErr{}}
	parent := &recordingLookupDialer{
		lookupResult: []net.IPAddr{{IP: net.ParseIP("198.51.100.20")}},
		conn:         packetConn,
	}
	dialer := NewStickyIpDialer(parent, "proxy.example:443", NewProxyIpCache())

	conn, err := dialer.DialContext(context.Background(), "udp", "proxy.example:443")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	if conn == nil {
		t.Fatal("DialContext() returned nil conn")
	}
	if packetConn.readFromCalls != 0 {
		t.Fatalf("ReadFrom() calls = %d, want 0", packetConn.readFromCalls)
	}
	if packetConn.setReadDeadlineCalls != 0 {
		t.Fatalf("SetReadDeadline() calls = %d, want 0", packetConn.setReadDeadlineCalls)
	}
}

func TestStickyIpDialerUsesCachedUDPProxyAddrWithoutReadProbe(t *testing.T) {
	firstConn := &trackingPacketConn{readErr: timeoutErr{}}
	secondConn := &trackingPacketConn{readErr: timeoutErr{}}
	parent := &recordingLookupDialer{
		lookupResult: []net.IPAddr{
			{IP: net.ParseIP("198.51.100.10")},
			{IP: net.ParseIP("198.51.100.20")},
		},
		dialFunc: func(_ string, addr string) (netproxy.Conn, error) {
			switch addr {
			case "198.51.100.10:443":
				return firstConn, nil
			default:
				return secondConn, nil
			}
		},
	}
	dialer := NewStickyIpDialer(parent, "proxy.example:443", NewProxyIpCache())

	conn, err := dialer.DialContext(context.Background(), "udp", "proxy.example:443")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	if conn != firstConn {
		t.Fatal("DialContext() did not return the first successfully dialed UDP conn")
	}
	conn, err = dialer.DialContext(context.Background(), "udp", "proxy.example:443")
	if err != nil {
		t.Fatalf("second DialContext() error = %v", err)
	}
	if conn != firstConn {
		t.Fatal("second DialContext() did not use the cached UDP proxy addr")
	}

	parent.mu.Lock()
	defer parent.mu.Unlock()
	if parent.lookupCalls != 1 {
		t.Fatalf("LookupIPAddr() calls = %d, want 1", parent.lookupCalls)
	}
	if len(parent.dialCalls) != 2 {
		t.Fatalf("DialContext() calls = %d, want 2", len(parent.dialCalls))
	}
	if got, want := parent.dialCalls[0][1], "198.51.100.10:443"; got != want {
		t.Fatalf("first dial addr = %q, want %q", got, want)
	}
	if got, want := parent.dialCalls[1][1], "198.51.100.10:443"; got != want {
		t.Fatalf("second dial addr = %q, want %q", got, want)
	}
	if firstConn.readFromCalls != 0 {
		t.Fatalf("first conn ReadFrom() calls = %d, want 0", firstConn.readFromCalls)
	}
	if firstConn.setReadDeadlineCalls != 0 {
		t.Fatalf("first conn SetReadDeadline() calls = %d, want 0", firstConn.setReadDeadlineCalls)
	}
	if secondConn.readFromCalls != 0 {
		t.Fatalf("second conn ReadFrom() calls = %d, want 0", secondConn.readFromCalls)
	}
	if secondConn.setReadDeadlineCalls != 0 {
		t.Fatalf("second conn SetReadDeadline() calls = %d, want 0", secondConn.setReadDeadlineCalls)
	}
}

func TestStickyIpDialerReturnsStableErrorWhenNoUsableIPsResolved(t *testing.T) {
	parent := &recordingLookupDialer{
		lookupResult: []net.IPAddr{{}},
	}
	dialer := NewStickyIpDialer(parent, "proxy.example:443", NewProxyIpCache())

	_, err := dialer.DialContext(context.Background(), "tcp", "proxy.example:443")
	if err == nil {
		t.Fatal("DialContext() error = nil, want non-nil")
	}
	if got, want := err.Error(), "no usable proxy IP addresses"; got == want {
		return
	}
	if !strings.Contains(err.Error(), "no usable proxy IP addresses") {
		t.Fatalf("DialContext() error = %q, want substring %q", err.Error(), "no usable proxy IP addresses")
	}
}

func TestStickyIpDialerFallsBackToOriginalAddrWhenResolverReturnsEmptySet(t *testing.T) {
	parent := &recordingLookupDialer{
		lookupResult: []net.IPAddr{},
		conn:         nopConn{},
	}
	dialer := NewStickyIpDialer(parent, "proxy.example:443", NewProxyIpCache())

	conn, err := dialer.DialContext(context.Background(), "tcp", "proxy.example:443")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	if conn == nil {
		t.Fatal("DialContext() returned nil conn")
	}

	parent.mu.Lock()
	defer parent.mu.Unlock()
	if len(parent.dialCalls) != 1 {
		t.Fatalf("DialContext() calls = %d, want 1", len(parent.dialCalls))
	}
	if got, want := parent.dialCalls[0][1], "proxy.example:443"; got != want {
		t.Fatalf("DialContext() addr = %q, want %q", got, want)
	}
}

func TestStickyIpDialerHonorsRequestedIPVersion(t *testing.T) {
	network := netproxy.MagicNetwork{Network: "udp", IPVersion: "6"}.Encode()
	parent := &recordingLookupDialer{
		lookupResult: []net.IPAddr{
			{IP: net.ParseIP("203.0.113.10")},
			{IP: net.ParseIP("2001:db8::10")},
		},
		conn: &trackingPacketConn{readErr: timeoutErr{}},
	}
	dialer := NewStickyIpDialer(parent, "proxy.example:443", NewProxyIpCache())

	conn, err := dialer.DialContext(context.Background(), network, "proxy.example:443")
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	if conn == nil {
		t.Fatal("DialContext() returned nil conn")
	}

	parent.mu.Lock()
	defer parent.mu.Unlock()
	if len(parent.dialCalls) != 1 {
		t.Fatalf("DialContext() calls = %d, want 1", len(parent.dialCalls))
	}
	if got, want := parent.dialCalls[0][1], "[2001:db8::10]:443"; got != want {
		t.Fatalf("DialContext() addr = %q, want %q", got, want)
	}
}
