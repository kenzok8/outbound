package http

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/daeuniverse/outbound/netproxy"
)

func TestH2ConnsPoolMarkDeadCleansUpEmptyAddressState(t *testing.T) {
	pool := newH2ConnsPool()
	addr := "proxy.example:443"
	pool.h2ConnsPool[addr] = newLockedList()
	pool.registerAddrToDialerMapping(addr, noopDialer{})
	pool.registerAddrToMagicNetworkMapping(addr, "tcp")

	h2c := &http2.ClientConn{}
	pool.h2ConnsPool[addr].mu.Lock()
	ele := pool.h2ConnsPool[addr].l.PushFront(&h2Conn{h2Conn: h2c})
	pool.h2ConnsPool[addr].mu.Unlock()
	pool.h2Conn2Ident[h2c] = &poolIdent{ele: ele, addr: addr}

	pool.MarkDead(h2c)

	if _, ok := pool.h2ConnsPool[addr]; ok {
		t.Fatal("expected empty connection list to be removed")
	}
	if _, ok := pool.addr2Dialer.Load(addr); ok {
		t.Fatal("expected dialer mapping to be removed")
	}
	if _, ok := pool.addr2Somark.Load(addr); ok {
		t.Fatal("expected magic-network mapping to be removed")
	}
}

func TestH2ConnsPoolMarkDeadKeepsAddressStateWhileConnListIsInUse(t *testing.T) {
	pool := newH2ConnsPool()
	addr := "proxy.example:443"
	conns := newLockedList()
	pool.h2ConnsPool[addr] = conns
	pool.registerAddrToDialerMapping(addr, noopDialer{})
	pool.registerAddrToMagicNetworkMapping(addr, "tcp")

	oldH2 := &http2.ClientConn{}
	conns.mu.Lock()
	oldEle := conns.l.PushFront(&h2Conn{h2Conn: oldH2})
	conns.mu.Unlock()
	pool.h2Conn2Ident[oldH2] = &poolIdent{ele: oldEle, addr: addr}

	inUseConns, cached := pool.acquireConnList(addr)
	if !cached {
		t.Fatal("expected existing connection list to be reused")
	}
	if inUseConns != conns {
		t.Fatal("expected acquireConnList to return the existing list")
	}

	pool.MarkDead(oldH2)

	if got := pool.h2ConnsPool[addr]; got != conns {
		t.Fatal("expected MarkDead to keep the address state while GetConn still holds a reference")
	}
	if _, ok := pool.addr2Dialer.Load(addr); !ok {
		t.Fatal("expected dialer mapping to remain while list is in use")
	}
	if _, ok := pool.addr2Somark.Load(addr); !ok {
		t.Fatal("expected magic-network mapping to remain while list is in use")
	}

	newH2 := &http2.ClientConn{}
	conns.mu.Lock()
	newEle := conns.l.PushFront(&h2Conn{h2Conn: newH2})
	conns.mu.Unlock()
	pool.h2Conn2Ident[newH2] = &poolIdent{ele: newEle, addr: addr}

	pool.releaseConnList(addr, inUseConns)

	if got := pool.h2ConnsPool[addr]; got != conns {
		t.Fatal("expected address state to remain after a replacement h2 connection is added")
	}
	if _, ok := pool.addr2Dialer.Load(addr); !ok {
		t.Fatal("expected dialer mapping to remain after replacement h2 connection is added")
	}
	if _, ok := pool.addr2Somark.Load(addr); !ok {
		t.Fatal("expected magic-network mapping to remain after replacement h2 connection is added")
	}
}

func TestH2ConnsPoolReleaseConnListCleansUpDeferredEmptyAddressState(t *testing.T) {
	pool := newH2ConnsPool()
	addr := "proxy.example:443"
	conns := newLockedList()
	pool.h2ConnsPool[addr] = conns
	pool.registerAddrToDialerMapping(addr, noopDialer{})
	pool.registerAddrToMagicNetworkMapping(addr, "tcp")

	inUseConns, cached := pool.acquireConnList(addr)
	if !cached {
		t.Fatal("expected existing connection list to be reused")
	}
	if inUseConns != conns {
		t.Fatal("expected acquireConnList to return the existing list")
	}

	pool.releaseConnList(addr, inUseConns)

	if _, ok := pool.h2ConnsPool[addr]; ok {
		t.Fatal("expected deferred cleanup to remove the empty connection list once the last reference is released")
	}
	if _, ok := pool.addr2Dialer.Load(addr); ok {
		t.Fatal("expected deferred cleanup to remove the dialer mapping")
	}
	if _, ok := pool.addr2Somark.Load(addr); ok {
		t.Fatal("expected deferred cleanup to remove the magic-network mapping")
	}
}

func TestConnBuffersIncompleteInitialHTTPRequest(t *testing.T) {
	dialer := &recordingDialer{conn: &recordingConn{}}
	proxy := &HttpProxy{Addr: "proxy.example:8080"}
	conn := NewConn(context.Background(), dialer, proxy, "example.com:80", "tcp")

	part1 := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test")
	n, err := conn.Write(part1)
	if err != nil {
		t.Fatalf("first write failed: %v", err)
	}
	if n != len(part1) {
		t.Fatalf("first write n = %d, want %d", n, len(part1))
	}
	if dialer.calls != 0 {
		t.Fatalf("dialer called before request was complete: %d", dialer.calls)
	}

	part2 := []byte("\r\n\r\n")
	n, err = conn.Write(part2)
	if err != nil {
		t.Fatalf("second write failed: %v", err)
	}
	if n != len(part2) {
		t.Fatalf("second write n = %d, want %d", n, len(part2))
	}
	if dialer.calls != 1 {
		t.Fatalf("dialer calls = %d, want 1", dialer.calls)
	}

	got := dialer.conn.(*recordingConn).writes.String()
	if !bytes.Contains([]byte(got), []byte("GET http://example.com/ HTTP/1.1\r\n")) {
		t.Fatalf("proxy request missing absolute-form request line: %q", got)
	}
	if !bytes.Contains([]byte(got), []byte("User-Agent: test\r\n")) {
		t.Fatalf("proxy request missing buffered headers: %q", got)
	}
}

func TestConnBuffersSplitHTTPRequestLinePrefix(t *testing.T) {
	dialer := &recordingDialer{conn: &recordingConn{}}
	proxy := &HttpProxy{Addr: "proxy.example:8080"}
	conn := NewConn(context.Background(), dialer, proxy, "example.com:80", "tcp")

	part1 := []byte("GE")
	n, err := conn.Write(part1)
	if err != nil {
		t.Fatalf("first write failed: %v", err)
	}
	if n != len(part1) {
		t.Fatalf("first write n = %d, want %d", n, len(part1))
	}
	if dialer.calls != 0 {
		t.Fatalf("dialer called before request line was complete: %d", dialer.calls)
	}

	part2 := []byte("T / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	n, err = conn.Write(part2)
	if err != nil {
		t.Fatalf("second write failed: %v", err)
	}
	if n != len(part2) {
		t.Fatalf("second write n = %d, want %d", n, len(part2))
	}
	if dialer.calls != 1 {
		t.Fatalf("dialer calls = %d, want 1", dialer.calls)
	}

	got := dialer.conn.(*recordingConn).writes.String()
	if !bytes.Contains([]byte(got), []byte("GET http://example.com/ HTTP/1.1\r\n")) {
		t.Fatalf("proxy request missing reconstructed request line: %q", got)
	}
}

func TestConnBufferedPrefixFallbackKeepsPayload(t *testing.T) {
	dialer := &recordingDialer{conn: &recordingConnWithRead{read: bytes.NewBufferString("HTTP/1.1 200 Connection Established\r\n\r\n")}}
	proxy := &HttpProxy{Addr: "proxy.example:8080"}
	conn := NewConn(context.Background(), dialer, proxy, "example.com:443", "tcp")

	part1 := []byte("PO")
	n, err := conn.Write(part1)
	if err != nil {
		t.Fatalf("first write failed: %v", err)
	}
	if n != len(part1) {
		t.Fatalf("first write n = %d, want %d", n, len(part1))
	}
	if dialer.calls != 0 {
		t.Fatalf("dialer called before protocol type was known: %d", dialer.calls)
	}

	part2 := []byte("X")
	n, err = conn.Write(part2)
	if err != nil {
		t.Fatalf("second write failed: %v", err)
	}
	if n != len(part2) {
		t.Fatalf("second write n = %d, want %d", n, len(part2))
	}
	if dialer.calls != 1 {
		t.Fatalf("dialer calls = %d, want 1", dialer.calls)
	}

	got := dialer.conn.(*recordingConnWithRead).writes.String()
	if !bytes.Contains([]byte(got), []byte("CONNECT example.com:443 HTTP/1.1\r\n")) {
		t.Fatalf("proxy connect request missing: %q", got)
	}
	if !bytes.HasSuffix([]byte(got), []byte("POX")) {
		t.Fatalf("buffered tcp payload missing after CONNECT handshake: %q", got)
	}
}

type recordingDialer struct {
	conn  netproxy.Conn
	calls int
}

func (d *recordingDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	d.calls++
	return d.conn, nil
}

type recordingConn struct {
	writes bytes.Buffer
}

func (c *recordingConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *recordingConn) Write(p []byte) (int, error)      { return c.writes.Write(p) }
func (c *recordingConn) Close() error                     { return nil }
func (c *recordingConn) SetDeadline(time.Time) error      { return nil }
func (c *recordingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordingConn) SetWriteDeadline(time.Time) error { return nil }

type recordingConnWithRead struct {
	recordingConn
	read *bytes.Buffer
}

func (c *recordingConnWithRead) Read(p []byte) (int, error) {
	if c.read == nil {
		return 0, io.EOF
	}
	return c.read.Read(p)
}
