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
	key := "|" + "tcp" + "|" + addr
	pool.h2ConnsPool[key] = newLockedList()
	pool.registerAddrToDialerMapping(addr, noopDialer{}, "tcp")

	h2c := &http2.ClientConn{}
	pool.h2ConnsPool[key].mu.Lock()
	ele := pool.h2ConnsPool[key].l.PushFront(&h2Conn{h2Conn: h2c})
	pool.h2ConnsPool[key].mu.Unlock()
	pool.h2Conn2Ident[h2c] = &poolIdent{ele: ele, key: key}

	pool.MarkDead(h2c)

	if _, ok := pool.h2ConnsPool[key]; ok {
		t.Fatal("expected empty connection list to be removed")
	}
	if _, ok := pool.addr2Dialer[addr]; ok {
		t.Fatal("expected dialer mapping to be removed")
	}
}

func TestH2ConnsPoolMarkDeadKeepsAddressStateWhileConnListIsInUse(t *testing.T) {
	pool := newH2ConnsPool()
	addr := "proxy.example:443"
	key := "|" + "tcp" + "|" + addr
	conns := newLockedList()
	pool.h2ConnsPool[key] = conns
	pool.registerAddrToDialerMapping(addr, noopDialer{}, "tcp")

	oldH2 := &http2.ClientConn{}
	conns.mu.Lock()
	oldEle := conns.l.PushFront(&h2Conn{h2Conn: oldH2})
	conns.mu.Unlock()
	pool.h2Conn2Ident[oldH2] = &poolIdent{ele: oldEle, key: key}

	inUseConns, cached := pool.acquireConnList(key)
	if !cached {
		t.Fatal("expected existing connection list to be reused")
	}
	if inUseConns != conns {
		t.Fatal("expected acquireConnList to return the existing list")
	}

	pool.MarkDead(oldH2)

	if got := pool.h2ConnsPool[key]; got != conns {
		t.Fatal("expected MarkDead to keep the address state while GetConn still holds a reference")
	}
	if _, ok := pool.addr2Dialer[addr]; !ok {
		t.Fatal("expected dialer mapping to remain while list is in use")
	}

	newH2 := &http2.ClientConn{}
	conns.mu.Lock()
	newEle := conns.l.PushFront(&h2Conn{h2Conn: newH2})
	conns.mu.Unlock()
	pool.h2Conn2Ident[newH2] = &poolIdent{ele: newEle, key: key}

	pool.releaseConnList(key, inUseConns)

	if got := pool.h2ConnsPool[key]; got != conns {
		t.Fatal("expected address state to remain after a replacement h2 connection is added")
	}
	if _, ok := pool.addr2Dialer[addr]; !ok {
		t.Fatal("expected dialer mapping to remain after replacement h2 connection is added")
	}
}

func TestH2ConnsPoolReleaseConnListCleansUpDeferredEmptyAddressState(t *testing.T) {
	pool := newH2ConnsPool()
	addr := "proxy.example:443"
	key := "|" + "tcp" + "|" + addr
	conns := newLockedList()
	pool.h2ConnsPool[key] = conns
	pool.registerAddrToDialerMapping(addr, noopDialer{}, "tcp")

	inUseConns, cached := pool.acquireConnList(key)
	if !cached {
		t.Fatal("expected existing connection list to be reused")
	}
	if inUseConns != conns {
		t.Fatal("expected acquireConnList to return the existing list")
	}

	pool.releaseConnList(key, inUseConns)

	if _, ok := pool.h2ConnsPool[key]; ok {
		t.Fatal("expected deferred cleanup to remove the empty connection list once the last reference is released")
	}
	if _, ok := pool.addr2Dialer[addr]; ok {
		t.Fatal("expected deferred cleanup to remove the dialer mapping")
	}
}

type scopedDialer struct {
	noopDialer
	ns string
}

func (d scopedDialer) TransportCacheNamespace() string { return d.ns }

func TestH2ConnsPoolMarkDeadUsesScopedKey(t *testing.T) {
	pool := newH2ConnsPool()
	addr := "proxy.example:443"
	keyA := "ns-a|tcp|" + addr
	keyB := "ns-b|tcp|" + addr

	listA := newLockedList()
	listB := newLockedList()
	pool.h2ConnsPool[keyA] = listA
	pool.h2ConnsPool[keyB] = listB
	pool.registerAddrToDialerMapping(addr, scopedDialer{ns: "ns-a"}, "tcp")
	pool.registerAddrToDialerMapping(addr, scopedDialer{ns: "ns-b"}, "tcp")

	h2a := &http2.ClientConn{}
	h2b := &http2.ClientConn{}
	listA.mu.Lock()
	eleA := listA.l.PushFront(&h2Conn{h2Conn: h2a})
	listA.mu.Unlock()
	listB.mu.Lock()
	eleB := listB.l.PushFront(&h2Conn{h2Conn: h2b})
	listB.mu.Unlock()
	pool.h2Conn2Ident[h2a] = &poolIdent{ele: eleA, key: keyA}
	pool.h2Conn2Ident[h2b] = &poolIdent{ele: eleB, key: keyB}

	pool.MarkDead(h2a)

	if _, ok := pool.h2ConnsPool[keyA]; ok {
		t.Fatal("expected ns-a list to be removed after MarkDead")
	}
	if got := pool.h2ConnsPool[keyB]; got != listB {
		t.Fatal("expected ns-b list to survive MarkDead of an ns-a conn")
	}
	if listB.l.Len() != 1 {
		t.Fatalf("ns-b list len = %d, want 1", listB.l.Len())
	}
	bindings := pool.addr2Dialer[addr]
	if len(bindings) != 1 || bindings[0].key != keyB {
		t.Fatalf("bindings after ns-a removal = %+v, want only ns-b", bindings)
	}
}

func TestH2ConnsPoolLatestBindingRemovalFallsBack(t *testing.T) {
	pool := newH2ConnsPool()
	addr := "proxy.example:443"
	dialerA := scopedDialer{ns: "ns-a"}
	dialerB := scopedDialer{ns: "ns-b"}
	keyA := "ns-a|tcp|" + addr
	keyB := "ns-b|tcp|" + addr

	listA, _ := pool.acquireConnListForDialer(keyA, addr, dialerA, "tcp")
	listB, _ := pool.acquireConnListForDialer(keyB, addr, dialerB, "tcp")
	pool.releaseConnList(keyB, listB)

	bindings := pool.addr2Dialer[addr]
	if len(bindings) != 1 || bindings[0].key != keyA {
		t.Fatalf("bindings after latest removal = %+v, want ns-a fallback", bindings)
	}
	pool.releaseConnList(keyA, listA)
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
