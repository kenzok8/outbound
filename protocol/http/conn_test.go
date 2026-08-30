package http

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"sync/atomic"
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

func TestCloseUnblocksHandshakeRead(t *testing.T) {
	conn := NewConn(context.Background(), &recordingDialer{conn: &recordingConn{}}, &HttpProxy{Addr: "proxy.example:8080"}, "example.com:443", "tcp")
	done := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 8))
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-done:
		if err != io.EOF {
			t.Fatalf("Read after Close: %v, want EOF", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Read remained blocked after Close")
	}
}

func TestHTTP2LogicalCloseDoesNotClosePooledPhysicalConn(t *testing.T) {
	physical := &closeCountConn{}
	pr, pw := io.Pipe()
	logical := newHTTP2Conn(physical, pw, pr)
	c := NewConn(context.Background(), &recordingDialer{conn: physical}, &HttpProxy{Addr: "proxy.example:443", https: true}, "example.com:443", "tcp")
	c.conn = logical
	c.isH2 = true
	c.cancelShakeFinished()

	if err := c.Close(); err != nil && err != io.ErrClosedPipe {
		t.Fatalf("logical Close: %v", err)
	}
	if physical.closes.Load() != 0 {
		t.Fatalf("physical conn closed %d times, want 0", physical.closes.Load())
	}
}

func TestHTTP2LogicalCloseClosesRequestPipeAndResponseBody(t *testing.T) {
	physical := &closeCountConn{}
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pr.Close() })
	body := &closeCountReadCloser{Reader: bytes.NewReader(nil)}
	logical := newHTTP2Conn(physical, pw, body)
	c := NewConn(context.Background(), &recordingDialer{conn: physical}, &HttpProxy{Addr: "proxy.example:443", https: true}, "example.com:443", "tcp")
	c.conn = logical
	c.isH2 = true
	c.cancelShakeFinished()

	if err := c.Close(); err != nil && err != io.ErrClosedPipe {
		t.Fatalf("logical Close: %v", err)
	}
	if _, err := pw.Write([]byte("x")); err == nil {
		t.Fatal("request pipe still writable after logical Close")
	}
	if body.closes.Load() != 1 {
		t.Fatalf("resp.Body closed %d times, want 1", body.closes.Load())
	}
	if physical.closes.Load() != 0 {
		t.Fatalf("physical conn closed %d times, want 0", physical.closes.Load())
	}
}

type closeCountReadCloser struct {
	io.Reader
	closes atomic.Int32
}

func (c *closeCountReadCloser) Close() error {
	c.closes.Add(1)
	return nil
}

type closeCountConn struct {
	recordingConn
	closes atomic.Int32
}

func (c *closeCountConn) Close() error {
	c.closes.Add(1)
	return nil
}
func (c *closeCountConn) LocalAddr() net.Addr  { return nil }
func (c *closeCountConn) RemoteAddr() net.Addr { return nil }

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

func TestH2PoolClosesRawConnOnUnsupportedALPN(t *testing.T) {
	cert := mustSelfSignedCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"foo"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		accepted <- c
		_ = c.(*tls.Conn).Handshake()
	}()

	raw, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"foo"},
		ServerName:         "example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	dialer := &recordingDialer{conn: raw}
	pool := newH2ConnsPool()
	_, _, err = pool.GetConn(context.Background(), dialer, "proxy.example:443", "tcp")
	if err == nil {
		t.Fatal("expected unsupported ALPN error")
	}
	if !strings.Contains(err.Error(), "unsupported application layer protocol") {
		t.Fatalf("err = %v", err)
	}
	if _, writeErr := raw.Write([]byte{1}); writeErr == nil {
		t.Fatal("client rawConn still writable after unsupported ALPN")
	}

	select {
	case serverConn := <-accepted:
		done := make(chan error, 1)
		go func() {
			_, readErr := serverConn.Read(make([]byte, 1))
			done <- readErr
		}()
		select {
		case readErr := <-done:
			if readErr == nil {
				t.Fatal("server still readable after unsupported ALPN; client rawConn was not closed")
			}
			var ne net.Error
			if errors.As(readErr, &ne) && ne.Timeout() {
				t.Fatal("server Read timed out; client rawConn was not closed")
			}
		case <-time.After(time.Second):
			t.Fatal("server Read remained blocked; client rawConn was not closed")
		}
		_ = serverConn.Close()
	case <-time.After(time.Second):
		t.Fatal("server did not accept")
	}
}

func mustSelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		DNSNames:              []string{"example.com"},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: mustMarshalEC(t, key),
	}))
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func mustMarshalEC(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	b, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
