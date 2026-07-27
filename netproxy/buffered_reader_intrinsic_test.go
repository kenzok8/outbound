package netproxy

import (
	gotls "crypto/tls"
	"net"
	"testing"
)

// TestBufferedReaderConnIntrinsicConnUnwrapsToTLSConn verifies that XTLS/Vision
// can reach the underlying *tls.Conn through a BufferedReaderConn wrapper.
// Without this method, visionIntrinsicConn's type assertion fails with
// "XTLS only supports TLS and REALITY directly for now: *BufferedReaderConn".
func TestBufferedReaderConnIntrinsicConnUnwrapsToTLSConn(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	tlsConn := gotls.Client(client, &gotls.Config{InsecureSkipVerify: true})
	// The TLS handshake won't complete over net.Pipe without a peer, but
	// *tls.Client's identity as a netproxy.Conn is what matters here.
	wrapped := NewBufferedReaderConn(tlsConn, 0)

	got := wrapped.IntrinsicConn()
	if got != tlsConn {
		t.Fatalf("IntrinsicConn() = %T, want the wrapped *tls.Conn", got)
	}
}

// TestBufferedReaderConnIntrinsicConnForwardsThroughNestedWrapper ensures that
// when BufferedReaderConn wraps another IntrinsicConn-bearing wrapper, the
// call recurses so callers always reach the innermost TLS/REALITY connection.
func TestBufferedReaderConnIntrinsicConnForwardsThroughNestedWrapper(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	tlsConn := gotls.Client(client, &gotls.Config{InsecureSkipVerify: true})
	inner := &intrinsicForwarder{Conn: tlsConn, inner: tlsConn}
	outer := NewBufferedReaderConn(inner, 0)

	got := outer.IntrinsicConn()
	if got != tlsConn {
		t.Fatalf("IntrinsicConn() = %T, want the innermost *tls.Conn", got)
	}
}

// TestBufferedReaderConnIsAnIntrinsicConn is a regression guard: if the
// IntrinsicConn method is ever removed, this test stops passing, which
// surfaces the breakage before a user hits the Vision type-assertion error.
func TestBufferedReaderConnIsAnIntrinsicConn(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()

	wrapped := NewBufferedReaderConn(netPipeConn{client}, 0)
	type intrinsicConn interface {
		IntrinsicConn() Conn
	}
	if _, ok := interface{}(wrapped).(intrinsicConn); !ok {
		t.Fatal("BufferedReaderConn no longer satisfies the intrinsicConn interface")
	}
}

// netPipeConn adapts net.Pipe's endpoint to netproxy.Conn.
type netPipeConn struct {
	net.Conn
}

type intrinsicForwarder struct {
	Conn
	inner Conn
}

func (w *intrinsicForwarder) IntrinsicConn() Conn { return w.inner }
