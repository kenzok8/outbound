package netproxy

import (
	"bufio"
	"net"
	"time"
)

// BufferedReaderConn wraps a Conn with a bufio.Reader so that callers using
// io.ReadFull on small, frequent reads (chunk headers, nonces, length prefixes)
// do not each incur their own syscall. Without this wrapper, every protocol
// that frames data into chunks (shadowsocks, vmess, trojan, vless, ...) ends
// up doing at least two reads per chunk: one for the 2-byte length+tag and one
// for the payload. On a raw TCP socket each Read may hit the kernel, doubling
// the syscall count compared to what dae's relay loop issues on the write side.
//
// The buffer size is chosen to comfortably hold a full decryption chunk so the
// wrapped protocol's io.ReadFull completes in a single underlying read once
// data starts flowing.
const defaultReadBufferSize = 32 << 10 // 32 KiB, matches dae's relay buffer

// BufferedReaderConn embeds the original Conn and routes Read through a
// per-connection bufio.Reader. All other Conn methods (Write, Close, deadlines)
// pass straight through to the underlying Conn, so Write semantics and any
// SO_MARK / socket options set on the raw fd are preserved unchanged.
type BufferedReaderConn struct {
	Conn
	reader *bufio.Reader
}

// NewBufferedReaderConn wraps c with a bufio.Reader of the given size.
// Pass 0 to use the default (32 KiB).
func NewBufferedReaderConn(c Conn, size int) *BufferedReaderConn {
	if size <= 0 {
		size = defaultReadBufferSize
	}
	return &BufferedReaderConn{
		Conn:   c,
		reader: bufio.NewReaderSize(readerOf{c}, size),
	}
}

// Read drains buffered bytes first, then refills from the underlying Conn.
// bufio.Reader handles partial reads internally, so io.ReadFull callers see a
// single logical read even when the kernel only delivered part of the chunk.
func (b *BufferedReaderConn) Read(p []byte) (int, error) {
	return b.reader.Read(p)
}

// SetReadDeadline is forwarded to the underlying Conn. Note that bufio may
// have already buffered data that will be returned before the deadline takes
// effect on the next kernel read; this matches the semantics users expect
// from a buffered connection (deadline applies to new data, not buffered).
func (b *BufferedReaderConn) SetReadDeadline(t time.Time) error {
	return b.Conn.SetReadDeadline(t)
}

// LocalAddr exposes the underlying connection's local address so that
// BufferedReaderConn satisfies the net.Conn interface. Callers such as the
// Shadowsocks-2022 dialer type-assert the wrapped connection to net.Conn
// (its TCPConn embeds net.Conn); without these accessors the assertion
// panics even though the underlying socket carries the address. If the
// wrapped Conn does not expose address information, nil is returned.
func (b *BufferedReaderConn) LocalAddr() net.Addr {
	if a, ok := b.Conn.(interface{ LocalAddr() net.Addr }); ok {
		return a.LocalAddr()
	}
	return nil
}

// RemoteAddr exposes the underlying connection's remote address. See
// LocalAddr for the rationale.
func (b *BufferedReaderConn) RemoteAddr() net.Addr {
	if a, ok := b.Conn.(interface{ RemoteAddr() net.Addr }); ok {
		return a.RemoteAddr()
	}
	return nil
}

// IntrinsicConn unwraps the buffered layer so callers that need direct
// access to the underlying TLS/REALITY connection (notably XTLS/Vision,
// which reflects on *tls.Conn / *utls.UConn / *RealityUConn fields) can
// reach it. Without this method, Vision's intrinsicConn type assertion
// fails with "XTLS only supports TLS and REALITY directly for now".
// If the underlying Conn is itself a wrapper exposing IntrinsicConn,
// forward to it so nested wrappers compose correctly.
func (b *BufferedReaderConn) IntrinsicConn() Conn {
	if ic, ok := b.Conn.(interface{ IntrinsicConn() Conn }); ok {
		return ic.IntrinsicConn()
	}
	return b.Conn
}

// UnderlyingConn returns the wrapped Conn for callers (e.g. dae's relay
// unwrap path) that need direct access to the raw socket.
func (b *BufferedReaderConn) UnderlyingConn() net.Conn {
	if u, ok := b.Conn.(interface{ UnderlyingConn() net.Conn }); ok {
		return u.UnderlyingConn()
	}
	return nil
}

// readerOf adapts a netproxy.Conn to an io.Reader for bufio by stripping the
// deadline-bearing Read signature. We do NOT implement SetReadDeadline on this
// adapter: deadline control stays on the outer BufferedReaderConn so callers
// keep working with the wrapper, not the inner reader.
type readerOf struct{ c Conn }

func (r readerOf) Read(p []byte) (int, error) { return r.c.Read(p) }
