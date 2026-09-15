package coalesce

import (
	"github.com/daeuniverse/outbound/netproxy"
)

// FlushConn is the netproxy.Conn wrapper a transport returns to its
// protocol layer: every Write returns only after the coalesced records of
// that write burst have been pushed to the socket, so plain Write/Read
// users need no flush discipline of their own.
type FlushConn struct {
	netproxy.Conn // the TLS-layer conn (tls.Conn or utls.UConn)
	co            *Conn
}

// NewFlushConn wraps an established TLS-layer conn and binds it to the
// coalescer sitting underneath that TLS layer.
func NewFlushConn(tlsConn netproxy.Conn, co *Conn) *FlushConn {
	return &FlushConn{Conn: tlsConn, co: co}
}

func (f *FlushConn) Write(b []byte) (int, error) {
	n, err := f.Conn.Write(b)
	if ferr := f.co.Flush(); ferr != nil && err == nil {
		err = ferr
	}
	return n, err
}

// compile-time interface check.
var _ netproxy.Conn = (*FlushConn)(nil)
