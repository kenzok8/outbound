package anytls

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol"
)

func init() {
	protocol.Register("anytls", NewDialer)
}

type Dialer struct {
	proxyAddress string
	nextDialer   netproxy.Dialer
	metadata     protocol.Metadata
	key          []byte
	tlsConfig    *tls.Config

	sessionCounter atomic.Uint64

	idleSessionLock sync.Mutex
	idleSessions    map[uint64]*session
	sessions        map[uint64]*session
	closed          bool
}

func NewDialer(nextDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	metadata := protocol.Metadata{
		IsClient: header.IsClient,
	}
	sum := sha256.Sum256([]byte(header.Password))
	return &Dialer{
		proxyAddress: header.ProxyAddress,
		nextDialer:   nextDialer,
		metadata:     metadata,
		key:          sum[:],
		tlsConfig:    header.TlsConfig,
		idleSessions: make(map[uint64]*session),
		sessions:     make(map[uint64]*session),
	}, nil
}

func (d *Dialer) UnwrapDialer() netproxy.Dialer {
	return d.nextDialer
}

func (d *Dialer) watchSession(s *session) {
	for {
		select {
		case <-s.Done():
			d.idleSessionLock.Lock()
			if current, ok := d.idleSessions[s.seq]; ok && current == s {
				delete(d.idleSessions, s.seq)
			}
			if current, ok := d.sessions[s.seq]; ok && current == s {
				delete(d.sessions, s.seq)
			}
			d.idleSessionLock.Unlock()
			return
		case <-s.closeStreamChan:
			if s.Closed() {
				continue
			}
			d.idleSessionLock.Lock()
			if !d.closed {
				if _, ok := d.idleSessions[s.seq]; !ok {
					d.idleSessions[s.seq] = s
				}
			}
			d.idleSessionLock.Unlock()
		}
	}
}

func (d *Dialer) DialContext(ctx context.Context, network string, addr string) (c netproxy.Conn, err error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp", "udp":
		mdata, err := protocol.ParseMetadata(addr)
		if err != nil {
			return nil, err
		}
		mdata.IsClient = d.metadata.IsClient
		if magicNetwork.Network == "udp" {
			mdata.Hostname = "sp.v2.udp-over-tcp.arpa"
		}
		tcpNetwork := netproxy.MagicNetwork{
			Network: "tcp",
			Mark:    magicNetwork.Mark,
			Mptcp:   magicNetwork.Mptcp,
		}.Encode()

		s, err := d.getSession(ctx, tcpNetwork)
		if err != nil {
			return nil, err
		}
		if magicNetwork.Network == "udp" {
			streamAddr := net.JoinHostPort(mdata.Hostname, strconv.Itoa(int(mdata.Port)))
			return s.newPacketStream(streamAddr, addr)
		}
		return s.newStream(addr)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, magicNetwork.Network)
	}
}

func (d *Dialer) getSession(ctx context.Context, tcpNetwork string) (*session, error) {
	d.idleSessionLock.Lock()
	if d.closed {
		d.idleSessionLock.Unlock()
		return nil, net.ErrClosed
	}
	for seq := range d.idleSessions {
		s := d.idleSessions[seq]
		delete(d.idleSessions, seq)
		if s.closed.Load() {
			continue
		}
		d.idleSessionLock.Unlock()
		return s, nil
	}
	d.idleSessionLock.Unlock()

	rawConn, err := d.nextDialer.DialContext(ctx, tcpNetwork, d.proxyAddress)
	if err != nil {
		return nil, err
	}
	conn := rawConn.(net.Conn)

	tlsConn := tls.Client(conn, d.tlsConfig)
	if err := netproxy.HandshakeWithContext(ctx, tlsConn); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}

	buf := pool.Get(len(d.key) + 2)
	defer pool.Put(buf)
	copy(buf, d.key)
	binary.BigEndian.PutUint16(buf[len(d.key):], uint16(0))
	restoreDeadline, err := netproxy.ApplyConnDeadlineFromContext(ctx, tlsConn)
	if err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	defer restoreDeadline()
	if _, err := tlsConn.Write(buf); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}

	seq := d.sessionCounter.Add(1)
	s := newSession(tlsConn, seq)
	d.idleSessionLock.Lock()
	if d.closed {
		d.idleSessionLock.Unlock()
		_ = s.Close()
		return nil, net.ErrClosed
	}
	d.sessions[seq] = s
	d.idleSessionLock.Unlock()
	go d.watchSession(s)

	go func() { _ = s.run() }()

	return s, nil
}

func (d *Dialer) Close() error {
	d.idleSessionLock.Lock()
	if d.closed {
		d.idleSessionLock.Unlock()
		return nil
	}
	d.closed = true
	sessions := make([]*session, 0, len(d.sessions))
	for _, s := range d.sessions {
		sessions = append(sessions, s)
	}
	d.idleSessions = make(map[uint64]*session)
	d.sessions = make(map[uint64]*session)
	d.idleSessionLock.Unlock()

	for _, s := range sessions {
		_ = s.Close()
	}
	return nil
}
