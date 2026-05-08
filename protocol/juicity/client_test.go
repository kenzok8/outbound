package juicity

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/trojanc"
	"github.com/daeuniverse/outbound/protocol/tuic/common"
	"github.com/olicesx/quic-go"
	"github.com/olicesx/quic-go/congestion"
)

type juicityTestQUICConn struct {
	ctx        context.Context
	openStream func() (quic.Stream, error)
}

func (c *juicityTestQUICConn) AcceptStream(context.Context) (quic.Stream, error) {
	return nil, errors.New("unused")
}

func (c *juicityTestQUICConn) AcceptUniStream(context.Context) (quic.ReceiveStream, error) {
	return nil, errors.New("unused")
}

func (c *juicityTestQUICConn) OpenStream() (quic.Stream, error) {
	if c.openStream != nil {
		return c.openStream()
	}
	return nil, errors.New("unused")
}

func (c *juicityTestQUICConn) OpenStreamSync(context.Context) (quic.Stream, error) {
	return c.OpenStream()
}

func (c *juicityTestQUICConn) OpenUniStream() (quic.SendStream, error) {
	return nil, errors.New("unused")
}

func (c *juicityTestQUICConn) OpenUniStreamSync(context.Context) (quic.SendStream, error) {
	return nil, errors.New("unused")
}

func (c *juicityTestQUICConn) LocalAddr() net.Addr {
	return &net.UDPAddr{}
}

func (c *juicityTestQUICConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{}
}

func (c *juicityTestQUICConn) CloseWithError(quic.ApplicationErrorCode, string) error {
	return nil
}

func (c *juicityTestQUICConn) Context() context.Context {
	if c.ctx != nil {
		return c.ctx
	}
	return context.Background()
}

func (c *juicityTestQUICConn) ConnectionState() quic.ConnectionState {
	return quic.ConnectionState{}
}

func (c *juicityTestQUICConn) SendDatagram([]byte) error {
	return nil
}

func (c *juicityTestQUICConn) ReceiveDatagram(context.Context) ([]byte, error) {
	return nil, errors.New("unused")
}

func (c *juicityTestQUICConn) SetCongestionControl(congestion.CongestionControl) {}

type juicityTestStream struct {
	ctx context.Context
}

func (s *juicityTestStream) StreamID() quic.StreamID {
	return 0
}

func (s *juicityTestStream) Read([]byte) (int, error) {
	return 0, io.EOF
}

func (s *juicityTestStream) Write(p []byte) (int, error) {
	return len(p), nil
}

func (s *juicityTestStream) Close() error {
	return nil
}

func (s *juicityTestStream) CancelRead(quic.StreamErrorCode) {}

func (s *juicityTestStream) CancelWrite(quic.StreamErrorCode) {}

func (s *juicityTestStream) Context() context.Context {
	if s.ctx != nil {
		return s.ctx
	}
	return context.Background()
}

func (s *juicityTestStream) SetDeadline(time.Time) error {
	return nil
}

func (s *juicityTestStream) SetReadDeadline(time.Time) error {
	return nil
}

func (s *juicityTestStream) SetWriteDeadline(time.Time) error {
	return nil
}

func TestIsStreamLimitReached(t *testing.T) {
	if !isStreamLimitReached(&quic.StreamLimitReachedError{}) {
		t.Fatal("expected typed stream-limit error to be detected")
	}
	if !isStreamLimitReached(errors.New("too many open streams")) {
		t.Fatal("expected stream-limit message to be detected")
	}
	if isStreamLimitReached(errors.New("connection closed")) {
		t.Fatal("did not expect unrelated error to be detected as stream-limit")
	}
}

func TestGetQuicConnDialFailureDoesNotDeadlock(t *testing.T) {
	clientCtx, clientCancel := context.WithCancel(context.Background())
	defer clientCancel()

	client := &clientImpl{
		ClientOption: &ClientOption{
			TlsConfig: &tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         []string{"h3"},
				ServerName:         "localhost",
			},
			QuicConfig: &quic.Config{},
			Ctx:        clientCtx,
			Cancel:     clientCancel,
		},
	}

	detached := make(chan struct{})
	client.detachCallback = func() {
		close(detached)
	}

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	udpConn := pc.(*net.UDPConn)
	defer func() { _ = udpConn.Close() }()

	raddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:1")
	if err != nil {
		t.Fatalf("ResolveUDPAddr: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	errCh := make(chan error, 1)
	go func() {
		_, err := client.getQuicConn(ctx, nil, func(context.Context, netproxy.Dialer) (*quic.Transport, net.Addr, error) {
			return &quic.Transport{Conn: udpConn}, raddr, nil
		})
		errCh <- err
	}()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected getQuicConn to fail with canceled context")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("getQuicConn deadlocked on transport dial failure")
	}

	select {
	case <-detached:
	case <-time.After(time.Second):
		t.Fatal("expected failed dial to detach the client")
	}

	select {
	case <-clientCtx.Done():
	default:
		t.Fatal("expected failed dial to cancel the client context")
	}

	if _, err := udpConn.WriteToUDP([]byte("x"), raddr); err == nil {
		t.Fatal("expected failed dial path to close the underlay UDP socket")
	}
}

func TestGetQuicConnRejectsClosedCachedConnection(t *testing.T) {
	clientCtx, clientCancel := context.WithCancel(context.Background())
	defer clientCancel()
	quicCtx, quicCancel := context.WithCancel(context.Background())
	quicCancel()

	client := &clientImpl{
		ClientOption: &ClientOption{
			Ctx:    clientCtx,
			Cancel: clientCancel,
		},
		quicConn: &juicityTestQUICConn{ctx: quicCtx},
	}

	_, err := client.getQuicConn(context.Background(), nil, nil)
	if !errors.Is(err, common.ErrClientClosed) {
		t.Fatalf("expected ErrClientClosed, got %v", err)
	}
	if client.quicConn != nil {
		t.Fatal("expected closed cached QUIC connection to be dropped")
	}
	select {
	case <-clientCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("expected client context to be canceled")
	}
}

func TestClientRingRetriesAfterClosedStream(t *testing.T) {
	staleCtx, staleCancel := context.WithCancel(context.Background())
	defer staleCancel()
	freshCtx, freshCancel := context.WithCancel(context.Background())
	defer freshCancel()

	staleClient := &clientImpl{
		ClientOption: &ClientOption{
			Ctx:    staleCtx,
			Cancel: staleCancel,
		},
		quicConn: &juicityTestQUICConn{
			openStream: func() (quic.Stream, error) {
				return nil, errors.New("connection closed")
			},
		},
	}
	freshClient := &clientImpl{
		ClientOption: &ClientOption{
			Ctx:    freshCtx,
			Cancel: freshCancel,
		},
		quicConn: &juicityTestQUICConn{
			openStream: func() (quic.Stream, error) {
				return &juicityTestStream{}, nil
			},
		},
	}

	r := newClientRing(func(func(int64)) *clientImpl {
		return freshClient
	}, 0)
	r._insertAfterCurrent(&clientRingNode{cli: staleClient, capability: -1})

	conn, err := r.DialContext(context.Background(), &trojanc.Metadata{
		Metadata: protocol.Metadata{
			Type:     protocol.MetadataTypeDomain,
			Hostname: "example.com",
			Port:     443,
			IsClient: true,
		},
		Network: "tcp",
	}, nil, nil)
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	if conn == nil {
		t.Fatal("expected retry to return a connection")
	}
	select {
	case <-staleCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("expected stale client to be canceled")
	}
}

func TestClientRingCloseCancelsClientsAndClearsRing(t *testing.T) {
	r := newClientRing(func(func(int64)) *clientImpl { return &clientImpl{} }, 0)
	ctx1, cancel1 := context.WithCancel(context.Background())
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel1()
	defer cancel2()
	client1 := &clientImpl{ClientOption: &ClientOption{Ctx: ctx1, Cancel: cancel1}}
	client2 := &clientImpl{ClientOption: &ClientOption{Ctx: ctx2, Cancel: cancel2}}
	r._insertAfterCurrent(&clientRingNode{cli: client1, capability: -1})
	r._insertAfterCurrent(&clientRingNode{cli: client2, capability: -1})

	if err := r.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if r.current != nil || r.ring.Len() != 0 {
		t.Fatalf("ring not cleared: current=%v len=%d", r.current, r.ring.Len())
	}
	select {
	case <-ctx1.Done():
	case <-time.After(time.Second):
		t.Fatal("client1 context was not canceled")
	}
	select {
	case <-ctx2.Done():
	case <-time.After(time.Second):
		t.Fatal("client2 context was not canceled")
	}
	if err := r.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}
