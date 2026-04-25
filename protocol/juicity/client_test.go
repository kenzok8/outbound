package juicity

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/olicesx/quic-go"
)

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
