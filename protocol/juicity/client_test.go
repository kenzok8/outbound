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
