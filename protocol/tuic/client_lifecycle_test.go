package tuic

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/olicesx/quic-go"
)

func TestDeferQuicConnKeepsAliveOnDatagramQueueTimeout(t *testing.T) {
	t.Parallel()

	client := &clientImpl{}
	var closed atomic.Bool
	client.onClose = func() { closed.Store(true) }

	client.deferQuicConn(nil, quic.ErrDatagramQueueFullTimeout)
	if client.closed.Load() {
		t.Fatal("datagram send-queue timeout must not mark the shared TUIC client closed")
	}
	if closed.Load() {
		t.Fatal("datagram send-queue timeout must not invoke the client close callback")
	}

	client.deferQuicConn(nil, errors.Join(errors.New("association write"), quic.ErrDatagramQueueFullTimeout))
	if client.closed.Load() {
		t.Fatal("wrapped datagram send-queue timeout must not close the shared TUIC client")
	}
	if closed.Load() {
		t.Fatal("wrapped datagram send-queue timeout must not invoke the client close callback")
	}
}

func TestDeferQuicConnStillClosesOnPermanentError(t *testing.T) {
	t.Parallel()

	client := &clientImpl{}
	done := make(chan struct{})
	client.onClose = func() { close(done) }

	client.deferQuicConn(nil, errors.New("connection lost"))
	if !client.closed.Load() {
		t.Fatal("permanent errors must still close the shared TUIC client")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("permanent errors must invoke the client close callback")
	}
}
