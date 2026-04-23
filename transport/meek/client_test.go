package meek

import (
	"context"
	"testing"
	"time"
)

type staticTripper struct {
	started chan struct{}
	data    []byte
}

func (t *staticTripper) RoundTrip(context.Context, Request) (Response, error) {
	select {
	case <-t.started:
	default:
		close(t.started)
	}
	return Response{Data: t.data}, nil
}

func TestRunOnceReturnsAfterCloseWhileReaderChanIsFull(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tripper := &staticTripper{
		started: make(chan struct{}),
		data:    []byte("payload"),
	}
	session := &assemblerClientSession{
		assembler: &assemblerClient{
			tripper: tripper,
			config: &config{
				MaxWriteSize:          1024,
				FailedRetryIntervalMs: 1,
			},
		},
		tripper:          tripper,
		writerChan:       make(chan []byte),
		readerChan:       make(chan []byte, 1),
		ctx:              ctx,
		finish:           cancel,
		currentWriteWait: 0,
		sessionID:        []byte("session"),
	}
	session.readerChan <- []byte("blocked")

	done := make(chan struct{})
	go func() {
		defer close(done)
		session.runOnce()
	}()

	select {
	case <-tripper.started:
	case <-time.After(time.Second):
		t.Fatal("RoundTrip() was not reached")
	}

	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("runOnce() did not return after Close/cancel")
	}
}
