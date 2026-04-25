package tuic

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestAcquireUniStreamSlotWaitsForCapacity(t *testing.T) {
	client := &clientImpl{streamSem: make(chan struct{}, 1)}
	if err := client.acquireUniStreamSlot(context.Background()); err != nil {
		t.Fatalf("acquireUniStreamSlot() initial error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- client.acquireUniStreamSlot(ctx)
	}()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("acquireUniStreamSlot() error = %v, want context deadline exceeded", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("acquireUniStreamSlot() did not unblock on context cancellation")
	}
}

func TestAcquireUniStreamSlotSucceedsAfterRelease(t *testing.T) {
	client := &clientImpl{streamSem: make(chan struct{}, 1)}
	if err := client.acquireUniStreamSlot(context.Background()); err != nil {
		t.Fatalf("acquireUniStreamSlot() initial error = %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		errCh <- client.acquireUniStreamSlot(ctx)
	}()

	time.Sleep(20 * time.Millisecond)
	client.releaseUniStreamSlot()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("acquireUniStreamSlot() error = %v", err)
		}
		client.releaseUniStreamSlot()
	case <-time.After(200 * time.Millisecond):
		t.Fatal("acquireUniStreamSlot() did not acquire released capacity")
	}
}

func TestClientRingCloseClosesClientsAndClearsRing(t *testing.T) {
	r := newClientRing(func(func(int64)) *clientImpl { return &clientImpl{} }, 0)
	client1 := &clientImpl{}
	client2 := &clientImpl{}
	r._insertAfterCurrent(&clientRingNode{cli: client1, capability: -1})
	r._insertAfterCurrent(&clientRingNode{cli: client2, capability: -1})

	if err := r.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if r.current != nil || r.ring.Len() != 0 {
		t.Fatalf("ring not cleared: current=%v len=%d", r.current, r.ring.Len())
	}
	client1.connMutex.Lock()
	client1Closed := client1.closed
	client1.connMutex.Unlock()
	client2.connMutex.Lock()
	client2Closed := client2.closed
	client2.connMutex.Unlock()
	if !client1Closed || !client2Closed {
		t.Fatalf("clients not marked closed: client1=%v client2=%v", client1Closed, client2Closed)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}
