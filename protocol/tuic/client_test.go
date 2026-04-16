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
