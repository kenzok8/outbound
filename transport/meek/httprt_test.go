package meek

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
)

type closeIdleSpyRoundTripper struct {
	closeCalls atomic.Int32
}

func (s *closeIdleSpyRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("unexpected RoundTrip call")
}

func (s *closeIdleSpyRoundTripper) CloseIdleConnections() {
	s.closeCalls.Add(1)
}

func TestCleanGlobalRoundTripperCacheClosesIdleConnections(t *testing.T) {
	globalRoundTripperCacheAccess.Lock()
	original := globalRoundTripperCacheMap
	globalRoundTripperCacheMap = nil
	globalRoundTripperCacheAccess.Unlock()
	t.Cleanup(func() {
		globalRoundTripperCacheAccess.Lock()
		globalRoundTripperCacheMap = original
		globalRoundTripperCacheAccess.Unlock()
	})

	spy := &closeIdleSpyRoundTripper{}

	globalRoundTripperCacheAccess.Lock()
	globalRoundTripperCacheMap = map[string]http.RoundTripper{
		"test": spy,
	}
	globalRoundTripperCacheAccess.Unlock()

	CleanGlobalRoundTripperCache()

	if got := spy.closeCalls.Load(); got != 1 {
		t.Fatalf("CloseIdleConnections called %d times, want 1", got)
	}

	globalRoundTripperCacheAccess.Lock()
	defer globalRoundTripperCacheAccess.Unlock()
	if len(globalRoundTripperCacheMap) != 0 {
		t.Fatalf("global round tripper cache size = %d, want 0", len(globalRoundTripperCacheMap))
	}
}

type contextSpyRoundTripper struct {
	ctx context.Context
}

func (s *contextSpyRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	s.ctx = req.Context()
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(http.NoBody),
	}, nil
}

func TestRoundTripPropagatesRequestContext(t *testing.T) {
	globalRoundTripperCacheAccess.Lock()
	original := globalRoundTripperCacheMap
	globalRoundTripperCacheMap = nil
	globalRoundTripperCacheAccess.Unlock()
	t.Cleanup(func() {
		globalRoundTripperCacheAccess.Lock()
		globalRoundTripperCacheMap = original
		globalRoundTripperCacheAccess.Unlock()
	})

	spy := &contextSpyRoundTripper{}
	client := &httpTripperClient{
		addr: "test",
		url:  "https://example.com",
	}

	globalRoundTripperCacheAccess.Lock()
	globalRoundTripperCacheMap = map[string]http.RoundTripper{
		client.addr: spy,
	}
	globalRoundTripperCacheAccess.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, err := client.RoundTrip(ctx, Request{Data: []byte("ping")})
	if err != nil {
		t.Fatalf("RoundTrip() error = %v", err)
	}
	if spy.ctx != ctx {
		t.Fatal("request context was not propagated to the round tripper")
	}
}
