package grpc

import (
	"context"
	"net"
	"testing"
	"time"

	grpcpkg "google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
)

func TestCleanGlobalClientConnectionCacheClosesCachedConnections(t *testing.T) {
	globalCCAccess.Lock()
	original := globalCCMap
	globalCCMap = nil
	globalCCAccess.Unlock()
	t.Cleanup(func() {
		globalCCAccess.Lock()
		globalCCMap = original
		globalCCAccess.Unlock()
	})

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = lis.Close() }()

	server := grpcpkg.NewServer()
	defer server.Stop()
	go func() { _ = server.Serve(lis) }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cc, err := grpcpkg.DialContext(
		ctx,
		lis.Addr().String(),
		grpcpkg.WithTransportCredentials(insecure.NewCredentials()),
		grpcpkg.WithBlock(),
	)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}

	globalCCAccess.Lock()
	globalCCMap = map[string]*clientConnMeta{
		"test": {cc: cc},
	}
	globalCCAccess.Unlock()

	CleanGlobalClientConnectionCache()

	deadline := time.Now().Add(time.Second)
	for cc.GetState() != connectivity.Shutdown && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if state := cc.GetState(); state != connectivity.Shutdown {
		t.Fatalf("client conn state = %v, want %v", state, connectivity.Shutdown)
	}
}
