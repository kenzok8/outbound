package protocol

import (
	"context"
	"crypto/rand"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/direct"
)

func TestDaeUDPConcurrencyStress(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping UDP stress test in short mode")
	}

	serverConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP() error = %v", err)
	}
	defer func() { _ = serverConn.Close() }()

	stopDrain := make(chan struct{})
	drainDone := make(chan struct{})
	go func() {
		defer close(drainDone)
		buf := make([]byte, 2048)
		for {
			_ = serverConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			if _, _, err := serverConn.ReadFromUDP(buf); err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					select {
					case <-stopDrain:
						return
					default:
						continue
					}
				}
				return
			}
		}
	}()
	defer func() {
		close(stopDrain)
		<-drainDone
	}()

	target := serverConn.LocalAddr().String()
	conn, err := direct.SymmetricDirect.DialContext(context.Background(), "udp", target)
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	packetConn, ok := conn.(netproxy.PacketConn)
	if !ok {
		_ = conn.Close()
		t.Fatalf("DialContext() returned %T, want netproxy.PacketConn", conn)
	}
	defer func() { _ = packetConn.Close() }()

	t.Log("Starting dae->outbound high-concurrency UDP stress test")

	const (
		goroutines   = 200
		packetsPerGo = 5000
		total        = goroutines * packetsPerGo
	)

	payload := make([]byte, 1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand.Read() error = %v", err)
	}

	var successfulWrites atomic.Int64
	var failedWrites atomic.Int64

	start := time.Now()
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < packetsPerGo; j++ {
				n, err := packetConn.WriteTo(payload, target)
				if err != nil || n != len(payload) {
					failedWrites.Add(1)
				} else {
					successfulWrites.Add(1)
				}
			}
		}()
	}

	wg.Wait()
	elapsed := time.Since(start)

	succ := successfulWrites.Load()
	fail := failedWrites.Load()

	t.Logf("Completed %d UDP payload injections in %s", total, elapsed)
	rate := float64(succ) / elapsed.Seconds()
	t.Logf("Throughput: %.2f packets/sec", rate)
	t.Logf("Bandwidth equivalent: %.2f MiB/sec", (rate*1024)/(1024*1024))
	t.Logf("Failures: %d", fail)

	if succ != total {
		t.Fatalf("successful writes = %d, want %d", succ, total)
	}
}
