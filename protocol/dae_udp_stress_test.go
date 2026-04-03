package protocol

import (
"crypto/rand"
"net"
"sync"
"sync/atomic"
"testing"
"time"
    
"github.com/daeuniverse/outbound/protocol/direct"
)

func TestDaeUDPConcurrencyStress(t *testing.T) {
// Setup underlying OS UDP
udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
if err != nil {
t.Fatal(err)
}
osConn, err := net.ListenUDP("udp", udpAddr)
if err != nil {
t.Fatal(err)
}
defer osConn.Close()

// Using standard dial to retrieve directPacketConn interface implicitly
directDialer, err := direct.NewDialer(true, nil)
if err != nil {
t.Fatal(err)
}

packetConn, err := directDialer.DialPacketConn()
if err != nil {
t.Fatal(err)
}
defer packetConn.Close()

t.Log("Starting dae->outbound high-concurrency UDP stress test (Lock-Free)")

const Goroutines = 200     // 200 concurrent streams from dae
const PacketsPerGr = 5000  // Each sending 5000 packets
const Total = Goroutines * PacketsPerGr

payload := make([]byte, 1024)
rand.Read(payload) // 1KB Random UDP Payload

var successfulWrites atomic.Int64
var failedWrites atomic.Int64

start := time.Now()
var wg sync.WaitGroup
wg.Add(Goroutines)

for i := 0; i < Goroutines; i++ {
go func(grId int) {
defer wg.Done()
for j := 0; j < PacketsPerGr; j++ {
// Simulating Dae dispatching to UdpEndpoint write buffer concurrently
n, err := packetConn.WriteTo(payload, "127.0.0.1:53")
if err != nil || n != len(payload) {
failedWrites.Add(1)
} else {
successfulWrites.Add(1)
}
}
}(i)
}

wg.Wait()
elapsed := time.Since(start)

succ := successfulWrites.Load()
fail := failedWrites.Load()

t.Logf("Completed 1,000,000 UDP payload injections in %s", elapsed)

rate := float64(succ) / elapsed.Seconds()
t.Logf("Throughput: %.2f Packets/Sec", rate)
t.Logf("Bandwidth equivalent: %.2f MB/sec", (rate*1024)/(1024*1024))
t.Logf("Failures: %d (expected 0 under lock-free architecture)", fail)

if succ != Total {
t.Fatalf("Lost packets! Expected %d, got %d", Total, succ)
}
}
