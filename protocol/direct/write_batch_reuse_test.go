package direct

import (
	"net"
	"runtime"
	"testing"
)

func TestReleaseDirectBatchScratchClearsPayloadReferences(t *testing.T) {
	oldProcs := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(oldProcs)

	scratch := directBatchScratchPool.Get().(*directBatchScratch)
	payload := []byte("payload")
	scratch.iovs[0] = payload
	scratch.msgs[0].Buffers = scratch.iovs[:1]
	releaseDirectBatchScratch(scratch, 1)

	reused := directBatchScratchPool.Get().(*directBatchScratch)
	defer directBatchScratchPool.Put(reused)
	if reused != scratch {
		t.Fatal("sync.Pool did not return the just-released scratch")
	}
	if reused.iovs[0] != nil {
		t.Fatal("scratch retained payload reference")
	}
	if reused.msgs[0].Buffers != nil || reused.msgs[0].Addr != nil {
		t.Fatal("scratch retained message references")
	}
}

func TestDirectPacketConnCachesBatchWriter(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()
	client, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()

	conn := &directPacketConn{UDPConn: client}
	first := conn.getBatchWriter()
	second := conn.getBatchWriter()
	if first != second {
		t.Fatal("batch writer was rebuilt")
	}
}
