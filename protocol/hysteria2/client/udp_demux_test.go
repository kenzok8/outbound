package client

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/protocol"
)

// chanUDPIO feeds datagrams from a channel and reports a fatal transport
// error when closed, mirroring the real udpIOImpl contract.
type chanUDPIO struct {
	msgs chan *protocol.UDPMessage
	dead chan struct{}
}

func (io *chanUDPIO) ReceiveMessage() (*protocol.UDPMessage, error) {
	select {
	case msg := <-io.msgs:
		return msg, nil
	case <-io.dead:
		return nil, errors.New("transport closed")
	}
}

func (io *chanUDPIO) SendMessage([]byte, *protocol.UDPMessage) error { return nil }

// TestUDPSessionManagerParallelDemux 回归测试：多个 run() goroutine 并发
// 消费 datagram 时，各 session 的消息仍被完整、正确地分发。
func TestUDPSessionManagerParallelDemux(t *testing.T) {
	const numSessions = 4
	const msgsPerSession = 500

	io := &chanUDPIO{
		msgs: make(chan *protocol.UDPMessage, 64),
		dead: make(chan struct{}),
	}
	m := newUDPSessionManager(io)

	conns := make([]*udpConn, numSessions)
	var counts [numSessions]atomic.Int32
	for i := range numSessions {
		c, err := m.NewUDP("192.0.2.1:443")
		if err != nil {
			t.Fatalf("NewUDP #%d: %v", i, err)
		}
		uc := c.(*udpConn)
		conns[i] = uc
		idx := i
		_, ok := uc.RegisterPacketReceiver(func(packet *netproxy.ReceivedPacket) bool {
			counts[idx].Add(1)
			packet.Release()
			return true
		})
		if !ok {
			t.Fatalf("RegisterPacketReceiver #%d failed", i)
		}
	}

	// Interleave messages from all sessions so concurrent run() goroutines
	// must demux them in parallel.
	var wg sync.WaitGroup
	wg.Add(numSessions)
	for i := range numSessions {
		go func(idx int) {
			defer wg.Done()
			for j := range msgsPerSession {
				io.msgs <- &protocol.UDPMessage{
					SessionID: conns[idx].ID,
					PacketID:  0,
					FragID:    0,
					FragCount: 1,
					Addr:      "192.0.2.1:443",
					Data:      []byte{byte(idx), byte(j)},
				}
			}
		}(i)
	}
	wg.Wait()

	deadline := time.Now().Add(10 * time.Second)
	for {
		done := true
		for i := range numSessions {
			if counts[i].Load() != msgsPerSession {
				done = false
				break
			}
		}
		if done {
			break
		}
		if time.Now().After(deadline) {
			for i := range numSessions {
				t.Logf("session %d received %d/%d", i, counts[i].Load(), msgsPerSession)
			}
			t.Fatal("messages were not fully delivered")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Fatal transport error: every run() goroutine exits; closeCleanup must
	// run exactly once (sync.Once) without panicking on close(m.done).
	close(io.dead)
	select {
	case <-m.done:
	case <-time.After(5 * time.Second):
		t.Fatal("manager done channel was not closed")
	}
	m.mutex.RLock()
	closed := m.closed
	m.mutex.RUnlock()
	if !closed {
		t.Fatal("manager not marked closed after transport death")
	}
	for i, c := range conns {
		if _, ok := <-c.ReceiveCh; ok {
			t.Fatalf("session %d ReceiveCh still open after cleanup", i)
		}
	}
}
