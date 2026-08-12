package tuic

import (
	"testing"
	"time"
)

// TestPushBackFullDoesNotBlock 回归测试：队列满时 PushBack 必须丢弃而非阻塞，
// 否则唯一的解复用 goroutine 会停摆（head-of-line blocking）。
func TestPushBackFullDoesNotBlock(t *testing.T) {
	p := NewPackets()
	for i := 0; i < packetChanCap; i++ {
		p.PushBack(NewPacket(0, 0, 0, 0, 0, nil, nil, 0))
	}
	done := make(chan struct{})
	go func() {
		p.PushBack(NewPacket(0, 0, 0, 0, 0, nil, nil, 0))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("PushBack blocked on full queue (head-of-line blocking)")
	}

	// 队列仍可正常消费（丢弃不影响既有数据）。
	for i := 0; i < packetChanCap; i++ {
		pkt, closed := p.PopFrontBlock()
		if closed || pkt == nil {
			t.Fatalf("PopFrontBlock #%d: closed=%v pkt=%v", i, closed, pkt)
		}
	}
}
