package client

import (
	"bytes"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/protocol"
)

type noopUDPTestIO struct{}

func (noopUDPTestIO) ReceiveMessage() (*protocol.UDPMessage, error)  { return nil, nil }
func (noopUDPTestIO) SendMessage([]byte, *protocol.UDPMessage) error { return nil }

func TestUDPConnWriteToSerializesSendFunc(t *testing.T) {
	t.Helper()

	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	secondEntered := make(chan struct{}, 1)

	var active atomic.Int32
	var calls atomic.Int32

	u := &udpConn{
		ID:        1,
		ReceiveCh: make(chan *protocol.UDPMessage, 1),
		SendBuf:   make([]byte, protocol.MaxUDPSize),
		SendFunc: func(buf []byte, msg *protocol.UDPMessage) error {
			if len(buf) != protocol.MaxUDPSize {
				t.Fatalf("unexpected send buffer length: got %d want %d", len(buf), protocol.MaxUDPSize)
			}

			if active.Add(1) > 1 {
				select {
				case secondEntered <- struct{}{}:
				default:
				}
			}

			if calls.Add(1) == 1 {
				close(firstEntered)
				<-releaseFirst
			}

			active.Add(-1)
			return nil
		},
		CloseFunc: func() {},
		target:    "127.0.0.1:443",
	}

	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := u.WriteTo([]byte("payload"), "127.0.0.1:443"); err != nil {
				t.Errorf("WriteTo returned error: %v", err)
			}
		}()
	}

	select {
	case <-firstEntered:
	case <-time.After(time.Second):
		t.Fatal("first WriteTo did not enter SendFunc")
	}

	select {
	case <-secondEntered:
		t.Fatal("SendFunc entered concurrently for the same udpConn")
	case <-time.After(150 * time.Millisecond):
	}

	close(releaseFirst)
	wg.Wait()

	if got := calls.Load(); got != 2 {
		t.Fatalf("unexpected SendFunc call count: got %d want 2", got)
	}
}

func TestUDPSessionManagerTransportDoneClosesWithManager(t *testing.T) {
	m := &udpSessionManager{
		io:     noopUDPTestIO{},
		m:      make(map[uint32]*udpConn),
		nextID: 1,
		done:   make(chan struct{}),
	}

	connRaw, err := m.NewUDP("127.0.0.1:53")
	if err != nil {
		t.Fatalf("NewUDP returned error: %v", err)
	}
	conn, ok := connRaw.(*udpConn)
	if !ok {
		t.Fatalf("unexpected conn type: %T", connRaw)
	}
	if got := conn.TransportDone(); got != m.done {
		t.Fatal("expected UDP session to expose manager transport done channel")
	}

	m.closeCleanup()

	select {
	case <-conn.TransportDone():
	case <-time.After(time.Second):
		t.Fatal("expected manager cleanup to close transport done channel")
	}
}

func TestUDPConnWriteToFragmentsWhenLocalSendBufferIsTooSmall(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 64)
	addr := "203.0.113.10:40000"

	var sent []protocol.UDPMessage
	u := &udpConn{
		ID:        7,
		ReceiveCh: make(chan *protocol.UDPMessage, 1),
		SendBuf:   make([]byte, 32),
		SendFunc: func(_ []byte, msg *protocol.UDPMessage) error {
			msgCopy := *msg
			msgCopy.Data = append([]byte(nil), msg.Data...)
			sent = append(sent, msgCopy)
			return nil
		},
		CloseFunc: func() {},
		target:    addr,
	}

	n, err := u.WriteTo(payload, addr)
	if err != nil {
		t.Fatalf("WriteTo() error = %v", err)
	}
	if n != len(payload) {
		t.Fatalf("WriteTo() n = %d, want %d", n, len(payload))
	}
	if len(sent) < 2 {
		t.Fatalf("expected fragmentation to emit multiple messages, got %d", len(sent))
	}

	var reassembled []byte
	for i, msg := range sent {
		if got := msg.Size(); got > len(u.SendBuf) {
			t.Fatalf("fragment %d size = %d, want <= %d", i, got, len(u.SendBuf))
		}
		reassembled = append(reassembled, msg.Data...)
	}
	if !bytes.Equal(reassembled, payload) {
		t.Fatalf("reassembled payload mismatch: got %d bytes want %d", len(reassembled), len(payload))
	}
}

func TestUDPSessionManagerQueueAbsorbsModerateBurstWithoutDrop(t *testing.T) {
	m := &udpSessionManager{
		io:     noopUDPTestIO{},
		m:      make(map[uint32]*udpConn),
		nextID: 1,
		done:   make(chan struct{}),
	}

	connRaw, err := m.NewUDP("127.0.0.1:53")
	if err != nil {
		t.Fatalf("NewUDP() error = %v", err)
	}
	conn := connRaw.(*udpConn)

	const burst = 1536
	if burst >= udpMessageChanSize {
		t.Fatalf("burst = %d must stay below queue size %d", burst, udpMessageChanSize)
	}

	for i := 0; i < burst; i++ {
		m.feed(&protocol.UDPMessage{
			SessionID: conn.ID,
			PacketID:  uint16(i + 1),
			FragID:    0,
			FragCount: 1,
			Addr:      "127.0.0.1:53",
			Data:      []byte{byte(i)},
		})
	}

	if got := len(conn.ReceiveCh); got != burst {
		t.Fatalf("queued messages = %d, want %d", got, burst)
	}

	m.closeCleanup()
}
