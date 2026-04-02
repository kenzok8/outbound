package client

import (
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
