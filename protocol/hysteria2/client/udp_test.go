package client

import (
	"bytes"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/frag"
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
	largePayload := make([]byte, redundantSendThreshold+1) // above redundancy threshold → single send
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := u.WriteTo(largePayload, "127.0.0.1:443"); err != nil {
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

func TestUDPConnPacketReceiverDrainsQueuedMessage(t *testing.T) {
	targetAddr := netip.MustParseAddrPort("192.0.2.10:5353")
	u := &udpConn{
		ID:         1,
		D:          &frag.Defragger{},
		ReceiveCh:  make(chan *protocol.UDPMessage, 2),
		target:     targetAddr.String(),
		targetAddr: targetAddr,
	}
	u.ReceiveCh <- &protocol.UDPMessage{
		SessionID: 1,
		FragCount: 1,
		Addr:      "192.0.2.10:5353",
		Data:      []byte("queued"),
	}

	packets := make(chan *netproxy.ReceivedPacket, 1)
	unregister, ok := u.RegisterPacketReceiver(func(packet *netproxy.ReceivedPacket) bool {
		packets <- packet
		return true
	})
	if !ok || unregister == nil {
		t.Fatal("expected packet receiver registration")
	}
	defer unregister()

	select {
	case packet := <-packets:
		if string(packet.Data) != "queued" {
			t.Fatalf("packet data = %q, want queued", packet.Data)
		}
		if packet.From.String() != "192.0.2.10:5353" {
			t.Fatalf("packet address = %v", packet.From)
		}
		packet.Release()
	case <-time.After(time.Second):
		t.Fatal("packet receiver did not drain queued message")
	}
}

func TestUDPSessionManagerUsesPacketReceiverForNewMessages(t *testing.T) {
	m := &udpSessionManager{
		io:     noopUDPTestIO{},
		m:      make(map[uint32]*udpConn),
		nextID: 1,
		done:   make(chan struct{}),
	}
	connRaw, err := m.NewUDP("192.0.2.20:443")
	if err != nil {
		t.Fatalf("NewUDP returned error: %v", err)
	}
	u := connRaw.(*udpConn)
	packets := make(chan *netproxy.ReceivedPacket, 1)
	unregister, ok := u.RegisterPacketReceiver(func(packet *netproxy.ReceivedPacket) bool {
		packets <- packet
		return true
	})
	if !ok {
		t.Fatal("expected packet receiver registration")
	}
	defer func() {
		unregister()
		_ = u.Close()
	}()

	m.feed(&protocol.UDPMessage{
		SessionID: u.ID,
		FragCount: 1,
		Addr:      "198.51.100.8:443",
		Data:      []byte("transport-owned"),
	})
	select {
	case packet := <-packets:
		if string(packet.Data) != "transport-owned" {
			t.Fatalf("packet data = %q, want transport-owned", packet.Data)
		}
		packet.Release()
	case <-time.After(time.Second):
		t.Fatal("session manager did not use registered packet receiver")
	}
	if got := len(u.ReceiveCh); got != 0 {
		t.Fatalf("ReceiveCh length = %d, want 0 when receiver is registered", got)
	}
}

func TestUDPConnSetDeadlineZeroClearsTimer(t *testing.T) {
	var closes atomic.Int32
	u := &udpConn{
		ReceiveCh: make(chan *protocol.UDPMessage, 1),
		CloseFunc: func() { closes.Add(1) },
	}

	if err := u.SetDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
		t.Fatalf("SetDeadline() error = %v", err)
	}
	if err := u.SetDeadline(time.Time{}); err != nil {
		t.Fatalf("SetDeadline(zero) error = %v", err)
	}
	time.Sleep(75 * time.Millisecond)
	if got := closes.Load(); got != 0 {
		t.Fatalf("CloseFunc calls after clearing deadline = %d, want 0", got)
	}
}

func TestUDPConnCloseStopsDeadlineTimer(t *testing.T) {
	var closes atomic.Int32
	u := &udpConn{
		ReceiveCh: make(chan *protocol.UDPMessage, 1),
		CloseFunc: func() { closes.Add(1) },
	}

	if err := u.SetDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
		t.Fatalf("SetDeadline() error = %v", err)
	}
	if err := u.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	time.Sleep(75 * time.Millisecond)
	if got := closes.Load(); got != 1 {
		t.Fatalf("CloseFunc calls after Close() = %d, want 1", got)
	}
}

func TestUDPConnDeadlineClosesSession(t *testing.T) {
	var closes atomic.Int32
	var closeOnce sync.Once
	u := &udpConn{
		ID:        1,
		D:         &frag.Defragger{},
		ReceiveCh: make(chan *protocol.UDPMessage, 1),
	}
	u.CloseFunc = func() {
		closes.Add(1)
		closeOnce.Do(func() { close(u.ReceiveCh) })
	}

	if err := u.SetDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
		t.Fatalf("SetDeadline() error = %v", err)
	}

	select {
	case msg := <-u.ReceiveCh:
		if msg != nil {
			t.Fatalf("ReceiveCh yielded %v, want closed channel", msg)
		}
	case <-time.After(time.Second):
		t.Fatal("deadline did not close UDP session")
	}
	if got := closes.Load(); got != 1 {
		t.Fatalf("CloseFunc calls after deadline = %d, want 1", got)
	}
}

func TestUDPConnDeadlineCanBeAppliedWhileReadIsPending(t *testing.T) {
	var closes atomic.Int32
	var closeOnce sync.Once
	u := &udpConn{
		ID:        1,
		D:         &frag.Defragger{},
		ReceiveCh: make(chan *protocol.UDPMessage, 1),
	}
	u.CloseFunc = func() {
		closes.Add(1)
		closeOnce.Do(func() { close(u.ReceiveCh) })
	}

	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 64)
		_, _, err := u.ReadFrom(buf)
		errCh <- err
	}()

	time.Sleep(20 * time.Millisecond)
	if err := u.SetReadDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}

	select {
	case err := <-errCh:
		if err != io.EOF {
			t.Fatalf("ReadFrom() error = %T %v, want EOF after close", err, err)
		}
	case <-time.After(time.Second):
		t.Fatal("ReadFrom did not unblock after deadline closed the session")
	}
	if got := closes.Load(); got != 1 {
		t.Fatalf("CloseFunc calls after pending read deadline = %d, want 1", got)
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

	// 3/4 of the queue depth: large enough to prove burst absorption, small
	// enough to leave headroom for the concurrent feed path.
	const burst = udpMessageChanSize * 3 / 4
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

func TestUDPConnRedundantSend(t *testing.T) {
	// Small packets (≤ redundantSendThreshold) should trigger redundant sends.
	// Large packets should not.
	// Redundant copies are sent via time.AfterFunc, so we need to wait.
	tests := []struct {
		name      string
		payloadSz int
		wantCalls int // 1 + redundantSendCopies for small, 1 for large
	}{
		{"small=128", 128, 1 + redundantSendCopies},
		{"threshold=256", redundantSendThreshold, 1 + redundantSendCopies},
		{"large=257", redundantSendThreshold + 1, 1},
		{"large=1024", 1024, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls atomic.Int32
			u := &udpConn{
				ID:        1,
				ReceiveCh: make(chan *protocol.UDPMessage, 1),
				SendBuf:   make([]byte, protocol.MaxUDPSize),
				SendFunc: func(buf []byte, msg *protocol.UDPMessage) error {
					calls.Add(1)
					return nil
				},
				CloseFunc: func() {},
				target:    "127.0.0.1:443",
			}
			payload := make([]byte, tt.payloadSz)
			if _, err := u.WriteTo(payload, "127.0.0.1:443"); err != nil {
				t.Fatalf("WriteTo error: %v", err)
			}
			// Wait for delayed redundant copies to fire.
			// Max delay = redundantSendInterval × redundantSendCopies + scheduling slack.
			time.Sleep(redundantSendInterval*time.Duration(redundantSendCopies) + 100*time.Millisecond)
			if got := calls.Load(); int(got) != tt.wantCalls {
				t.Fatalf("SendFunc calls: got %d want %d", got, tt.wantCalls)
			}
		})
	}
}
