package juicity

import (
	"testing"

	"github.com/daeuniverse/outbound/protocol/trojanc"
)

func TestConnTransportDoneReturnsConfiguredChannel(t *testing.T) {
	done := make(chan struct{})
	conn := NewConn(nil, &trojanc.Metadata{}, nil, done)

	if got := conn.TransportDone(); got != done {
		t.Fatal("expected juicity stream conn to expose configured transport done channel")
	}
}

func TestPacketConnTransportDoneForwardsConnLifecycle(t *testing.T) {
	done := make(chan struct{})
	pc := &PacketConn{
		Conn: NewConn(nil, &trojanc.Metadata{}, nil, done),
	}

	if got := pc.TransportDone(); got != done {
		t.Fatal("expected juicity packet conn to forward underlying transport done channel")
	}
}
