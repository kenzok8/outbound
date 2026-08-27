package trojanc

import (
	"bytes"
	"io"
	"testing"

	"github.com/daeuniverse/outbound/protocol"
)

func TestClientReadDoesNotConsumeRequestHeader(t *testing.T) {
	payload := []byte("payload-bytes")
	raw := bytes.NewBuffer(payload)
	c := &Conn{
		Conn:      &bufferConn{Buffer: raw},
		metadata:  Metadata{Metadata: protocol.Metadata{IsClient: true}, Network: "tcp"},
		onceWrite: true, // skip the client-side request-header write on first Read
	}
	got := make([]byte, len(payload))
	n, err := c.Read(got)
	if err != nil && err != io.EOF {
		t.Fatalf("client Read: %v", err)
	}
	if string(got[:n]) != string(payload) {
		t.Fatalf("client Read consumed a request header: got %q want %q", got[:n], payload)
	}
}

func TestServerReadParsesRequestHeaderThenPayload(t *testing.T) {
	server := &Conn{
		Conn:     &captureConn{},
		metadata: Metadata{Metadata: protocol.Metadata{IsClient: false}, Network: "tcp"},
		pass:     getPasswordHash("secret"),
	}
	clientUnderlay := &captureConn{}
	client := &Conn{
		Conn: clientUnderlay,
		metadata: Metadata{
			Metadata: protocol.Metadata{
				Type:     protocol.MetadataTypeIPv4,
				Hostname: "203.0.113.10",
				Port:     443,
				IsClient: true,
			},
			Network: "tcp",
		},
		pass: getPasswordHash("secret"),
	}
	payload := []byte("hello-from-client")
	if _, err := client.Write(payload); err != nil {
		t.Fatalf("client Write: %v", err)
	}

	server.Conn = &bufferConn{Buffer: bytes.NewBuffer(clientUnderlay.Bytes())}
	got := make([]byte, len(payload))
	n, err := server.Read(got)
	if err != nil && err != io.EOF {
		t.Fatalf("server Read: %v", err)
	}
	if string(got[:n]) != string(payload) {
		t.Fatalf("server payload = %q, want %q", got[:n], payload)
	}
	if server.metadata.Hostname != "203.0.113.10" {
		t.Fatalf("parsed hostname = %q", server.metadata.Hostname)
	}
	if server.metadata.Port != 443 {
		t.Fatalf("parsed port = %d", server.metadata.Port)
	}
}

func TestHeaderErrorIsStickyAfterPartialConsume(t *testing.T) {
	// 10 bytes is enough to start the 56-byte password, then EOF.
	raw := bytes.NewBuffer([]byte("short-head"))
	c := &Conn{
		Conn:     &bufferConn{Buffer: raw},
		metadata: Metadata{Metadata: protocol.Metadata{IsClient: false}, Network: "tcp"},
		pass:     getPasswordHash("secret"),
	}
	_, err := c.Read(make([]byte, 8))
	if err == nil {
		t.Fatal("expected header read error")
	}
	_, err2 := c.Read(make([]byte, 8))
	if err2 != err {
		t.Fatalf("second Read = %v, want sticky %v", err2, err)
	}
}
