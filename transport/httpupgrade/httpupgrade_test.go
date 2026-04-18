package httpupgrade

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

type stallingUpgradeDialer struct {
	server net.Conn
}

func (d *stallingUpgradeDialer) DialContext(context.Context, string, string) (netproxy.Conn, error) {
	client, server := net.Pipe()
	d.server = server
	go func() {
		var req bytes.Buffer
		buf := make([]byte, 256)
		for !bytes.Contains(req.Bytes(), []byte("\r\n\r\n")) {
			n, err := server.Read(buf)
			if n > 0 {
				_, _ = req.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
		_, _ = server.Read(make([]byte, 1))
	}()
	return client, nil
}

func TestDialContextUpgradeResponseRespectsDeadline(t *testing.T) {
	parent := &stallingUpgradeDialer{}
	t.Cleanup(func() {
		if parent.server != nil {
			_ = parent.server.Close()
		}
	})

	dialer := &Dialer{
		nextDialer: parent,
		host:       "proxy.example",
		path:       "/upgrade",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := dialer.DialContext(ctx, "tcp", "proxy.example:80")
	if err == nil {
		t.Fatal("DialContext() error = nil, want timeout")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("DialContext() took %v, want deadline-bound failure", elapsed)
	}
}
