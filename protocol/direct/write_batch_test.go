package direct

import (
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/stretchr/testify/require"
)

// TestDirectPacketConnWriteBatchConnected verifies sendmmsg batching on a
// connected (non-FullCone) UDP socket: several datagrams flushed in one
// WriteBatch call, each arriving intact at the connected peer.
func TestDirectPacketConnWriteBatchConnected(t *testing.T) {
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP(server): %v", err)
	}
	defer func() { _ = server.Close() }()

	client, err := net.DialUDP("udp", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("DialUDP(client): %v", err)
	}
	defer func() { _ = client.Close() }()

	conn := &directPacketConn{UDPConn: client, FullCone: false}
	_ = server.SetReadDeadline(time.Now().Add(3 * time.Second))

	want := []string{"a", "bb", "ccc", "dddd"}
	items := make([]netproxy.BatchItem, len(want))
	for i, w := range want {
		items[i] = netproxy.BatchItem{Data: []byte(w), Addr: ""}
	}
	n, err := conn.WriteBatch(items)
	require.NoError(t, err)
	require.Equal(t, len(want), n)

	for i, w := range want {
		buf := make([]byte, 32)
		rn, _, err := server.ReadFromUDP(buf)
		require.NoError(t, err)
		require.Equal(t, w, string(buf[:rn]), "payload #%d", i)
	}
}

// TestDirectPacketConnWriteBatchFullCone verifies per-item destinations on a
// FullCone socket: each datagram must land on its own Addr.
func TestDirectPacketConnWriteBatchFullCone(t *testing.T) {
	serverA, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP(serverA): %v", err)
	}
	defer func() { _ = serverA.Close() }()
	serverB, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP(serverB): %v", err)
	}
	defer func() { _ = serverB.Close() }()

	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP(client): %v", err)
	}
	defer func() { _ = client.Close() }()

	oldResolveUDPAddr := resolveUDPAddr
	resolveUDPAddr = func(_ *net.Resolver, addr string) (*net.UDPAddr, error) {
		if addr == "a.example:53" {
			return serverA.LocalAddr().(*net.UDPAddr), nil
		}
		return net.ResolveUDPAddr("udp", addr)
	}
	defer func() { resolveUDPAddr = oldResolveUDPAddr }()

	conn := &directPacketConn{
		UDPConn:  client,
		FullCone: true,
		dialTgt:  "a.example:53",
		resolver: net.DefaultResolver,
	}
	_ = serverA.SetReadDeadline(time.Now().Add(3 * time.Second))
	_ = serverB.SetReadDeadline(time.Now().Add(3 * time.Second))

	addrB := serverB.LocalAddr().(*net.UDPAddr).String()
	items := []netproxy.BatchItem{
		{Data: []byte("to-a"), Addr: "a.example:53"},
		{Data: []byte("to-b"), Addr: addrB},
	}
	n, err := conn.WriteBatch(items)
	require.NoError(t, err)
	require.Equal(t, 2, n)

	buf := make([]byte, 32)
	rn, _, err := serverA.ReadFromUDP(buf)
	require.NoError(t, err)
	require.Equal(t, "to-a", string(buf[:rn]))

	rn, _, err = serverB.ReadFromUDP(buf)
	require.NoError(t, err)
	require.Equal(t, "to-b", string(buf[:rn]))
}
