package http

import (
	"testing"

	"golang.org/x/net/http2"
)

func TestH2ConnsPoolMarkDeadCleansUpEmptyAddressState(t *testing.T) {
	pool := newH2ConnsPool()
	addr := "proxy.example:443"
	pool.h2ConnsPool[addr] = newLockedList()
	pool.registerAddrToDialerMapping(addr, noopDialer{})
	pool.registerAddrToMagicNetworkMapping(addr, "tcp")

	h2c := &http2.ClientConn{}
	pool.h2ConnsPool[addr].mu.Lock()
	ele := pool.h2ConnsPool[addr].l.PushFront(&h2Conn{h2Conn: h2c})
	pool.h2ConnsPool[addr].mu.Unlock()
	pool.h2Conn2Ident[h2c] = &poolIdent{ele: ele, addr: addr}

	pool.MarkDead(h2c)

	if _, ok := pool.h2ConnsPool[addr]; ok {
		t.Fatal("expected empty connection list to be removed")
	}
	if _, ok := pool.addr2Dialer.Load(addr); ok {
		t.Fatal("expected dialer mapping to be removed")
	}
	if _, ok := pool.addr2Somark.Load(addr); ok {
		t.Fatal("expected magic-network mapping to be removed")
	}
}

func TestH2ConnsPoolMarkDeadKeepsAddressStateWhileConnListIsInUse(t *testing.T) {
	pool := newH2ConnsPool()
	addr := "proxy.example:443"
	conns := newLockedList()
	pool.h2ConnsPool[addr] = conns
	pool.registerAddrToDialerMapping(addr, noopDialer{})
	pool.registerAddrToMagicNetworkMapping(addr, "tcp")

	oldH2 := &http2.ClientConn{}
	conns.mu.Lock()
	oldEle := conns.l.PushFront(&h2Conn{h2Conn: oldH2})
	conns.mu.Unlock()
	pool.h2Conn2Ident[oldH2] = &poolIdent{ele: oldEle, addr: addr}

	inUseConns, cached := pool.acquireConnList(addr)
	if !cached {
		t.Fatal("expected existing connection list to be reused")
	}
	if inUseConns != conns {
		t.Fatal("expected acquireConnList to return the existing list")
	}

	pool.MarkDead(oldH2)

	if got := pool.h2ConnsPool[addr]; got != conns {
		t.Fatal("expected MarkDead to keep the address state while GetConn still holds a reference")
	}
	if _, ok := pool.addr2Dialer.Load(addr); !ok {
		t.Fatal("expected dialer mapping to remain while list is in use")
	}
	if _, ok := pool.addr2Somark.Load(addr); !ok {
		t.Fatal("expected magic-network mapping to remain while list is in use")
	}

	newH2 := &http2.ClientConn{}
	conns.mu.Lock()
	newEle := conns.l.PushFront(&h2Conn{h2Conn: newH2})
	conns.mu.Unlock()
	pool.h2Conn2Ident[newH2] = &poolIdent{ele: newEle, addr: addr}

	pool.releaseConnList(addr, inUseConns)

	if got := pool.h2ConnsPool[addr]; got != conns {
		t.Fatal("expected address state to remain after a replacement h2 connection is added")
	}
	if _, ok := pool.addr2Dialer.Load(addr); !ok {
		t.Fatal("expected dialer mapping to remain after replacement h2 connection is added")
	}
	if _, ok := pool.addr2Somark.Load(addr); !ok {
		t.Fatal("expected magic-network mapping to remain after replacement h2 connection is added")
	}
}

func TestH2ConnsPoolReleaseConnListCleansUpDeferredEmptyAddressState(t *testing.T) {
	pool := newH2ConnsPool()
	addr := "proxy.example:443"
	conns := newLockedList()
	pool.h2ConnsPool[addr] = conns
	pool.registerAddrToDialerMapping(addr, noopDialer{})
	pool.registerAddrToMagicNetworkMapping(addr, "tcp")

	inUseConns, cached := pool.acquireConnList(addr)
	if !cached {
		t.Fatal("expected existing connection list to be reused")
	}
	if inUseConns != conns {
		t.Fatal("expected acquireConnList to return the existing list")
	}

	pool.releaseConnList(addr, inUseConns)

	if _, ok := pool.h2ConnsPool[addr]; ok {
		t.Fatal("expected deferred cleanup to remove the empty connection list once the last reference is released")
	}
	if _, ok := pool.addr2Dialer.Load(addr); ok {
		t.Fatal("expected deferred cleanup to remove the dialer mapping")
	}
	if _, ok := pool.addr2Somark.Load(addr); ok {
		t.Fatal("expected deferred cleanup to remove the magic-network mapping")
	}
}
