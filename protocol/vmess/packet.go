package vmess

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/daeuniverse/outbound/pool"
)

func (c *Conn) ReadFrom(p []byte) (n int, addr netip.AddrPort, err error) {
	buf := pool.Get(MaxUDPSize)
	defer pool.Put(buf)
	n, err = c.read(buf)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}

	if c.metadata.IsPacketAddr() {
		addrTyp, address, err := ExtractPacketAddr(buf)
		addrLen := PacketAddrLength(addrTyp)
		if n < addrLen {
			return 0, netip.AddrPort{}, fmt.Errorf("not enough data to read for PacketAddr")
		}
		copy(p, buf[addrLen:n])
		return n - addrLen, address, err
	} else {
		tgt, err := c.dialTargetAddrPort()
		if err != nil {
			return 0, netip.AddrPort{}, err
		}
		copy(p, buf[:n])
		return n, tgt, err
	}
}

func (c *Conn) WriteTo(p []byte, addr string) (n int, err error) {
	if c.metadata.IsPacketAddr() {
		// VMess packet addr does not support domain.
		address, err := c.writeTargetAddrPort(addr)
		if err != nil {
			return 0, err
		}
		packetAddrLen := UDPAddrToPacketAddrLength(address)
		buf := pool.Get(packetAddrLen + len(p))
		defer pool.Put(buf)

		err = PutPacketAddr(buf, address)
		if err != nil {
			return 0, err
		}
		copy(buf[packetAddrLen:], p)
		return c.write(buf)
	}

	return c.write(p)
}

func (c *Conn) writeTargetAddrPort(addr string) (*net.UDPAddr, error) {
	if addr == c.dialTgt {
		target, err := c.dialTargetAddrPort()
		if err != nil {
			return nil, err
		}
		return net.UDPAddrFromAddrPort(target), nil
	}
	if cached, ok := c.writeCache.Load(addr); ok {
		return net.UDPAddrFromAddrPort(cached), nil
	}
	target, err := resolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	addrPort := target.AddrPort()
	c.writeCache.Store(addr, addrPort)
	return target, nil
}
