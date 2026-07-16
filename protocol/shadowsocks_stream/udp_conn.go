package shadowsocks_stream

import (
	"fmt"
	"net/netip"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/common"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/infra/socks"
)

// UdpConn the struct that override the netproxy.Conn methods
type UdpConn struct {
	netproxy.PacketConn
	cipher      *ciphers.StreamCipher
	defaultAddr socks.Addr
	proxyAddr   string
	targetAddr  common.LastStringValue[socks.Addr]
}

var _ netproxy.PacketReceiver = (*UdpConn)(nil)

func (c *UdpConn) RegisterPacketReceiver(handler netproxy.PacketReceiveHandler) (func(), bool) {
	receiver, ok := c.PacketConn.(netproxy.PacketReceiver)
	if !ok {
		return nil, false
	}
	return netproxy.RegisterMappedPacketReceiver(receiver, handler, c.mapReceivedPacket)
}

func (c *UdpConn) mapReceivedPacket(packet *netproxy.ReceivedPacket) (*netproxy.ReceivedPacket, bool) {
	if packet.Err != nil {
		return packet, true
	}
	if len(packet.Data) < c.cipher.InfoIVLen() {
		packet.Err = fmt.Errorf("packet too short")
		packet.Data = nil
		return packet, true
	}
	dec, err := c.cipher.NewDecryptor(packet.Data[:c.cipher.InfoIVLen()])
	if err != nil {
		packet.Err = err
		packet.Data = nil
		return packet, true
	}
	data := packet.Data[c.cipher.InfoIVLen():]
	dec.XORKeyStream(data, data)
	addr := socks.SplitAddr(data)
	if addr == nil {
		packet.Err = fmt.Errorf("no addr present")
		packet.Data = nil
		return packet, true
	}
	from, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		packet.Err = fmt.Errorf("bad addr: %w", err)
		packet.Data = nil
		return packet, true
	}
	packet.Data = data[len(addr):]
	packet.From = from
	return packet, true
}

var parseSocksAddr = socks.ParseAddr

func NewUdpConn(c netproxy.PacketConn, cipher *ciphers.StreamCipher, defaultAddr socks.Addr, proxyAddr string) *UdpConn {
	return &UdpConn{
		PacketConn:  c,
		cipher:      cipher,
		defaultAddr: defaultAddr,
		proxyAddr:   proxyAddr,
	}
}

func (c *UdpConn) Cipher() *ciphers.StreamCipher {
	return c.cipher
}

func (c *UdpConn) ReadFrom(b []byte) (n int, from netip.AddrPort, err error) {
	n, _, err = c.PacketConn.ReadFrom(b)
	if err != nil {
		return n, netip.AddrPort{}, err
	}

	if n < c.cipher.InfoIVLen() {
		return 0, netip.AddrPort{}, fmt.Errorf("packet too short")
	}
	dec, err := c.cipher.NewDecryptor(b[:c.cipher.InfoIVLen()])
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	data := b[c.cipher.InfoIVLen():n]
	dec.XORKeyStream(data, data)

	addr := socks.SplitAddr(data)
	if addr == nil {
		return 0, netip.AddrPort{}, fmt.Errorf("no addr present")
	}

	from, err = netip.ParseAddrPort(addr.String())
	if err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("bad addr: %w", err)
	}

	n = copy(b, data[len(addr):])

	return n, from, nil
}

func (c *UdpConn) writeTo(p []byte, addr socks.Addr) (n int, err error) {
	infoIvLen := c.cipher.InfoIVLen()
	buf := pool.Get(infoIvLen + len(addr) + len(p))
	defer pool.Put(buf)
	enc, err := c.cipher.NewEncryptor(buf)
	if err != nil {
		return 0, err
	}
	copy(buf[infoIvLen:], addr)
	copy(buf[infoIvLen+len(addr):], p)
	enc.XORKeyStream(buf[infoIvLen:], buf[infoIvLen:])
	if _, err = c.PacketConn.WriteTo(buf, c.proxyAddr); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *UdpConn) WriteTo(p []byte, to string) (n int, err error) {
	addr, err := c.cachedTargetAddr(to)
	if err != nil {
		return 0, err
	}
	return c.writeTo(p, addr)
}

func (c *UdpConn) cachedTargetAddr(addr string) (socks.Addr, error) {
	if cached, ok := c.targetAddr.Load(addr); ok {
		return cached, nil
	}
	target, err := parseSocksAddr(addr)
	if err != nil {
		return nil, err
	}
	target = append(socks.Addr(nil), target...)
	c.targetAddr.Store(addr, target)
	return target, nil
}

func (c *UdpConn) Write(b []byte) (n int, err error) {
	return c.writeTo(b, c.defaultAddr)
}

func (c *UdpConn) WriteTransport(p []byte) (n int, err error) {
	infoIvLen := c.cipher.InfoIVLen()
	buf := pool.Get(infoIvLen + len(p))
	defer pool.Put(buf)
	enc, err := c.cipher.NewEncryptor(buf)
	if err != nil {
		return 0, err
	}
	copy(buf[infoIvLen:], p)
	enc.XORKeyStream(buf[infoIvLen:], buf[infoIvLen:])
	if _, err = c.PacketConn.WriteTo(buf, c.proxyAddr); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *UdpConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return n, err
}

func (c *UdpConn) ReadTransport(b []byte) (n int, err error) {

	n, _, err = c.PacketConn.ReadFrom(b)
	if err != nil {
		return n, err
	}

	if n < c.cipher.InfoIVLen() {
		return 0, fmt.Errorf("packet too short")
	}
	dec, err := c.cipher.NewDecryptor(b[:c.cipher.InfoIVLen()])
	if err != nil {
		return 0, err
	}
	data := b[c.cipher.InfoIVLen():n]
	dec.XORKeyStream(data, data)

	n = copy(b, data)

	return n, err
}

type UdpTransportConn struct {
	*UdpConn
}

var _ netproxy.PacketReceiver = (*UdpTransportConn)(nil)

func (c *UdpTransportConn) RegisterPacketReceiver(handler netproxy.PacketReceiveHandler) (func(), bool) {
	receiver, ok := c.PacketConn.(netproxy.PacketReceiver)
	if !ok {
		return nil, false
	}
	return netproxy.RegisterMappedPacketReceiver(receiver, handler, c.mapTransportPacket)
}

func (c *UdpTransportConn) mapTransportPacket(packet *netproxy.ReceivedPacket) (*netproxy.ReceivedPacket, bool) {
	if packet.Err != nil {
		return packet, true
	}
	if len(packet.Data) < c.cipher.InfoIVLen() {
		packet.Err = fmt.Errorf("packet too short")
		packet.Data = nil
		return packet, true
	}
	dec, err := c.cipher.NewDecryptor(packet.Data[:c.cipher.InfoIVLen()])
	if err != nil {
		packet.Err = err
		packet.Data = nil
		return packet, true
	}
	data := packet.Data[c.cipher.InfoIVLen():]
	dec.XORKeyStream(data, data)
	packet.Data = data
	packet.From = netip.AddrPort{}
	return packet, true
}

func (c *UdpTransportConn) WriteTo(p []byte, to string) (n int, err error) {
	return c.WriteTransport(p)
}

func (c *UdpTransportConn) Write(b []byte) (n int, err error) {
	return c.WriteTransport(b)
}

func (c *UdpTransportConn) Read(b []byte) (n int, err error) {
	return c.ReadTransport(b)
}

func (c *UdpTransportConn) ReadFrom(b []byte) (n int, from netip.AddrPort, err error) {
	n, err = c.ReadTransport(b)
	return n, netip.AddrPort{}, err
}
