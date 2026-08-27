package tuic

import (
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/outbound/pool/bytes"
	"github.com/olicesx/quic-go"
)

// fragmentPackets splits one oversized packet into per-fragment Packet
// copies. Fragment 0 keeps the original address pointer; every later
// fragment carries a value copy of the address with TYPE set to AtypNone,
// so the caller's shared *Address is never mutated.
func fragmentPackets(packet *Packet, fragSize int) []*Packet {
	fullPayload := packet.DATA
	fragCount := uint8((len(fullPayload) + fragSize - 1) / fragSize)
	packet.FRAG_TOTAL = fragCount
	frags := make([]*Packet, 0, int(fragCount))
	for off := 0; off < len(fullPayload); {
		payloadSize := len(fullPayload) - off
		if payloadSize > fragSize {
			payloadSize = fragSize
		}
		var fragAddr *Address
		if off == 0 {
			// Fragment 0 must carry the address on the wire.
			fragAddr = packet.ADDR
		} else {
			addrCopy := *packet.ADDR
			addrCopy.TYPE = AtypNone // avoid "fragment 2/2: address in non-first fragment"
			fragAddr = &addrCopy
		}
		frag := *packet
		frag.ADDR = fragAddr
		frag.FRAG_ID = uint8(len(frags))
		frag.SIZE = uint16(payloadSize)
		frag.DATA = fullPayload[off : off+payloadSize]
		frags = append(frags, &frag)
		off += payloadSize
	}
	return frags
}

func fragWriteNative(quicConn quic.Connection, packet *Packet, buf *bytes.Buffer, fragSize int) (err error) {
	if fragSize == 0 {
		fragSize = 1
	}
	frags := fragmentPackets(packet, fragSize)
	for _, frag := range frags {
		buf.Reset()
		err = frag.WriteTo(buf)
		if err != nil {
			return
		}
		data := buf.Bytes()
		err = quicConn.SendDatagram(data)
		if err != nil {
			return
		}
	}
	return
}

type deFragger struct {
	pkgID          uint16
	frags          []*Packet
	count          uint8
	firstAddrPort  netip.AddrPort
	hasFirstFrag   bool
	lastUpdateNano atomic.Int64
}

func newDeFragger(nowNano int64) *deFragger {
	d := &deFragger{}
	d.touch(nowNano)
	return d
}

func (d *deFragger) touch(nowNano int64) {
	if nowNano == 0 {
		nowNano = time.Now().UnixNano()
	}
	d.lastUpdateNano.Store(nowNano)
}

func (d *deFragger) IsExpired(nowNano int64, ttl time.Duration) bool {
	if ttl <= 0 {
		return false
	}
	lastUpdateNano := d.lastUpdateNano.Load()
	return lastUpdateNano > 0 && nowNano-lastUpdateNano >= ttl.Nanoseconds()
}

func packetFragmentAddrPort(packet *Packet) netip.AddrPort {
	if packet == nil || packet.ADDR == nil || packet.ADDR.TYPE == AtypNone {
		return netip.AddrPort{}
	}
	return packet.ADDR.UDPAddr().AddrPort()
}

func (d *deFragger) matches(packet *Packet) bool {
	if packet == nil || packet.FRAG_TOTAL <= 1 {
		return false
	}
	if d.count == 0 {
		return true
	}
	if d.pkgID != packet.PKT_ID || len(d.frags) != int(packet.FRAG_TOTAL) {
		return false
	}
	if packet.FRAG_ID >= packet.FRAG_TOTAL {
		return false
	}
	if packet.FRAG_ID == 0 {
		if !d.hasFirstFrag {
			return true
		}
		addrPort := packetFragmentAddrPort(packet)
		return addrPort.IsValid() && d.firstAddrPort == addrPort
	}
	return d.frags[packet.FRAG_ID] == nil
}

func (d *deFragger) Feed(m *Packet, p []byte, nowNano int64) (n int, addrPort netip.AddrPort, assembled bool) {
	d.touch(nowNano)
	if m.FRAG_TOTAL <= 1 {
		return copy(p, m.DATA), m.ADDR.UDPAddr().AddrPort(), true
	}
	if m.FRAG_ID >= m.FRAG_TOTAL {
		// wtf is this?
		return
	}
	if d.count == 0 {
		// new message, clear previous state
		d.pkgID = m.PKT_ID
		d.frags = make([]*Packet, m.FRAG_TOTAL)
		d.count = 0
		d.firstAddrPort = netip.AddrPort{}
		d.hasFirstFrag = false
	}
	if len(d.frags) != int(m.FRAG_TOTAL) {
		return
	}
	if m.FRAG_ID == 0 {
		if addr := packetFragmentAddrPort(m); addr.IsValid() {
			d.firstAddrPort = addr
			d.hasFirstFrag = true
		}
	}
	if d.frags[m.FRAG_ID] == nil {
		d.frags[m.FRAG_ID] = m
		d.count++
		if int(d.count) == len(d.frags) && d.hasFirstFrag {
			// all fragments received, assemble
			for _, frag := range d.frags {
				if n >= len(p) {
					break
				}
				n += copy(p[n:], frag.DATA)
			}
			d.count = 0
			return n, d.firstAddrPort, true
		}
	}
	return
}
