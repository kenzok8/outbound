package tuic

import (
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/outbound/pool/bytes"
	"github.com/olicesx/quic-go"
)

func fragWriteNative(quicConn quic.Connection, packet *Packet, buf *bytes.Buffer, fragSize int) (err error) {
	fullPayload := packet.DATA
	off := 0
	fragID := uint8(0)
	if fragSize == 0 {
		fragSize = 1
	}
	fragCount := uint8((len(fullPayload) + fragSize - 1) / fragSize) // round up
	packet.FRAG_TOTAL = fragCount
	for off < len(fullPayload) {
		payloadSize := len(fullPayload) - off
		if payloadSize > fragSize {
			payloadSize = fragSize
		}
		frag := packet
		frag.FRAG_ID = fragID
		frag.SIZE = uint16(payloadSize)
		frag.DATA = fullPayload[off : off+payloadSize]
		off += payloadSize
		fragID++
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
		packet.ADDR.TYPE = AtypNone // avoid "fragment 2/2: address in non-first fragment"
	}
	return
}

type deFragger struct {
	pkgID          uint16
	frags          []*Packet
	count          uint8
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
		d.count = 1
		d.frags[m.FRAG_ID] = m
	} else if d.frags[m.FRAG_ID] == nil {
		d.frags[m.FRAG_ID] = m
		d.count++
		if int(d.count) == len(d.frags) {
			// all fragments received, assemble
			for _, frag := range d.frags {
				if n >= len(p) {
					break
				}
				n += copy(p[n:], frag.DATA)
			}
			d.count = 0
			return n, d.frags[0].ADDR.UDPAddr().AddrPort(), true
		}
	}
	return
}
