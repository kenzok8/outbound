package frag

import (
	"github.com/daeuniverse/outbound/protocol/hysteria2/internal/protocol"
)

func FragUDPMessage(m *protocol.UDPMessage, maxSize int) []protocol.UDPMessage {
	if m.Size() <= maxSize {
		return []protocol.UDPMessage{*m}
	}
	fullPayload := m.Data
	maxPayloadSize := maxSize - m.HeaderSize()
	off := 0
	fragID := uint8(0)
	fragCount := uint8((len(fullPayload) + maxPayloadSize - 1) / maxPayloadSize) // round up
	frags := make([]protocol.UDPMessage, fragCount)
	for off < len(fullPayload) {
		payloadSize := len(fullPayload) - off
		if payloadSize > maxPayloadSize {
			payloadSize = maxPayloadSize
		}
		frag := *m
		frag.FragID = fragID
		frag.FragCount = fragCount
		frag.Data = fullPayload[off : off+payloadSize]
		frags[fragID] = frag
		off += payloadSize
		fragID++
	}
	return frags
}

// Defragger handles the defragmentation of UDP messages.
// The current implementation can only handle one packet ID at a time.
// If another packet arrives before a packet has received all fragments
// in their entirety, any previous state is discarded.
type Defragger struct {
	pktID uint16
	frags []*protocol.UDPMessage
	count uint8
	size  int // data size
}

func (d *Defragger) Feed(m *protocol.UDPMessage) *protocol.UDPMessage {
	if m.FragCount <= 1 {
		return m
	}
	if m.FragID >= m.FragCount {
		// wtf is this?
		if m.Release != nil {
			m.Release()
		}
		return nil
	}
	if m.PacketID != d.pktID || m.FragCount != uint8(len(d.frags)) {
		// new message, clear previous state: release the buffers of any
		// fragments that were still pending reassembly.
		d.releasePending()
		d.pktID = m.PacketID
		d.frags = make([]*protocol.UDPMessage, m.FragCount)
		d.frags[m.FragID] = m
		d.count = 1
		d.size = len(m.Data)
	} else if d.frags[m.FragID] == nil {
		d.frags[m.FragID] = m
		d.count++
		d.size += len(m.Data)
		if int(d.count) == len(d.frags) {
			// all fragments received, assemble
			data := make([]byte, d.size)
			off := 0
			for _, frag := range d.frags {
				off += copy(data[off:], frag.Data)
			}
			// The assembled payload lives in the freshly allocated data
			// slice; every fragment's backing buffer can now be returned
			// to its pool. The trigger fragment's Release must be cleared:
			// its buffer was already released by releaseAll, and the
			// caller will (correctly) invoke Release on the returned
			// message - double-returning the same buffer to the pool
			// would hand one buffer to two consumers.
			d.releaseAll()
			m.Data = data
			m.FragID = 0
			m.FragCount = 1
			m.Release = nil
			return m
		}
	}
	return nil
}

// releasePending returns the pooled storage of fragments that are still held
// for reassembly. Used when a new message supersedes an incomplete one.
func (d *Defragger) releasePending() {
	for _, frag := range d.frags {
		if frag != nil && frag.Release != nil {
			frag.Release()
		}
	}
	d.frags = nil
	d.count = 0
	d.size = 0
}

// releaseAll returns the pooled storage of every fragment that contributed to
// a completed reassembly, including the fragment that triggered it.
func (d *Defragger) releaseAll() {
	for _, frag := range d.frags {
		if frag != nil && frag.Release != nil {
			frag.Release()
		}
	}
	d.frags = nil
	d.count = 0
	d.size = 0
}

// Close returns any fragments still held for reassembly to their pools.
// Called when the owning session dies with an incomplete message in flight;
// without this, those pooled datagram buffers would be retained until the
// session object itself is garbage collected.
func (d *Defragger) Close() {
	d.releasePending()
}
