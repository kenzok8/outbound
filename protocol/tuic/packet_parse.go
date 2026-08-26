package tuic

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/daeuniverse/outbound/pool"
)

// readPacketFromMessage parses a TUIC Packet command from its wire-format
// message (CommandHead + Packet fields + Address + DATA) using direct slice
// indexing, avoiding the per-call bytes.Reader allocation and binary.Read
// reflection overhead that dominate ReadPacket/ReadPacketWithHead.
//
// Hot path: processDatagram calls this for every inbound UDP datagram.
//
// Allocations: 4 (Packet + Address + ADDR slice + DATA slice), down from
// 12 via the reader+binary.Read path.
func readPacketFromMessage(msg []byte) (*Packet, error) {
	// VER(1) + TYPE(1) + ASSOC_ID(2) + PKT_ID(2) + FRAG_TOTAL(1) + FRAG_ID(1) + SIZE(2)
	const fixedLen = 2 + 2 + 2 + 1 + 1 + 2
	if len(msg) < fixedLen {
		return nil, fmt.Errorf("tuic: packet too short: %d bytes", len(msg))
	}
	if typ := CommandType(msg[1]); typ != PacketType {
		return nil, fmt.Errorf("tuic: not a packet command: %s", typ)
	}
	ver := msg[0]
	off := 2
	assocId := binary.BigEndian.Uint16(msg[off:])
	off += 2
	pktId := binary.BigEndian.Uint16(msg[off:])
	off += 2
	fragTotal := msg[off]
	off += 1
	fragId := msg[off]
	off += 1
	size := binary.BigEndian.Uint16(msg[off:])
	off += 2

	addr, n, err := readAddressFromSlice(msg[off:])
	if err != nil {
		return nil, err
	}
	off += n

	var data []byte
	dataFromPool := false
	if size > 0 {
		if len(msg[off:]) < int(size) {
			return nil, fmt.Errorf("tuic: data truncated: need %d have %d", size, len(msg[off:]))
		}
		// Unfragmented packets take DATA from the pool to avoid a per-datagram
		// heap allocation scaling with payload size. Fragmented packets keep make:
		// their DATA is sliced during reassembly (frag.go) and outlives the parse,
		// which the pool cannot track safely.
		if fragTotal <= 1 {
			data = pool.Get(int(size))
			dataFromPool = true
		} else {
			data = make([]byte, size)
		}
		copy(data, msg[off:off+int(size)])
	}

	return &Packet{
		CommandHead:  &CommandHead{VER: ver, TYPE: PacketType},
		ASSOC_ID:     assocId,
		PKT_ID:       pktId,
		FRAG_TOTAL:   fragTotal,
		FRAG_ID:      fragId,
		SIZE:         size,
		ADDR:         addr,
		DATA:         data,
		dataFromPool: dataFromPool,
	}, nil
}

// readAddressFromSlice parses an Address directly from a byte slice,
// returning the Address, the number of bytes consumed, and any error.
// Avoids the BufferedReader interface and io.ReadFull overhead.
func readAddressFromSlice(msg []byte) (*Address, int, error) {
	if len(msg) < 1 {
		return nil, 0, fmt.Errorf("tuic: address type byte missing")
	}
	typ := msg[0]
	off := 1
	var addr []byte
	switch typ {
	case AtypIPv4:
		const addrLen = net.IPv4len
		if len(msg[off:]) < addrLen+2 {
			return nil, 0, fmt.Errorf("tuic: ipv4 address too short")
		}
		addr = make([]byte, addrLen)
		copy(addr, msg[off:])
		off += addrLen
	case AtypIPv6:
		const addrLen = net.IPv6len
		if len(msg[off:]) < addrLen+2 {
			return nil, 0, fmt.Errorf("tuic: ipv6 address too short")
		}
		addr = make([]byte, addrLen)
		copy(addr, msg[off:])
		off += addrLen
	case AtypDomainName:
		if len(msg[off:]) < 1 {
			return nil, 0, fmt.Errorf("tuic: domain length byte missing")
		}
		addrLen := int(msg[off])
		if len(msg[off:]) < 1+addrLen+2 {
			return nil, 0, fmt.Errorf("tuic: domain address too short")
		}
		addr = make([]byte, 1+addrLen)
		addr[0] = byte(addrLen)
		copy(addr[1:], msg[off+1:off+1+addrLen])
		off += 1 + addrLen
	case AtypNone:
		// Address type None: no ADDR, no PORT (used on non-first fragments).
		return &Address{TYPE: typ}, off, nil
	default:
		return nil, 0, fmt.Errorf("tuic: unknown address type: %#x", typ)
	}
	if len(msg[off:]) < 2 {
		return nil, 0, fmt.Errorf("tuic: address port missing")
	}
	port := binary.BigEndian.Uint16(msg[off:])
	off += 2
	return &Address{TYPE: typ, ADDR: addr, PORT: port}, off, nil
}

// readPacketFromStream parses a TUIC Packet command from a stream that
// carries exactly one command (a udp_relay_mode=quic uni stream). It mirrors
// readPacketFromMessage's field and pooling semantics while reading
// incrementally, keeping the per-datagram bufio.Reader allocation and the
// binary.Read reflection of the ReadPacketWithHead path out of the QUIC
// relay hot path.
func readPacketFromStream(r io.Reader) (*Packet, error) {
	// VER(1) + TYPE(1) + ASSOC_ID(2) + PKT_ID(2) + FRAG_TOTAL(1) + FRAG_ID(1) + SIZE(2)
	var head [10]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, err
	}
	if typ := CommandType(head[1]); typ != PacketType {
		return nil, fmt.Errorf("tuic: not a packet command: %s", typ)
	}
	assocId := binary.BigEndian.Uint16(head[2:4])
	pktId := binary.BigEndian.Uint16(head[4:6])
	fragTotal := head[6]
	fragId := head[7]
	size := binary.BigEndian.Uint16(head[8:10])

	addr, err := readAddressFromStream(r)
	if err != nil {
		return nil, err
	}

	var data []byte
	dataFromPool := false
	if size > 0 {
		// Same split as readPacketFromMessage: unfragmented packets take
		// DATA from the pool; fragmented packets keep make because their
		// DATA is sliced during reassembly and outlives the parse.
		if fragTotal <= 1 {
			data = pool.Get(int(size))
			dataFromPool = true
		} else {
			data = make([]byte, size)
		}
		if _, err := io.ReadFull(r, data); err != nil {
			if dataFromPool {
				pool.Put(data)
			}
			return nil, err
		}
	}

	return &Packet{
		CommandHead:  &CommandHead{VER: head[0], TYPE: PacketType},
		ASSOC_ID:     assocId,
		PKT_ID:       pktId,
		FRAG_TOTAL:   fragTotal,
		FRAG_ID:      fragId,
		SIZE:         size,
		ADDR:         addr,
		DATA:         data,
		dataFromPool: dataFromPool,
	}, nil
}

// readAddressFromStream reads an Address from r with the same wire layout
// readAddressFromSlice consumes from a buffer.
func readAddressFromStream(r io.Reader) (*Address, error) {
	var typeByte [1]byte
	if _, err := io.ReadFull(r, typeByte[:]); err != nil {
		return nil, err
	}
	addr := &Address{TYPE: typeByte[0]}
	switch addr.TYPE {
	case AtypIPv4:
		var rest [net.IPv4len + 2]byte
		if _, err := io.ReadFull(r, rest[:]); err != nil {
			return nil, err
		}
		addr.ADDR = append([]byte(nil), rest[:net.IPv4len]...)
		addr.PORT = binary.BigEndian.Uint16(rest[net.IPv4len:])
	case AtypIPv6:
		var rest [net.IPv6len + 2]byte
		if _, err := io.ReadFull(r, rest[:]); err != nil {
			return nil, err
		}
		addr.ADDR = append([]byte(nil), rest[:net.IPv6len]...)
		addr.PORT = binary.BigEndian.Uint16(rest[net.IPv6len:])
	case AtypDomainName:
		var lenByte [1]byte
		if _, err := io.ReadFull(r, lenByte[:]); err != nil {
			return nil, err
		}
		addrLen := int(lenByte[0])
		var rest []byte
		if addrLen+2 > 0 {
			rest = make([]byte, addrLen+2)
			if _, err := io.ReadFull(r, rest); err != nil {
				return nil, err
			}
		}
		addr.ADDR = make([]byte, 1+addrLen)
		addr.ADDR[0] = lenByte[0]
		copy(addr.ADDR[1:], rest[:addrLen])
		addr.PORT = binary.BigEndian.Uint16(rest[addrLen:])
	case AtypNone:
		// Address type None: no ADDR, no PORT (non-first fragments).
	default:
		return nil, fmt.Errorf("tuic: unknown address type: %#x", addr.TYPE)
	}
	return addr, nil
}
