package common

import (
	"github.com/daeuniverse/outbound/protocol/tuic/congestion"
	"github.com/olicesx/quic-go"
)

const (
	InitialStreamReceiveWindow     = 8 * 1024 * 1024  // 8 MB (fast start)
	MaxStreamReceiveWindow         = 12 * 1024 * 1024 // 12 MB (limits per-stream buffer, still > cross-border BDP ~6MB)
	InitialConnectionReceiveWindow = 12 * 1024 * 1024 // 12 MB (reduced from 20MB, enough for 1-2 concurrent streams)
	MaxConnectionReceiveWindow     = 20 * 1024 * 1024 // 20 MB (reduced from 32MB, caps total QUIC buffer)
)

func SetCongestionController(quicConn quic.Connection, cc string, cwnd int) {
	switch cc {
	default:
		fallthrough
	case "bbr":
		congestion.UseBBR(quicConn)
	}
}
