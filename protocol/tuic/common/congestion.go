package common

import (
	"github.com/daeuniverse/outbound/protocol/tuic/congestion"
	"github.com/olicesx/quic-go"
)

const (
	InitialStreamReceiveWindow     = 8 * 1024 * 1024  // 8 MB (fast start)
	MaxStreamReceiveWindow         = 32 * 1024 * 1024 // 32MB - netem sweep peak (same quic-go engine as hysteria2)
	InitialConnectionReceiveWindow = 12 * 1024 * 1024 // 12 MB (reduced from 20MB, enough for 1-2 concurrent streams)
	MaxConnectionReceiveWindow     = 64 * 1024 * 1024 // 64MB - stream x2, measured peak combo
)

func SetCongestionController(quicConn quic.Connection, cc string, cwnd int) {
	switch cc {
	default:
		fallthrough
	case "bbr":
		congestion.UseBBR(quicConn)
	}
}
