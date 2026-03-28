package shadowtls

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strconv"

	shadowtls "github.com/sagernet/sing-shadowtls"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
)

func init() {
	dialer.FromLinkRegister("shadow-tls", NewShadowTLS)
	dialer.FromLinkRegister("shadowtls", NewShadowTLS)
}

type ShadowTLS struct {
	nextDialer netproxy.Dialer
	addr       string
	version    int
	password   string
	sni        string
	skipVerify bool
}

func NewShadowTLS(option *dialer.ExtraOption, nextDialer netproxy.Dialer, link string) (netproxy.Dialer, *dialer.Property, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, nil, err
	}
	if u.Host == "" {
		return nil, nil, fmt.Errorf("missing shadow-tls server address")
	}
	if _, _, err = net.SplitHostPort(u.Host); err != nil {
		return nil, nil, fmt.Errorf("invalid shadow-tls server address %q: %w", u.Host, err)
	}

	query := u.Query()

	version := 3
	if v := query.Get("version"); v != "" {
		version, err = strconv.Atoi(v)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid version: %w", err)
		}
	}

	sni := query.Get("sni")
	if sni == "" {
		sni = u.Hostname()
	}

	skipVerify := parseAllowInsecure(query)
	if option != nil && option.AllowInsecure {
		skipVerify = true
	}

	password := ""
	if u.User != nil {
		password = u.User.Username()
	}

	s := &ShadowTLS{
		nextDialer: nextDialer,
		addr:       u.Host,
		version:    version,
		password:   password,
		sni:        sni,
		skipVerify: skipVerify,
	}

	return s, &dialer.Property{
		Name:     u.Fragment,
		Address:  u.Host,
		Protocol: "shadow-tls",
		Link:     link,
	}, nil
}

func (s *ShadowTLS) DialContext(ctx context.Context, network string, addr string) (netproxy.Conn, error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	if magicNetwork.Network != "tcp" {
		return nil, netproxy.UnsupportedTunnelTypeError
	}

	// Dial the underlying connection to the shadow-tls server
	conn, err := s.nextDialer.DialContext(ctx, magicNetwork.Encode(), s.addr)
	if err != nil {
		return nil, err
	}

	// Wrap netproxy.Conn to net.Conn for sing-shadowtls
	netConn := &connToNetConn{Conn: conn}

	// Build TLS handshake function
	var tlsHandshakeFunc shadowtls.TLSHandshakeFunc
	switch s.version {
	case 1:
		// V1: standard TLS 1.2 handshake (no session ID generator needed)
		tlsConfig := &tls.Config{
			NextProtos:         []string{"h2", "http/1.1"},
			MinVersion:         tls.VersionTLS12,
			MaxVersion:         tls.VersionTLS12,
			InsecureSkipVerify: s.skipVerify,
			ServerName:         s.sni,
		}
		tlsHandshakeFunc = func(ctx context.Context, conn net.Conn, _ shadowtls.TLSSessionIDGeneratorFunc) error {
			tlsConn := tls.Client(conn, tlsConfig)
			return tlsConn.HandshakeContext(ctx)
		}
	case 2, 3:
		// V2/V3: use DefaultTLSHandshakeFunc from sing-shadowtls
		// This uses the internal TLS library with SessionIDGenerator support
		tlsConfig := &tls.Config{
			NextProtos:         []string{"h2", "http/1.1"},
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: s.skipVerify,
			ServerName:         s.sni,
		}
		tlsHandshakeFunc = shadowtls.DefaultTLSHandshakeFunc(s.password, tlsConfig)
	default:
		conn.Close()
		return nil, fmt.Errorf("unsupported shadow-tls version: %d", s.version)
	}

	// Create shadow-tls client
	host, portStr, err := net.SplitHostPort(s.addr)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("invalid shadow-tls server address %q: %w", s.addr, err)
	}
	portValue, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("invalid shadow-tls server port %q: %w", portStr, err)
	}
	client, err := shadowtls.NewClient(shadowtls.ClientConfig{
		Version:      s.version,
		Password:     s.password,
		Server:       M.ParseSocksaddrHostPort(host, uint16(portValue)),
		TLSHandshake: tlsHandshakeFunc,
		Logger:       logger.NOP(),
	})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("shadow-tls NewClient: %w", err)
	}

	// Use DialContextConn since we already have the TCP connection
	shadowConn, err := client.DialContextConn(ctx, netConn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("shadow-tls handshake: %w", err)
	}

	return &netConnToConn{Conn: shadowConn}, nil
}

// connToNetConn wraps netproxy.Conn to implement net.Conn
type connToNetConn struct {
	netproxy.Conn
}

func (c *connToNetConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4zero, Port: 0}
}

func (c *connToNetConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4zero, Port: 0}
}

// netConnToConn wraps net.Conn to implement netproxy.Conn
type netConnToConn struct {
	net.Conn
}

func parseAllowInsecure(query url.Values) bool {
	keys := []string{"allowInsecure", "allow_insecure", "allowinsecure", "skipVerify", "skip-cert-verify"}
	for _, key := range keys {
		if value := query.Get(key); value != "" {
			allowInsecure, _ := strconv.ParseBool(value)
			if allowInsecure {
				return true
			}
		}
	}
	return false
}
