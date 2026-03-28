package shadowtls

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	shadowtls "github.com/sagernet/sing-shadowtls"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
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

	version, err := parseVersion(u, query)
	if err != nil {
		return nil, nil, err
	}

	password := parsePassword(u, query)
	if version >= 2 && password == "" {
		return nil, nil, fmt.Errorf("missing shadow-tls password")
	}

	sni := query.Get("sni")
	if sni == "" {
		sni = query.Get("host")
	}
	if sni == "" {
		sni = u.Hostname()
	}

	skipVerify := parseAllowInsecure(query)
	if option != nil && option.AllowInsecure {
		skipVerify = true
	}

	s := &ShadowTLS{
		nextDialer: nextDialer,
		addr:       u.Host,
		version:    version,
		password:   password,
		sni:        sni,
		skipVerify: skipVerify,
	}

	var d netproxy.Dialer = s
	innerCipher := strings.ToLower(query.Get("inner-cipher"))
	if innerCipher != "" {
		innerPassword := query.Get("inner-ss-pass")
		if innerPassword == "" {
			innerPassword = query.Get("inner-password")
		}
		if innerPassword == "" {
			return nil, nil, fmt.Errorf("missing inner shadowsocks password")
		}

		nextDialerName, err := shadowsocksProtocolName(innerCipher)
		if err != nil {
			return nil, nil, err
		}

		innerHost := query.Get("inner-ss-host")
		if innerHost == "" {
			innerHost = query.Get("inner-host")
		}
		if innerHost == "" {
			innerHost = u.Hostname()
		}

		innerPort := query.Get("inner-ss-port")
		if innerPort == "" {
			innerPort = query.Get("inner-port")
		}
		if innerPort == "" {
			innerPort = u.Port()
		}
		if innerPort == "" {
			return nil, nil, fmt.Errorf("missing inner shadowsocks port")
		}

		d, err = protocol.NewDialer(nextDialerName, s, protocol.Header{
			ProxyAddress: net.JoinHostPort(innerHost, innerPort),
			Cipher:       innerCipher,
			Password:     innerPassword,
			IsClient:     true,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("create inner shadowsocks dialer: %w", err)
		}
	}

	return d, &dialer.Property{
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

func parseVersion(u *url.URL, query url.Values) (int, error) {
	if value := query.Get("version"); value != "" {
		version, err := strconv.Atoi(value)
		if err != nil {
			return 0, fmt.Errorf("invalid version: %w", err)
		}
		return version, nil
	}
	if u.User != nil {
		username := u.User.Username()
		if isVersionMarker(username) {
			version, err := strconv.Atoi(username[1:])
			if err != nil {
				return 0, fmt.Errorf("invalid version marker: %w", err)
			}
			return version, nil
		}
	}
	return 3, nil
}

func parsePassword(u *url.URL, query url.Values) string {
	keys := []string{"password", "passwd", "pwd"}
	for _, key := range keys {
		if value := query.Get(key); value != "" {
			return value
		}
	}
	if u.User != nil {
		username := u.User.Username()
		if !isVersionMarker(username) {
			return username
		}
	}
	return ""
}

func isVersionMarker(value string) bool {
	if len(value) < 2 || value[0] != 'v' {
		return false
	}
	_, err := strconv.Atoi(value[1:])
	return err == nil
}

func shadowsocksProtocolName(cipher string) (string, error) {
	switch cipher {
	case "aes-256-gcm", "aes-128-gcm", "chacha20-poly1305", "chacha20-ietf-poly1305":
		return "shadowsocks", nil
	case "2022-blake3-aes-256-gcm", "2022-blake3-aes-128-gcm", "2022-blake3-chacha20-poly1305":
		return "shadowsocks_2022", nil
	case "aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "aes-128-ofb", "aes-192-ofb", "aes-256-ofb", "des-cfb", "bf-cfb", "cast5-cfb", "rc4-md5", "rc4-md5-6", "chacha20", "chacha20-ietf", "salsa20", "camellia-128-cfb", "camellia-192-cfb", "camellia-256-cfb", "idea-cfb", "rc2-cfb", "seed-cfb", "rc4", "none", "plain":
		return "shadowsocks_stream", nil
	default:
		return "", fmt.Errorf("unsupported shadowsocks encryption method: %v", cipher)
	}
}
