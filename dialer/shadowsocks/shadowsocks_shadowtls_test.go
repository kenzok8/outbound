package shadowsocks

import (
	"context"
	stderrors "errors"
	"net/url"
	"strings"
	"testing"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	_ "github.com/daeuniverse/outbound/protocol/shadowsocks"
)

type noopDialer struct{}

func (noopDialer) DialContext(_ context.Context, _, _ string) (netproxy.Conn, error) {
	return nil, stderrors.New("noop dialer")
}

func TestParseSip003ShadowTLSNoOpts(t *testing.T) {
	plugin := ParseSip003("shadowtls")
	if plugin.Name != "shadow-tls" {
		t.Fatalf("unexpected plugin name: %q", plugin.Name)
	}
}

func TestParseSip003ShadowTLSOpts(t *testing.T) {
	plugin := ParseSip003("shadow-tls;password=secret;version=3;host=example.com;sni=cdn.example.com;allowInsecure=true")
	if plugin.Name != "shadow-tls" {
		t.Fatalf("unexpected plugin name: %q", plugin.Name)
	}
	if plugin.Opts.Password != "secret" {
		t.Fatalf("unexpected password: %q", plugin.Opts.Password)
	}
	if plugin.Opts.Version != "3" {
		t.Fatalf("unexpected version: %q", plugin.Opts.Version)
	}
	if plugin.Opts.Host != "example.com" {
		t.Fatalf("unexpected host: %q", plugin.Opts.Host)
	}
	if plugin.Opts.SNI != "cdn.example.com" {
		t.Fatalf("unexpected sni: %q", plugin.Opts.SNI)
	}
	if plugin.Opts.AllowInsecure != "true" {
		t.Fatalf("unexpected allowInsecure: %q", plugin.Opts.AllowInsecure)
	}
}

func TestShadowsocksDialerWithShadowTLSPlugin(t *testing.T) {
	s := &Shadowsocks{
		Server:   "127.0.0.1",
		Port:     443,
		Password: "ss-password",
		Cipher:   "aes-128-gcm",
		Plugin:   ParseSip003("shadowtls;password=stls-password;version=3;host=example.com"),
		Protocol: "shadowsocks",
	}

	_, property, err := s.Dialer(&dialer.ExtraOption{}, noopDialer{})
	if err != nil {
		t.Fatalf("dialer creation failed: %v", err)
	}
	if property == nil {
		t.Fatal("dialer property is nil")
	}
	if !strings.Contains(property.Link, "plugin=shadow-tls") {
		t.Fatalf("unexpected exported link: %q", property.Link)
	}
	if !strings.Contains(property.Link, "password%3Dstls-password") {
		t.Fatalf("plugin options are missing from exported link: %q", property.Link)
	}
}

func TestParseSSURL_DecodesPercentEncodedPassword(t *testing.T) {
	password := "RCF/0OOYmo6crue3LwlEyD8izLAbuUuyPic/vasJH/o="
	link := (&url.URL{
		Scheme:   "ss",
		User:     url.UserPassword("2022-blake3-aes-256-gcm", password),
		Host:     "127.0.0.1:443",
		Fragment: "test",
	}).String()

	parsed, err := ParseSSURL(link)
	if err != nil {
		t.Fatalf("ParseSSURL failed: %v", err)
	}
	if parsed.Cipher != "2022-blake3-aes-256-gcm" {
		t.Fatalf("unexpected cipher: %q", parsed.Cipher)
	}
	if parsed.Password != password {
		t.Fatalf("unexpected password: got %q want %q", parsed.Password, password)
	}
}
