package shadowsocks_2022

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
)

type nopDialer struct{}

func (nopDialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	return nil, nil
}

func pskBase64(length int, v byte) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = v
	}
	return base64.StdEncoding.EncodeToString(b)
}

func TestNewDialer_UnsupportedCipher(t *testing.T) {
	_, err := NewDialer(nopDialer{}, protocol.Header{
		Cipher:       "2022-blake3-chacha20-poly1305-unknown",
		Password:     pskBase64(32, 0x11),
		ProxyAddress: "127.0.0.1:443",
	})
	if err == nil || !strings.Contains(err.Error(), "unsupported shadowsocks 2022 cipher") {
		t.Fatalf("expected unsupported cipher error, got: %v", err)
	}
}

func TestNewDialer_Chacha20SinglePSK(t *testing.T) {
	_, err := NewDialer(nopDialer{}, protocol.Header{
		Cipher:       "2022-blake3-chacha20-poly1305",
		Password:     pskBase64(32, 0x11),
		ProxyAddress: "127.0.0.1:443",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewDialer_Chacha20MultiPSK(t *testing.T) {
	_, err := NewDialer(nopDialer{}, protocol.Header{
		Cipher:       "2022-blake3-chacha20-poly1305",
		Password:     strings.Join([]string{pskBase64(32, 0x11), pskBase64(32, 0x12)}, ":"),
		ProxyAddress: "127.0.0.1:443",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewDialer_TooManyPSKs(t *testing.T) {
	keys := make([]string, maxPSKListLength+1)
	for i := range keys {
		keys[i] = pskBase64(16, byte(i+1))
	}
	_, err := NewDialer(nopDialer{}, protocol.Header{
		Cipher:       "2022-blake3-aes-128-gcm",
		Password:     strings.Join(keys, ":"),
		ProxyAddress: "127.0.0.1:443",
	})
	if err == nil || !strings.Contains(err.Error(), "too many PSKs") {
		t.Fatalf("expected too many PSKs error, got: %v", err)
	}
}

func TestNewDialer_ValidMultiPSK(t *testing.T) {
	_, err := NewDialer(nopDialer{}, protocol.Header{
		Cipher:       "2022-blake3-aes-256-gcm",
		Password:     strings.Join([]string{pskBase64(32, 0x21), pskBase64(32, 0x22)}, ":"),
		ProxyAddress: "127.0.0.1:443",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewDialer_Chacha20MultiPSKHasEIH(t *testing.T) {
	// Test that chacha multi-PSK creates EIH components
	netproxyDialer, err := NewDialer(nopDialer{}, protocol.Header{
		Cipher:       "2022-blake3-chacha20-poly1305",
		Password:     strings.Join([]string{pskBase64(32, 0x11), pskBase64(32, 0x12), pskBase64(32, 0x13)}, ":"),
		ProxyAddress: "127.0.0.1:443",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	d := netproxyDialer.(*Dialer)

	// Verify EIH is enabled
	if !d.core.HasMultiPSK() {
		t.Fatal("expected HasMultiPSK to be true for multi-PSK chacha")
	}

	// Verify EIH length: 3 PSKs = 2 EIH blocks * 16 bytes = 32 bytes
	expectedEIHLen := 2 * 16
	if d.core.IdentityHeaderLen() != expectedEIHLen {
		t.Fatalf("expected EIH length %d, got %d", expectedEIHLen, d.core.IdentityHeaderLen())
	}

	// Verify IsUsingBlockCipher returns false for chacha
	if d.core.IsUsingBlockCipher() {
		t.Fatal("expected IsUsingBlockCipher to be false for chacha")
	}
}

func TestNewDialer_AESMultiPSKHasEIH(t *testing.T) {
	// Test that AES multi-PSK still works correctly
	netproxyDialer, err := NewDialer(nopDialer{}, protocol.Header{
		Cipher:       "2022-blake3-aes-256-gcm",
		Password:     strings.Join([]string{pskBase64(32, 0x21), pskBase64(32, 0x22), pskBase64(32, 0x23)}, ":"),
		ProxyAddress: "127.0.0.1:443",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	d := netproxyDialer.(*Dialer)

	// Verify EIH is enabled
	if !d.core.HasMultiPSK() {
		t.Fatal("expected HasMultiPSK to be true for multi-PSK AES")
	}

	// Verify EIH length: 3 PSKs = 2 EIH blocks * 16 bytes = 32 bytes
	expectedEIHLen := 2 * 16
	if d.core.IdentityHeaderLen() != expectedEIHLen {
		t.Fatalf("expected EIH length %d, got %d", expectedEIHLen, d.core.IdentityHeaderLen())
	}

	// Verify IsUsingBlockCipher returns true for AES
	if !d.core.IsUsingBlockCipher() {
		t.Fatal("expected IsUsingBlockCipher to be true for AES")
	}
}

func TestNewDialer_SinglePSKNoEIH(t *testing.T) {
	// Test that single PSK doesn't create EIH for both AES and Chacha
	testCases := []struct {
		name   string
		cipher string
		psk    string
	}{
		{"chacha_single", "2022-blake3-chacha20-poly1305", pskBase64(32, 0x11)},
		{"aes256_single", "2022-blake3-aes-256-gcm", pskBase64(32, 0x21)},
		{"aes128_single", "2022-blake3-aes-128-gcm", pskBase64(16, 0x31)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			netproxyDialer, err := NewDialer(nopDialer{}, protocol.Header{
				Cipher:       tc.cipher,
				Password:     tc.psk,
				ProxyAddress: "127.0.0.1:443",
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			d := netproxyDialer.(*Dialer)

			// Verify EIH is not enabled for single PSK
			if d.core.HasMultiPSK() {
				t.Fatal("expected HasMultiPSK to be false for single PSK")
			}

			// Verify EIH length is 0
			if d.core.IdentityHeaderLen() != 0 {
				t.Fatalf("expected EIH length 0, got %d", d.core.IdentityHeaderLen())
			}
		})
	}
}
