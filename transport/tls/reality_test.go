package tls

import (
	"crypto/ecdh"
	"crypto/rand"
	"testing"

	utls "github.com/refraction-networking/utls"
)

func mustGenerateX25519Key(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate x25519 key: %v", err)
	}
	return key
}

func TestRealityECDHEKeyPrefersKeyShareKeysEcdhe(t *testing.T) {
	key := mustGenerateX25519Key(t)
	state := &utls.PubClientHandshakeState{
		State13: utls.TLS13OnlyState{
			KeyShareKeys: &utls.KeySharePrivateKeys{
				Ecdhe: key,
			},
		},
	}

	if got := realityECDHEKey(state); got != key {
		t.Fatalf("expected key from KeyShareKeys.Ecdhe")
	}
}

func TestRealityECDHEKeyFallsBackToMlkemEcdhe(t *testing.T) {
	key := mustGenerateX25519Key(t)
	state := &utls.PubClientHandshakeState{
		State13: utls.TLS13OnlyState{
			KeyShareKeys: &utls.KeySharePrivateKeys{
				MlkemEcdhe: key,
			},
		},
	}

	if got := realityECDHEKey(state); got != key {
		t.Fatalf("expected key from KeyShareKeys.MlkemEcdhe")
	}
}

func TestRealityECDHEKeyFallsBackToDeprecatedField(t *testing.T) {
	key := mustGenerateX25519Key(t)
	state := &utls.PubClientHandshakeState{
		State13: utls.TLS13OnlyState{
			EcdheKey: key,
		},
	}

	if got := realityECDHEKey(state); got != key {
		t.Fatalf("expected key from deprecated EcdheKey field")
	}
}
