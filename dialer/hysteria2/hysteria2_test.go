package hysteria2

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPinnedCertVerifierMatchesLeafOnly(t *testing.T) {
	leaf := []byte("leaf-cert")
	intermediate := []byte("intermediate-cert")

	leafHash := sha256.Sum256(leaf)
	verify := newPinnedCertVerifier(hex.EncodeToString(leafHash[:]))
	if err := verify([][]byte{leaf, intermediate}, nil); err != nil {
		t.Fatalf("verify() error = %v", err)
	}
}

func TestPinnedCertVerifierRejectsPinnedIntermediate(t *testing.T) {
	leaf := []byte("leaf-cert")
	intermediate := []byte("intermediate-cert")

	intermediateHash := sha256.Sum256(intermediate)
	verify := newPinnedCertVerifier(hex.EncodeToString(intermediateHash[:]))
	if err := verify([][]byte{leaf, intermediate}, nil); err == nil {
		t.Fatal("expected verifier to reject non-leaf certificate pin")
	}
}

func TestPinnedCertVerifierRejectsMissingCertificates(t *testing.T) {
	verify := newPinnedCertVerifier("deadbeef")
	if err := verify(nil, nil); err == nil {
		t.Fatal("expected verifier to reject empty certificate list")
	}
}

func TestParseHysteria2URLIncludesCA(t *testing.T) {
	link := "hy2://user:pass@example.com:443?insecure=0&sni=edge.example.com&pinSHA256=deadbeef&ca=%2Fetc%2Fssl%2Fcustom-ca.pem#demo"

	conf, err := ParseHysteria2URL(link)
	if err != nil {
		t.Fatalf("ParseHysteria2URL() error = %v", err)
	}
	if conf.CA != "/etc/ssl/custom-ca.pem" {
		t.Fatalf("ParseHysteria2URL() CA = %q, want %q", conf.CA, "/etc/ssl/custom-ca.pem")
	}

	roundTrip, err := ParseHysteria2URL(conf.ExportToURL())
	if err != nil {
		t.Fatalf("ParseHysteria2URL() on exported URL error = %v", err)
	}
	if roundTrip.CA != conf.CA {
		t.Fatalf("round-trip CA = %q, want %q", roundTrip.CA, conf.CA)
	}
}

func TestLoadCustomRootCAs(t *testing.T) {
	caPath := writeTestCAPEM(t)

	pool, err := loadCustomRootCAs(caPath)
	if err != nil {
		t.Fatalf("loadCustomRootCAs() error = %v", err)
	}
	if pool == nil {
		t.Fatal("loadCustomRootCAs() returned nil pool")
	}
	if len(pool.Subjects()) != 1 {
		t.Fatalf("loadCustomRootCAs() subjects = %d, want 1", len(pool.Subjects()))
	}
}

func TestLoadCustomRootCAsRejectsInvalidPEM(t *testing.T) {
	caPath := filepath.Join(t.TempDir(), "invalid-ca.pem")
	if err := os.WriteFile(caPath, []byte("not a pem"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	if _, err := loadCustomRootCAs(caPath); err == nil {
		t.Fatal("expected loadCustomRootCAs() to reject invalid PEM data")
	}
}

func writeTestCAPEM(t *testing.T) string {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}

	caPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	})
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return caPath
}
