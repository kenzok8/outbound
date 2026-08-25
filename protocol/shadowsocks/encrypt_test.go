package shadowsocks

import (
	"bytes"
	"testing"

	"github.com/daeuniverse/outbound/ciphers"
)

func TestEncryptDecrypt(t *testing.T) {
	conf := ciphers.AeadCiphersConf["aes-256-gcm"]
	masterKey := make([]byte, conf.KeyLen)
	fillRandom(t, masterKey)

	salt := make([]byte, conf.SaltLen)
	fillRandom(t, salt)

	plaintext := []byte("Hello, World! This is a test message for Shadowsocks encryption.")
	reusedInfo := []byte("ss-subkey")

	key := &Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	encrypted, err := EncryptUDPFromPool(key, plaintext, salt, reusedInfo)
	if err != nil {
		t.Fatalf("EncryptUDPFromPool failed: %v", err)
	}
	defer encrypted.Put()

	decrypted, err := DecryptUDPFromPool(key, encrypted, reusedInfo)
	if err != nil {
		t.Fatalf("DecryptUDPFromPool failed: %v", err)
	}
	defer decrypted.Put()

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted text doesn't match plaintext:\n  decrypted: %x\n  plaintext: %x", decrypted, plaintext)
	}
}

func TestEncryptUDPToMatchesPooledWire(t *testing.T) {
	conf := ciphers.AeadCiphersConf["aes-256-gcm"]
	key := &Key{CipherConf: conf, MasterKey: make([]byte, conf.KeyLen)}
	salt := make([]byte, conf.SaltLen)
	plaintext := []byte("destination-buffer")
	reusedInfo := []byte("ss-subkey")

	pooled, err := EncryptUDPFromPool(key, plaintext, salt, reusedInfo)
	if err != nil {
		t.Fatal(err)
	}
	defer pooled.Put()

	dst := make([]byte, len(pooled))
	n, err := EncryptUDPTo(dst, key, plaintext, salt, reusedInfo)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(pooled) || !bytes.Equal(dst[:n], pooled) {
		t.Fatal("destination encryption changed wire bytes")
	}
	if _, err := EncryptUDPTo(dst[:len(dst)-1], key, plaintext, salt, reusedInfo); err == nil {
		t.Fatal("short destination buffer was accepted")
	}

	scratchDst := make([]byte, len(pooled))
	subKeyScratch := make([]byte, conf.KeyLen)
	n, err = EncryptUDPToWithScratch(scratchDst, key, plaintext, salt, reusedInfo, subKeyScratch)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(pooled) || !bytes.Equal(scratchDst[:n], pooled) {
		t.Fatal("scratch encryption changed wire bytes")
	}
}

func TestMultipleSalts(t *testing.T) {
	conf := ciphers.AeadCiphersConf["aes-256-gcm"]
	masterKey := make([]byte, conf.KeyLen)
	fillRandom(t, masterKey)

	plaintext := []byte("Multi-salt test")
	reusedInfo := []byte("ss-subkey")

	key := &Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	for i := 0; i < 10; i++ {
		salt := make([]byte, conf.SaltLen)
		fillRandom(t, salt)

		encrypted, err := EncryptUDPFromPool(key, plaintext, salt, reusedInfo)
		if err != nil {
			t.Fatalf("Encrypt iteration %d failed: %v", i, err)
		}

		decrypted, err := DecryptUDPFromPool(key, encrypted, reusedInfo)
		if err != nil {
			encrypted.Put()
			t.Fatalf("Decrypt iteration %d failed: %v", i, err)
		}

		if !bytes.Equal(decrypted, plaintext) {
			t.Errorf("Salt %d failed", i)
		}

		encrypted.Put()
		decrypted.Put()
	}
}

func TestDecryptUDPWithScratchMatchesPlaintext(t *testing.T) {
	conf := ciphers.AeadCiphersConf["chacha20-poly1305"]
	key := &Key{CipherConf: conf, MasterKey: make([]byte, conf.KeyLen)}
	salt := make([]byte, conf.SaltLen)
	plaintext := []byte("destination-decryption")
	reusedInfo := []byte("ss-subkey")
	encrypted, err := EncryptUDPFromPool(key, plaintext, salt, reusedInfo)
	if err != nil {
		t.Fatal(err)
	}
	defer encrypted.Put()

	dst := make([]byte, len(plaintext))
	subKeyScratch := make([]byte, conf.KeyLen)
	n, err := DecryptUDPWithScratch(dst, key, encrypted, reusedInfo, subKeyScratch)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dst[:n], plaintext) {
		t.Fatal("scratch decryption changed plaintext")
	}
}

func TestEncryptUDPToAllocationCeiling(t *testing.T) {
	conf := ciphers.AeadCiphersConf["chacha20-poly1305"]
	key := &Key{CipherConf: conf, MasterKey: make([]byte, conf.KeyLen)}
	salt := make([]byte, conf.SaltLen)
	plaintext := make([]byte, 1400)
	dst := make([]byte, conf.SaltLen+len(plaintext)+conf.TagLen)
	reusedInfo := []byte("ss-subkey")

	var encryptErr error
	allocs := testing.AllocsPerRun(1000, func() {
		_, encryptErr = EncryptUDPTo(dst, key, plaintext, salt, reusedInfo)
	})
	if encryptErr != nil {
		t.Fatal(encryptErr)
	}
	if allocs > 3 {
		t.Fatalf("EncryptUDPTo allocations = %v, want at most 3", allocs)
	}
}

func TestEncryptUDPToWithScratchAllocationCeiling(t *testing.T) {
	conf := ciphers.AeadCiphersConf["chacha20-poly1305"]
	key := &Key{CipherConf: conf, MasterKey: make([]byte, conf.KeyLen)}
	salt := make([]byte, conf.SaltLen)
	plaintext := make([]byte, 1400)
	dst := make([]byte, conf.SaltLen+len(plaintext)+conf.TagLen)
	subKeyScratch := make([]byte, conf.KeyLen)
	reusedInfo := []byte("ss-subkey")

	var encryptErr error
	allocs := testing.AllocsPerRun(1000, func() {
		_, encryptErr = EncryptUDPToWithScratch(dst, key, plaintext, salt, reusedInfo, subKeyScratch)
	})
	if encryptErr != nil {
		t.Fatal(encryptErr)
	}
	if allocs > 1 {
		t.Fatalf("EncryptUDPToWithScratch allocations = %v, want at most 1", allocs)
	}
}

func TestDecryptUDPWithScratchAllocationCeiling(t *testing.T) {
	conf := ciphers.AeadCiphersConf["chacha20-poly1305"]
	key := &Key{CipherConf: conf, MasterKey: make([]byte, conf.KeyLen)}
	salt := make([]byte, conf.SaltLen)
	plaintext := make([]byte, 1400)
	reusedInfo := []byte("ss-subkey")
	encrypted, err := EncryptUDPFromPool(key, plaintext, salt, reusedInfo)
	if err != nil {
		t.Fatal(err)
	}
	defer encrypted.Put()
	dst := make([]byte, len(plaintext))
	subKeyScratch := make([]byte, conf.KeyLen)

	var decryptErr error
	allocs := testing.AllocsPerRun(1000, func() {
		_, decryptErr = DecryptUDPWithScratch(dst, key, encrypted, reusedInfo, subKeyScratch)
	})
	if decryptErr != nil {
		t.Fatal(decryptErr)
	}
	if allocs > 1 {
		t.Fatalf("DecryptUDPWithScratch allocations = %v, want at most 1", allocs)
	}
}

func BenchmarkEncrypt(b *testing.B) {
	conf := ciphers.AeadCiphersConf["aes-256-gcm"]
	masterKey := make([]byte, conf.KeyLen)
	salt := make([]byte, conf.SaltLen)
	plaintext := make([]byte, 1024)
	reusedInfo := []byte("ss-subkey")

	key := &Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		shadowBytes, _ := EncryptUDPFromPool(key, plaintext, salt, reusedInfo)
		shadowBytes.Put()
	}
}

func BenchmarkDecrypt(b *testing.B) {
	conf := ciphers.AeadCiphersConf["aes-256-gcm"]
	masterKey := make([]byte, conf.KeyLen)
	salt := make([]byte, conf.SaltLen)
	plaintext := make([]byte, 1024)
	reusedInfo := []byte("ss-subkey")

	key := &Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	shadowBytes, _ := EncryptUDPFromPool(key, plaintext, salt, reusedInfo)
	defer shadowBytes.Put()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf, _ := DecryptUDPFromPool(key, shadowBytes, reusedInfo)
		buf.Put()
	}
}
