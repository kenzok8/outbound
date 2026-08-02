package shadowsocks

import (
	"crypto/sha1"
	"fmt"
	"hash"
	"sync"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/pool"
)

// subKeyPool reuses subKey buffers to reduce allocations in the hot path.
// Shadowsocks AEAD uses either 16-byte (AES-128) or 32-byte (AES-256) keys.
var subKeyPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 32) // max key size
	},
}

// getSubKey gets a subKey buffer from the pool.
func getSubKey(keyLen int) []byte {
	return subKeyPool.Get().([]byte)[:keyLen]
}

// putSubKey returns a subKey buffer to the pool.
func putSubKey(subKey []byte) {
	if subKey != nil && cap(subKey) >= 16 && cap(subKey) <= 32 {
		// nolint:staticcheck
		subKeyPool.Put(subKey[:32])
	}
}

// sha1DigestPool reuses sha1 digests across the per-packet HKDF key schedule.
// hmac.New would allocate an hmac wrapper + opad + a fresh sha1 digest for each
// of the three HMACs, which dominated the UDP hot path (17 allocs/op with
// hkdf.New). One pooled digest is reset between HMACs instead.
var sha1DigestPool = sync.Pool{
	New: func() interface{} { return sha1.New() },
}

// hmacBuf holds the scratch arrays of one HMAC-SHA1. It is pool-allocated so
// that slices handed to the hash.Hash interface alias heap memory instead of
// escaping a stack array (which previously cost ~232 B and 5 allocs per HMAC).
type hmacBuf struct {
	kbuf, ipad, opad [64]byte
	inner            [sha1.Size]byte
}

var hmacBufPool = sync.Pool{
	New: func() interface{} { return &hmacBuf{} },
}

// hmacSHA1 computes HMAC-SHA1(key, msg...) into a fixed-size result using a
// caller-provided sha1 digest and hmacBuf, avoiding per-call hmac.New
// allocations. b is reused across HMACs within one deriveSubKey call.
func hmacSHA1(h hash.Hash, b *hmacBuf, key []byte, msg ...[]byte) (out [sha1.Size]byte) {
	if len(key) > 64 {
		h.Reset()
		h.Write(key)
		h.Sum(b.kbuf[:0])
		// kbuf is pooled and may hold stale bytes past the SHA-1 digest; HMAC
		// pads the hashed key to block size with zeros, so clear the tail.
		clear(b.kbuf[sha1.Size:])
	} else {
		copy(b.kbuf[:], key)
		// kbuf is pooled and may hold stale bytes past len(key); HMAC pads the
		// key to block size with zeros, so the tail must be cleared.
		clear(b.kbuf[len(key):])
	}
	for i := 0; i < len(b.kbuf); i++ {
		b.ipad[i] = b.kbuf[i] ^ 0x36
		b.opad[i] = b.kbuf[i] ^ 0x5c
	}
	h.Reset()
	h.Write(b.ipad[:])
	for _, m := range msg {
		h.Write(m)
	}
	h.Sum(b.inner[:0])
	h.Reset()
	h.Write(b.opad[:])
	h.Write(b.inner[:])
	h.Sum(out[:0])
	return out
}

// deriveSubKey computes subKey = HKDF-SHA1(masterKey, salt, info)[:len(dst)]
// inline. The SS AEAD key schedule only ever needs 1-2 HKDF-Expand blocks
// (SHA-1 is 20 bytes; keys are 16 or 32), so the hkdf.Reader wrapper and its
// per-Read hmac allocations are pure overhead on the per-packet UDP hot path.
func deriveSubKey(dst []byte, masterKey, salt, info []byte) {
	h := sha1DigestPool.Get().(hash.Hash)
	defer sha1DigestPool.Put(h)
	b := hmacBufPool.Get().(*hmacBuf)
	defer hmacBufPool.Put(b)

	// Extract: PRK = HMAC-SHA1(key=salt, data=masterKey)
	prk := hmacSHA1(h, b, salt, masterKey)

	// Expand: T(1) = HMAC-SHA1(PRK, info || 0x01)
	t1 := hmacSHA1(h, b, prk[:], info, one)
	n := copy(dst, t1[:])
	if n == len(dst) {
		return
	}
	// T(2) = HMAC-SHA1(PRK, T(1) || info || 0x02), only needed for 32-byte keys.
	t2 := hmacSHA1(h, b, prk[:], t1[:], info, two)
	copy(dst[n:], t2[:])
}

// one and two are the HKDF-Expand block counters, kept as package-level slices
// so the hmacSHA1 variadic call does not allocate per invocation.
var (
	one = []byte{0x01}
	two = []byte{0x02}
)

func EncryptUDPFromPool(key *Key, b []byte, salt []byte, reusedInfo []byte) (shadowBytes pool.PB, err error) {
	var buf = pool.Get(key.CipherConf.SaltLen + len(b) + key.CipherConf.TagLen)
	defer func() {
		if err != nil {
			pool.Put(buf)
		}
	}()
	copy(buf, salt)
	subKey := getSubKey(key.CipherConf.KeyLen)
	defer putSubKey(subKey)
	deriveSubKey(subKey, key.MasterKey, buf[:key.CipherConf.SaltLen], reusedInfo)
	ciph, err := key.CipherConf.NewCipher(subKey)
	if err != nil {
		return nil, err
	}
	_ = ciph.Seal(buf[key.CipherConf.SaltLen:key.CipherConf.SaltLen], ciphers.ZeroNonce[:key.CipherConf.NonceLen], b, nil)
	return buf, nil
}

func DecryptUDPFromPool(key *Key, shadowBytes []byte, reusedInfo []byte) (buf pool.PB, err error) {
	buf = pool.Get(len(shadowBytes))
	if buf.HeadOverlap(shadowBytes) {
		// The caller may still own the encrypted packet. Do not let pooled
		// output alias it, or AEAD Open will reject the overlap and the input
		// packet will be corrupted on successful decrypt.
		buf = pool.PB(make([]byte, len(shadowBytes)))
	}
	n, err := DecryptUDP(buf[:0], key, shadowBytes, reusedInfo)
	if err != nil {
		buf.Put()
		return nil, err
	}
	return buf[:n], nil
}

func DecryptUDP(writeTo []byte, key *Key, shadowBytes []byte, reusedInfo []byte) (n int, err error) {
	if len(shadowBytes) < key.CipherConf.SaltLen {
		return 0, fmt.Errorf("short length to decrypt")
	}
	subKey := getSubKey(key.CipherConf.KeyLen)
	defer putSubKey(subKey)
	deriveSubKey(subKey, key.MasterKey, shadowBytes[:key.CipherConf.SaltLen], reusedInfo)
	ciph, err := key.CipherConf.NewCipher(subKey)
	if err != nil {
		return 0, err
	}
	writeTo, err = ciph.Open(writeTo[:0], ciphers.ZeroNonce[:key.CipherConf.NonceLen], shadowBytes[key.CipherConf.SaltLen:], nil)
	if err != nil {
		return 0, err
	}
	return len(writeTo), nil
}
