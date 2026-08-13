// modified from https://github.com/nadoo/glider/blob/master/pool/buffer.go

package pool

import (
	"math/bits"
)

const (
	// number of pools.
	num          = 17
	maxsize      = 1 << (num - 1)
	minsizePower = 6
	minsize      = 1 << minsizePower
	// maxPooledPerBucket bounds how many buffers each bucket retains.
	// 64 x 64KiB = 4MiB worst case for the largest bucket.
	maxPooledPerBucket = 64
)

// poolBuckets is a set of bounded channel pools, one per power-of-2 size
// class. A sync.Pool is cleared on every GC cycle, so under GC pressure
// every packet/chunk re-allocates its buffer, driving the GC harder (the
// allocation spiral observed on vmess and hy2 speedtests). Channel pools
// survive GC and are capped.
var poolBuckets [num]bucketPool

type bucketPool struct {
	ch chan []byte
}

func (p *bucketPool) Get() []byte {
	select {
	case b := <-p.ch:
		return b
	default:
		return nil
	}
}

func (p *bucketPool) Put(b []byte) {
	select {
	case p.ch <- b:
	default:
		// pool full: drop the buffer, GC reclaims it
	}
}

func init() {
	for i := minsizePower; i < num; i++ {
		size := 1 << i
		ch := make(chan []byte, maxPooledPerBucket)
		// warm the pool so the first bursts don't all allocate
		for j := 0; j < maxPooledPerBucket/4; j++ {
			ch <- make([]byte, size)
		}
		poolBuckets[i].ch = ch
	}
}

func GetClosestN(need int) (n int) {
	// if need is exactly 2^n, return n-1
	if need&(need-1) == 0 {
		return bits.Len32(uint32(need)) - 1
	}
	// or return its closest n
	return bits.Len32(uint32(need))
}

func GetBiggerClosestN(need int) (n int) {
	n = bits.Len32(uint32(need))
	// bits.Len32 returns the number of bits needed to represent the number.
	// For a power of 2, it returns exponent+1, so we subtract 1.
	// For other numbers, we need the next power of 2, which is what bits.Len32 gives.
	// Examples:
	//   need=1024 (2^10): bits.Len32=11 → return 10
	//   need=1025: bits.Len32=11 → return 11 (need 2^11=2048)
	//   need=2048 (2^11): bits.Len32=12 → return 11
	//   need=2049: bits.Len32=12 → return 12 (need 2^12=4096)
	if need == (1 << (n - 1)) {
		// need is exactly a power of 2
		return n - 1
	}
	return n
}

// Get gets a buffer from pool, size should in range: [1, 65536],
// otherwise, this function will call make([]byte, size) directly.
// IMPORTANT: Returns a buffer with capacity >= size to prevent slice bounds panic.
func Get(size int) PB {
	if size >= 1 && size <= maxsize {
		i := GetBiggerClosestN(size) // Fixed: Use GetBiggerClosestN to ensure capacity >= size
		if i < minsizePower {
			i = minsizePower
		}
		b := poolBuckets[i].Get()
		if b == nil || cap(b) < size {
			// Pooled buffer missing or smaller than the bucket capacity
			// (grown by append and stored by Put): allocate fresh.
			return make([]byte, size)
		}
		return b[:size]
	}
	return make([]byte, size)
}

func GetFullCap(size int) PB {
	a := Get(size)
	a = a[:cap(a)]
	return a
}

func GetMustBigger(size int) PB {
	if size >= 1 && size <= maxsize {
		i := GetBiggerClosestN(size)
		if i < minsizePower {
			i = minsizePower
		}
		b := poolBuckets[i].Get()
		if b == nil || cap(b) < size {
			return make([]byte, size)
		}
		return b[:size]
	}
	return make([]byte, size)
}

func GetZero(size int) []byte {
	b := Get(size)
	for i := range b {
		b[i] = 0
	}
	return b
}

func Put(buf []byte) {
	size := cap(buf)
	if size < minsize || size > maxsize {
		// Strictly avoid returning oversize huge buffers to prevent memory leak/retention.
		// Small buffers are also directly discarded.
		return
	}
	// Buffers whose cap is not a power of 2 (grown by append) go to the
	// bucket that fits them. Get guards against them with a cap check and
	// falls back to a fresh allocation, so a later Get(2^n) can never
	// re-slice past their capacity.
	i := GetBiggerClosestN(size)
	if i < minsizePower {
		i = minsizePower
	}
	if i < num {
		poolBuckets[i].Put(buf)
	}
}
