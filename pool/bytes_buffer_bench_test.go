package pool

import (
	"sync"
	"testing"

	"github.com/daeuniverse/outbound/pkg/fastrand"
	poolbytes "github.com/daeuniverse/outbound/pool/bytes"
)

// Benchmarks for the shared serialization buffer pool (bytes_buffer.go).
// The pool design carries an explicit warning: do not replace the
// mutex-guarded LIFO without benchmark evidence. These benchmarks provide
// that evidence by racing Get/Write/Put cycles from every core, the shape of
// tuic/juicity per-datagram serialization under multi-connection load.
//
// Read the results as: wall time per cycle at full machine parallelism.
// sync.Pool's known GC-clear behavior is NOT modeled here; if its win is
// marginal the LIFO (or a sharded LIFO) stays preferable for GC stability.

var (
	benchFrameSmall = make([]byte, 128)  // ~TUIC fixed head + short addr
	benchFrameLarge = make([]byte, 1400) // near-MTU datagram serialize
)

func benchCycle(b *testing.B, frame []byte, get func() *poolbytes.Buffer, put func(*poolbytes.Buffer)) {
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			buf := get()
			_, _ = buf.Write(frame)
			put(buf)
		}
	})
}

func BenchmarkBytesBufferPoolCurrent(b *testing.B) {
	b.Run("small", func(b *testing.B) {
		benchCycle(b, benchFrameSmall, GetBuffer, PutBuffer)
	})
	b.Run("large", func(b *testing.B) {
		benchCycle(b, benchFrameLarge, GetBuffer, PutBuffer)
	})
}

// benchShardCount matches a plausible production sharding factor.
const benchShardCount = 16

type shardedBufferPool struct {
	shards [benchShardCount]bufferPoolT
}

func newShardedBufferPool() *shardedBufferPool {
	p := &shardedBufferPool{}
	for i := range p.shards {
		p.shards[i] = *newBufferPool()
	}
	return p
}

func (p *shardedBufferPool) get() *poolbytes.Buffer {
	// fastrand is per-P seeded, so the shard index costs ~nothing after
	// warmup and distributes without introducing a shared contended word.
	return p.shards[fastrand.Uint32()%benchShardCount].Get()
}

func (p *shardedBufferPool) put(buf *poolbytes.Buffer) {
	if buf.Cap() > 32*1024 {
		return
	}
	buf.Reset()
	p.shards[fastrand.Uint32()%benchShardCount].Put(buf)
}

func BenchmarkBytesBufferPoolSharded(b *testing.B) {
	p := newShardedBufferPool()
	b.Run("small", func(b *testing.B) {
		benchCycle(b, benchFrameSmall, p.get, p.put)
	})
	b.Run("large", func(b *testing.B) {
		benchCycle(b, benchFrameLarge, p.get, p.put)
	})
}

func BenchmarkBytesBufferPoolSyncPool(b *testing.B) {
	var sp sync.Pool
	sp.New = func() any { return poolbytes.NewBuffer(nil) }
	get := func() *poolbytes.Buffer { return sp.Get().(*poolbytes.Buffer) }
	put := func(buf *poolbytes.Buffer) {
		if buf.Cap() > 32*1024 {
			return
		}
		buf.Reset()
		sp.Put(buf)
	}
	b.Run("small", func(b *testing.B) {
		benchCycle(b, benchFrameSmall, get, put)
	})
	b.Run("large", func(b *testing.B) {
		benchCycle(b, benchFrameLarge, get, put)
	})
}
