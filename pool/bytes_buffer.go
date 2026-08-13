package pool

import (
	"sync"

	"github.com/daeuniverse/outbound/pool/bytes"
)

// maxBufferPoolLen bounds how many bytes.Buffer objects are retained. Buffers
// grow to the size of the packets they serialize (up to the 32KB Put cap), so
// this caps worst-case retention at roughly 256 x 32KB = 8MB.
const maxBufferPoolLen = 256

// bufferPool recycles serialization buffers for tuic/juicity per-packet
// encode/decode. It is a GC-stable LIFO pool: sync.Pool is cleared on every
// GC cycle, and under GC pressure the pool stays empty so every packet
// re-grows its backing slice, feeding the GC loop. LIFO keeps the temporal
// locality that a FIFO channel pool lacks — a buffer grown to one packet size
// is immediately reused by the next packet of the same size.
var bufferPool = newBufferPool()

type bufferPoolT struct {
	mu    sync.Mutex
	stack []*bytes.Buffer
}

func newBufferPool() *bufferPoolT {
	p := &bufferPoolT{stack: make([]*bytes.Buffer, 0, maxBufferPoolLen)}
	// warm the pool so the first bursts don't all allocate
	for i := 0; i < maxBufferPoolLen/4; i++ {
		p.stack = append(p.stack, bytes.NewBuffer(nil))
	}
	return p
}

func (p *bufferPoolT) Get() *bytes.Buffer {
	p.mu.Lock()
	defer p.mu.Unlock()
	if n := len(p.stack); n > 0 {
		b := p.stack[n-1]
		p.stack = p.stack[:n-1]
		return b
	}
	return bytes.NewBuffer(nil)
}

func (p *bufferPoolT) Put(b *bytes.Buffer) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.stack) >= maxBufferPoolLen {
		// pool full: drop the buffer, GC reclaims it
		return
	}
	p.stack = append(p.stack, b)
}

func GetBuffer() *bytes.Buffer {
	return bufferPool.Get()
}

func PutBuffer(buf *bytes.Buffer) {
	// Prevent slice drift leak for ridiculously large buffers
	if buf.Cap() > 32*1024 {
		return
	}
	buf.Reset()
	bufferPool.Put(buf)
}
