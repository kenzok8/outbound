// Package clientring provides the failover client ring shared by the QUIC
// based protocols (tuic, juicity): a circular list of live clients where a
// dial attempt walks to the next client on failover-class errors and spins
// up a new client when the ring is exhausted.
package clientring

import (
	"container/list"
	"errors"
	"sync"
	"sync/atomic"

	outbounderrors "github.com/daeuniverse/outbound/common/errors"
)

// IsFailoverError reports whether err is one of the conditions the ring
// treats as "try the next client": stream exhaustion, a closed client, or
// the capability hold gate. Stream exhaustion additionally matches the
// quic-go native *quic.StreamLimitReachedError via its message, so a raw
// transport error fails over instead of aborting the attempt.
func IsFailoverError(err error) bool {
	return outbounderrors.IsStreamExhausted(err) ||
		errors.Is(err, outbounderrors.ErrClientClosed) ||
		errors.Is(err, outbounderrors.ErrOperationHold)
}

// Node is one ring entry: the protocol client plus its last reported
// capability. capability is written by quic-go's stream-table goroutine and
// read from dial attempts holding the ring lock; the atomic keeps that
// cross-goroutine pair race-free without coupling the two locks.
type Node[T any] struct {
	Client     T
	capability atomic.Int64
}

// Capability returns the node's last reported capability (-1 = unknown).
func (n *Node[T]) Capability() int64 {
	if n == nil {
		return -1
	}
	return n.capability.Load()
}

// Ring is the shared failover ring. The protocol-specific dial bodies are
// supplied as attempt callbacks, so only client construction, close, and
// close-registration differ per protocol.
type Ring[T any] struct {
	mu         sync.Mutex
	ring       *list.List
	current    *list.Element
	newClient  func(capabilityCallback func(n int64)) T
	setOnClose func(T, func())
	close      func(T) error
	reserved   int64
}

// New constructs a ring. newClient builds a client and wires its capability
// feedback to the given callback; setOnClose registers a ring-removal hook
// on a client; close tears one down.
func New[T any](
	newClient func(capabilityCallback func(n int64)) T,
	setOnClose func(T, func()),
	close func(T) error,
	reserved int64,
) *Ring[T] {
	return &Ring[T]{
		ring:       list.New().Init(),
		newClient:  newClient,
		setOnClose: setOnClose,
		close:      close,
		reserved:   reserved,
	}
}

// TryNext runs one dial attempt against the current client, walking the ring
// on failover-class errors and inserting a fresh client when every existing
// one failed. The ring lock is held across attempts, matching the original
// per-protocol rings (dials on one ring serialize).
func (r *Ring[T]) TryNext(f func(node *Node[T]) error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	newCurrent := r.current
	err := r.tryNext(&newCurrent, f)
	r.current = newCurrent
	return err
}

func (r *Ring[T]) tryNext(current **list.Element, f func(*Node[T]) error) (err error) {
	var node *Node[T]
	if *current == nil {
		goto getNew
	}
	node = (*current).Value.(*Node[T])
	err = f(node)
	if err == nil {
		// OK.
		return nil
	}

	// Expected error: fail over to the next client.
	*current = (*current).Next()
	// NOTICE: Add the below code to reuse previous clients.
	{
		if *current == nil {
			*current = r.ring.Front()
		}
	}
	if *current == r.current {
		if IsFailoverError(err) {
			goto getNew
		}
		// Not the expected error.
		return err
	}

	return r.tryNext(current, f)

getNew:
	newNode := &Node[T]{
		Client: *new(T),
	}
	// -1 = unknown until the first capability report arrives.
	newNode.capability.Store(-1)
	newCli := r.newClient(func(n int64) { newNode.capability.Store(n) })
	newNode.Client = newCli
	r.current = r.insertAfterCurrent(newNode)
	*current = r.current
	return f(newNode)
}

func (r *Ring[T]) insertAfterCurrent(node *Node[T]) (elem *list.Element) {
	if r.current == nil {
		elem = r.ring.PushBack(node)
		r.current = elem
	} else {
		elem = r.ring.InsertAfter(node, r.current)
	}
	r.setOnClose(node.Client, func() {
		r.passiveRemove(elem)
	})
	return elem
}

func (r *Ring[T]) passiveRemove(elem *list.Element) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if elem.Value == nil {
		// Removed.
		return
	}
	elem.Value = nil
	if r.current == elem {
		r.current = elem.Next()
	}
	r.ring.Remove(elem)
}

// Len returns the number of clients currently held in the ring.
func (r *Ring[T]) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ring.Len()
}

// Close tears down every client in the ring.
func (r *Ring[T]) Close() error {
	r.mu.Lock()
	clients := make([]T, 0, r.ring.Len())
	for elem := r.ring.Front(); elem != nil; {
		next := elem.Next()
		if node, ok := elem.Value.(*Node[T]); ok && node != nil {
			clients = append(clients, node.Client)
		}
		elem.Value = nil
		r.ring.Remove(elem)
		elem = next
	}
	r.current = nil
	r.mu.Unlock()

	for _, cli := range clients {
		_ = r.close(cli)
	}
	return nil
}
