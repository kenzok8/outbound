/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

// Package errors provides error handling utilities for the outbound module.
// This package maintains interface consistency with dae/common/errors while
// allowing independent evolution of the outbound module.
package errors

import (
	"context"
	"errors"
	"net"

	"github.com/olicesx/quic-go"
)

// ============================================================================
// Standard Error Definitions (Sentinel Errors)
//
// These are exported for direct comparison in hot paths (1.19 ns/op).
// Usage: if err == ErrDNSTimeout { ... }
// ============================================================================

var (
	// DNS Errors
	ErrDNSTimeout          = errors.New("i/o timeout on DNS lookup")
	ErrDNSTemporaryFailure = errors.New("temporary DNS failure")

	// Stream Errors
	ErrStreamExhausted = errors.New("too many open streams")
	ErrClientClosed    = errors.New("client closed")
	ErrClientClosing   = errors.New("client closing")
	ErrOperationHold   = errors.New("hold on")
)

// ============================================================================
// DNS and Timeout Error Detection
// ============================================================================

// IsDNSTimeout checks if the error is a DNS timeout.
//
// Best Practice: Use direct comparison for best performance (1.19 ns/op):
//
//	if err == ErrDNSTimeout { ... }
//
// This function provides compatibility with wrapped errors.
// Performance: Direct comparison path (1.19 ns), wrapped error path (~47 ns)
func IsDNSTimeout(err error) bool {
	if err == nil {
		return false
	}

	// 🚀 Fast path: direct comparison (1.19 ns)
	if err == ErrDNSTimeout {
		return true
	}

	// 🚀 Fast path: interface check (11.6 ns)
	if timeoutErr, ok := err.(interface{ IsTimeout() bool }); ok {
		return timeoutErr.IsTimeout() && contains(err.Error(), "lookup")
	}

	// ⚡ Medium path: net.Error interface check
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return contains(err.Error(), "lookup")
	}

	// 🐌 Slow path: string matching for backward compatibility
	errStr := err.Error()
	return contains(errStr, "i/o timeout") && contains(errStr, "lookup")
}

// IsStreamExhausted checks if the error indicates no more streams available.
//
// Best Practice: Use direct comparison for best performance (1.19 ns/op):
//
//	if err == ErrStreamExhausted { ... }
func IsStreamExhausted(err error) bool {
	if err == nil {
		return false
	}
	if err == ErrStreamExhausted {
		return true
	}
	return contains(err.Error(), "too many open streams")
}

// IsTemporaryError checks if an error is temporary and should not close the connection.
// This is used to distinguish between fatal and non-fatal network/context errors.
func IsTemporaryError(err error) bool {
	if err == nil {
		return false
	}

	// Context timeout/cancelled are temporary
	if errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, context.Canceled) {
		return true
	}

	// A full DATAGRAM send queue drops the current datagram and keeps the
	// QUIC connection alive. Closing the shared tunnel here would replay the
	// HY2 game-disconnect failure on TUIC.
	if errors.Is(err, quic.ErrDatagramQueueFullTimeout) {
		return true
	}

	// Net temporary errors
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Temporary() { // nolint:staticcheck
		return true
	}

	return false
}

// ============================================================================
// Helper Functions
// ============================================================================

// contains checks if substr is within s without importing strings package.
// This is a lightweight implementation for error message checking.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && indexOf(s, substr) >= 0
}

// indexOf returns the index of the first occurrence of substr in s,
// or -1 if substr is not found.
func indexOf(s, substr string) int {
	n := len(substr)
	if n == 0 {
		return 0
	}
	if n > len(s) {
		return -1
	}
	for i := 0; i <= len(s)-n; i++ {
		if s[i:i+n] == substr {
			return i
		}
	}
	return -1
}
