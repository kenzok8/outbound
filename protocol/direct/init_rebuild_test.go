package direct

import (
	"testing"
)

func TestInitDirectDialersRebuildsOnLaterCalls(t *testing.T) {
	t.Cleanup(func() {
		directMu.Lock()
		directInited = false
		_symmetricDirect = nil
		_fullconeDirect = nil
		directMu.Unlock()
		directFallbackDNS.Store("")
	})

	InitDirectDialers("")
	firstSym := _symmetricDirect
	firstFull := _fullconeDirect
	if firstSym == nil || firstFull == nil {
		t.Fatal("expected dialers after first InitDirectDialers")
	}
	if firstSym.(*directDialer).Option.FallbackDNS != "" {
		t.Fatalf("first fallback = %q, want empty", firstSym.(*directDialer).Option.FallbackDNS)
	}

	InitDirectDialers("1.1.1.1:53")
	if _symmetricDirect == firstSym {
		t.Fatal("second InitDirectDialers reused the first symmetric dialer")
	}
	if _fullconeDirect == firstFull {
		t.Fatal("second InitDirectDialers reused the first fullcone dialer")
	}
	got := _symmetricDirect.(*directDialer).Option.FallbackDNS
	if got != "1.1.1.1:53" {
		t.Fatalf("rebuilt fallback = %q, want 1.1.1.1:53", got)
	}
	if _fullconeDirect.(*directDialer).Option.FallbackDNS != "1.1.1.1:53" {
		t.Fatalf("fullcone fallback = %q", _fullconeDirect.(*directDialer).Option.FallbackDNS)
	}
}
