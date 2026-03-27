package stickyip

import "testing"

func TestSplitHostPortSupportsPortUnion(t *testing.T) {
	host, port, err := splitHostPort("example.com:443,8443-8450")
	if err != nil {
		t.Fatalf("SplitHostPort() error = %v", err)
	}
	if got, want := host, "example.com"; got != want {
		t.Fatalf("host = %q, want %q", got, want)
	}
	if got, want := port, "443,8443-8450"; got != want {
		t.Fatalf("port = %q, want %q", got, want)
	}
}

func TestSplitHostPortSupportsBracketedIPv6(t *testing.T) {
	host, port, err := splitHostPort("[2001:db8::1]:443,8443")
	if err != nil {
		t.Fatalf("SplitHostPort() error = %v", err)
	}
	if got, want := host, "2001:db8::1"; got != want {
		t.Fatalf("host = %q, want %q", got, want)
	}
	if got, want := port, "443,8443"; got != want {
		t.Fatalf("port = %q, want %q", got, want)
	}
}

func TestRewriteAddrPortKeepsResolvedHostAndCurrentPort(t *testing.T) {
	if got, want := rewriteAddrPort("203.0.113.10:443", "example.com:8443"), "203.0.113.10:8443"; got != want {
		t.Fatalf("rewriteAddrPort() = %q, want %q", got, want)
	}
}

func TestRewriteAddrPortKeepsIPv6Formatting(t *testing.T) {
	if got, want := rewriteAddrPort("[2001:db8::10]:443", "example.com:8443"), "[2001:db8::10]:8443"; got != want {
		t.Fatalf("rewriteAddrPort() = %q, want %q", got, want)
	}
}
