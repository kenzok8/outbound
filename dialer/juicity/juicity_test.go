package juicity

import "testing"

func TestJuicityURLRoundTripWithCwnd(t *testing.T) {
	cases := []struct {
		name     string
		link     string
		wantCwnd int
	}{
		{
			name:     "brutal with cwnd",
			link:     "juicity://uuid:pass@example.com:443?congestion_control=brutal&cwnd=80000000",
			wantCwnd: 80000000,
		},
		{
			name:     "no cwnd defaults to zero",
			link:     "juicity://uuid:pass@example.com:443?congestion_control=bbr",
			wantCwnd: 0,
		},
		{
			name:     "malformed cwnd degrades to zero",
			link:     "juicity://uuid:pass@example.com:443?congestion_control=brutal&cwnd=abc",
			wantCwnd: 0,
		},
		{
			name:     "negative cwnd degrades to zero",
			link:     "juicity://uuid:pass@example.com:443?congestion_control=brutal&cwnd=-5",
			wantCwnd: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := ParseJuicityURL(tc.link)
			if err != nil {
				t.Fatalf("ParseJuicityURL: %v", err)
			}
			if parsed.Cwnd != tc.wantCwnd {
				t.Fatalf("Cwnd = %d, want %d", parsed.Cwnd, tc.wantCwnd)
			}

			reparsed, err := ParseJuicityURL(parsed.ExportToURL())
			if err != nil {
				t.Fatalf("re-ParseJuicityURL: %v", err)
			}
			if reparsed.Cwnd != tc.wantCwnd {
				t.Fatalf("round-trip Cwnd = %d, want %d", reparsed.Cwnd, tc.wantCwnd)
			}
			if reparsed.CongestionControl != parsed.CongestionControl {
				t.Fatalf("round-trip CongestionControl = %q, want %q",
					reparsed.CongestionControl, parsed.CongestionControl)
			}
		})
	}
}
