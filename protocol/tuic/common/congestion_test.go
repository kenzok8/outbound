package common

import "testing"

func TestCWNDFromFeature(t *testing.T) {
	cases := []struct {
		name string
		in   interface{}
		want uint64
	}{
		{name: "int", in: 80000000, want: 80000000},
		{name: "int64", in: int64(123), want: 123},
		{name: "uint64", in: uint64(9), want: 9},
		{name: "zero int", in: 0, want: 0},
		{name: "negative", in: -5, want: 0},
		{name: "nil", in: nil, want: 0},
		{name: "string", in: "brutal", want: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CWNDFromFeature(tc.in); got != tc.want {
				t.Fatalf("CWNDFromFeature(%v) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}
