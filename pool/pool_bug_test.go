package pool

import (
	"fmt"
	"testing"
)

// TestPool_Get_Bug 测试 pool.Get 对于 2 的幂次的问题
func TestPool_Get_Bug(t *testing.T) {
	fmt.Println("=== Testing pool.Get for powers of 2 ===")
	fmt.Println()

	testCases := []struct {
		size           int
		minExpectedCap int
		description    string
	}{
		{1024, 1024, "1024 bytes (power of 2)"},
		{2048, 2048, "2048 bytes (power of 2) - LIKELY BUG"},
		{4096, 4096, "4096 bytes (power of 2)"},
		{1025, 2048, "1025 bytes (not power of 2)"},
		{2049, 4096, "2049 bytes (not power of 2)"},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			buf := Get(tc.size)
			defer buf.Put()

			actualCap := cap(buf)
			actualLen := len(buf)

			fmt.Printf("Test: %s\n", tc.description)
			fmt.Printf("  Requested: %d bytes\n", tc.size)
			fmt.Printf("  Got: len=%d, cap=%d\n", actualLen, actualCap)
			fmt.Printf("  Min expected cap: %d\n", tc.minExpectedCap)

			if actualCap < tc.size {
				t.Errorf("❌ CRITICAL: cap=%d < requested size=%d (WILL PANIC!)\n", actualCap, tc.size)
			} else if actualCap < tc.minExpectedCap {
				t.Errorf("⚠️  WARNING: cap=%d < min expected=%d\n", actualCap, tc.minExpectedCap)
			} else {
				fmt.Printf("✅ PASS\n\n")
			}
		})
	}
}

// TestPutNonPowerOf2Cap verifies that a buffer whose cap was grown by
// append (non-power-of-2) can be Put back safely: a later Get requesting
// more than its cap must fall back to a fresh allocation instead of
// panicking, and a Get that fits must not panic either.
func TestPutNonPowerOf2Cap(t *testing.T) {
	grown := Get(1000)                          // bucket cap 1024
	grown = append(grown, make([]byte, 536)...) // cap 1536, non-power-of-2
	Put(grown)

	// A Get larger than the grown cap must allocate fresh (no panic).
	big := Get(2048)
	if cap(big) < 2048 {
		t.Fatalf("Get(2048) returned cap %d, want >= 2048", cap(big))
	}
	Put(big)

	// A Get that fits the grown cap must not panic either.
	small := Get(1500)
	if len(small) != 1500 {
		t.Fatalf("Get(1500) returned len %d", len(small))
	}
	Put(small)
}

func TestGetBucketCapacityBug(t *testing.T) {
	testCases := []struct {
		size        int
		expectedCap int
		description string
	}{
		{2080, 4096, "2080 bytes - should get bucket 12 (4096)"},
		{2048, 2048, "2048 bytes - should get bucket 11 (2048)"},
		{2049, 4096, "2049 bytes - should get bucket 12 (4096)"},
		{1536, 2048, "1536 bytes - should get bucket 11 (2048)"},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			buf := Get(tc.size)
			defer buf.Put()

			actualCap := cap(buf)
			actualLen := len(buf)

			fmt.Printf("Test: %s\n", tc.description)
			fmt.Printf("  Requested: %d bytes\n", tc.size)
			fmt.Printf("  Got: len=%d, cap=%d\n", actualLen, actualCap)
			fmt.Printf("  Expected cap: %d\n", tc.expectedCap)

			if actualCap < tc.size {
				t.Errorf("❌ FAIL: cap=%d < requested size=%d (PANIC!)\n", actualCap, tc.size)
			} else if actualCap < tc.expectedCap {
				t.Errorf("⚠️  WARNING: cap=%d < expected=%d\n", actualCap, tc.expectedCap)
			} else {
				fmt.Printf("✅ PASS\n\n")
			}
		})
	}
}

// TestPoolInitialization 测试 pool 初始化是否正确
func TestPoolInitialization(t *testing.T) {
	fmt.Println("\n=== Pool Initialization Test ===")

	// 测试每个 bucket
	for i := minsizePower; i < num; i++ {
		buf := pools[i].Get().([]byte)
		actualCap := cap(buf)
		expectedCap := 1 << i

		fmt.Printf("Bucket %d: expected cap=%d, actual cap=%d", i, expectedCap, actualCap)

		if actualCap != expectedCap {
			fmt.Printf(" ❌ MISMATCH!\n")
			t.Errorf("Bucket %d: expected cap=%d, got %d", i, expectedCap, actualCap)
		} else {
			fmt.Printf(" ✅\n")
		}
	}
	fmt.Println()
}

// TestPool_PutNonPowerOfTwoCapDoesNotPolluteBucket 回归测试：非 2 幂 cap 的缓冲
// 必须被丢弃而不是存入下一档桶——否则后续 Get(2^n) 会把池中的短缓冲
// 重新切片到桶大小，导致 slice bounds panic。
func TestPool_PutNonPowerOfTwoCapDoesNotPolluteBucket(t *testing.T) {
	// 模拟 append 增长产生的非 2 幂 cap（如 socks5 认证分支撑破 512 → ~832）。
	polluter := make([]byte, 512)
	polluter = append(polluter, make([]byte, 300)...)
	if cap(polluter)&(cap(polluter)-1) == 0 {
		t.Fatalf("test setup: expected non-power-of-2 cap, got %d", cap(polluter))
	}
	Put(polluter)

	// 若污染了下一档桶，这里对 1024/2048 的 Get 会 panic 或返回容量不足的缓冲。
	for i := 0; i < 200; i++ {
		b := Get(2048)
		if cap(b) < 2048 {
			t.Fatalf("iteration %d: Get(2048) returned cap=%d (bucket polluted)", i, cap(b))
		}
		b.Put()
	}
}
