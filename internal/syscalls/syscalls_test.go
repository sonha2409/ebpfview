package syscalls

import (
	"strings"
	"testing"
)

func Test_Percentile_EmptyHistogramReturnsZero(t *testing.T) {
	var buckets [HistBuckets]uint64
	if got := Percentile(buckets, 0.5); got != 0 {
		t.Errorf("Percentile(empty, 0.5) = %d, want 0", got)
	}
}

func Test_Percentile_OutOfRangeReturnsZero(t *testing.T) {
	var buckets [HistBuckets]uint64
	buckets[10] = 100
	if got := Percentile(buckets, -0.1); got != 0 {
		t.Errorf("Percentile(-0.1) = %d, want 0", got)
	}
	if got := Percentile(buckets, 1.5); got != 0 {
		t.Errorf("Percentile(1.5) = %d, want 0", got)
	}
}

func Test_Percentile_SingleBucket(t *testing.T) {
	// All samples in bucket 10 → any percentile returns 2^10 = 1024.
	var buckets [HistBuckets]uint64
	buckets[10] = 1000

	tests := []struct {
		name string
		p    float64
		want uint64
	}{
		{"p50", 0.5, 1024},
		{"p90", 0.9, 1024},
		{"p99", 0.99, 1024},
		{"p100", 1.0, 1024},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Percentile(buckets, tt.p); got != tt.want {
				t.Errorf("Percentile(%.2f) = %d, want %d", tt.p, got, tt.want)
			}
		})
	}
}

func Test_Percentile_Distribution(t *testing.T) {
	// Construct a histogram with known cumulative distribution.
	//   bucket 5  (32ns):  500 samples → 50% cumulative
	//   bucket 10 (1024ns): 400 samples → 90% cumulative
	//   bucket 15 (32768ns): 90 samples → 99% cumulative
	//   bucket 20 (1048576ns): 10 samples → 100%
	var buckets [HistBuckets]uint64
	buckets[5] = 500
	buckets[10] = 400
	buckets[15] = 90
	buckets[20] = 10

	tests := []struct {
		name string
		p    float64
		want uint64
	}{
		{"p50", 0.5, 1 << 5},
		{"p90", 0.9, 1 << 10},
		{"p99", 0.99, 1 << 15},
		{"p100", 1.0, 1 << 20},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Percentile(buckets, tt.p); got != tt.want {
				t.Errorf("Percentile(%.2f) = %d, want %d", tt.p, got, tt.want)
			}
		})
	}
}

func Test_SubBuckets_Monotonic(t *testing.T) {
	var cur, prev [HistBuckets]uint64
	cur[5] = 100
	cur[10] = 50
	prev[5] = 40
	prev[10] = 50 // unchanged

	got := SubBuckets(cur, prev)
	if got[5] != 60 {
		t.Errorf("delta[5] = %d, want 60", got[5])
	}
	if got[10] != 0 {
		t.Errorf("delta[10] = %d, want 0", got[10])
	}
}

func Test_SubBuckets_RegressionTreatedAsZero(t *testing.T) {
	// LRU eviction can cause a bucket to go backwards; the delta for
	// that slot is clamped to 0 so we never emit negative rates.
	var cur, prev [HistBuckets]uint64
	cur[5] = 10
	prev[5] = 100

	got := SubBuckets(cur, prev)
	if got[5] != 0 {
		t.Errorf("delta[5] = %d, want 0 (regression clamp)", got[5])
	}
}

func Test_Value_Total(t *testing.T) {
	v := Value{}
	v.Buckets[0] = 1
	v.Buckets[5] = 10
	v.Buckets[63] = 100
	if got := v.Total(); got != 111 {
		t.Errorf("Total() = %d, want 111", got)
	}
}

func Test_BucketBounds(t *testing.T) {
	tests := []struct {
		i         int
		wantLower uint64
		wantUpper uint64
	}{
		{0, 1, 2},
		{1, 2, 4},
		{10, 1024, 2048},
		{30, 1 << 30, 1 << 31},
		// Upper for the final bucket is undefined (returns 0).
		{HistBuckets - 1, 1 << 63, 0},
	}
	for _, tt := range tests {
		if got := BucketLowerNs(tt.i); got != tt.wantLower {
			t.Errorf("BucketLowerNs(%d) = %d, want %d", tt.i, got, tt.wantLower)
		}
		if got := BucketUpperNs(tt.i); got != tt.wantUpper {
			t.Errorf("BucketUpperNs(%d) = %d, want %d", tt.i, got, tt.wantUpper)
		}
	}
}

func Test_FormatLatency(t *testing.T) {
	tests := []struct {
		in   uint64
		want string
	}{
		{0, "-"},
		{1, "1ns"},
		{500, "500ns"},
		{1_000, "1.0µs"},
		{1_500, "1.5µs"},
		{1_000_000, "1.0ms"},
		{2_500_000, "2.5ms"},
		{1_000_000_000, "1.00s"},
		{3_250_000_000, "3.25s"},
	}
	for _, tt := range tests {
		if got := FormatLatency(tt.in); got != tt.want {
			t.Errorf("FormatLatency(%d) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func Test_FormatCount(t *testing.T) {
	tests := []struct {
		in   float64
		want string
	}{
		{0, "0"},
		{42, "42"},
		{999, "999"},
		{1_500, "1.5k"},
		{999_999, "1000.0k"},
		{1_500_000, "1.50M"},
	}
	for _, tt := range tests {
		if got := FormatCount(tt.in); got != tt.want {
			t.Errorf("FormatCount(%f) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func Test_SyscallName_UnknownFallback(t *testing.T) {
	// Use a number that won't be in any arch's syscall table.
	name := SyscallName(60000)
	if !strings.HasPrefix(name, "syscall_") {
		t.Errorf("SyscallName(60000) = %q, want prefix syscall_", name)
	}
}
