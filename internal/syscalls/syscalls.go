// Package syscalls aggregates per-syscall latency histograms from the
// syscall_lat BPF map. It reads log2-bucketed counts keyed by (pid, nr),
// computes percentiles, and emits Records for display or export.
package syscalls

import (
	"fmt"
	"time"
	"unsafe"
)

// HistBuckets is the number of log2 histogram buckets per (pid, syscall)
// entry. Must match HIST_BUCKETS in bpf/c/syscall_lat.c.
const HistBuckets = 64

// Key mirrors struct syscall_key in bpf/c/syscall_lat.c. The layout
// must match exactly — the BPF map stores raw bytes of this struct.
type Key struct {
	Pid uint32
	Nr  uint32
}

// Value mirrors struct syscall_lat_val in bpf/c/syscall_lat.c. Each
// bucket i holds the count of observations where the syscall latency
// falls in [2^i, 2^(i+1)) nanoseconds.
type Value struct {
	Buckets [HistBuckets]uint64
}

// KeySize is the exact byte size of Key as seen by BPF.
const KeySize = int(unsafe.Sizeof(Key{}))

// ValueSize is the exact byte size of Value as seen by BPF.
const ValueSize = int(unsafe.Sizeof(Value{}))

// Record is the aggregated form of a single (pid, syscall_nr) entry,
// including cumulative counts, per-interval deltas, and percentiles.
type Record struct {
	Pid          uint32
	Nr           uint32
	Name         string
	Count        uint64 // cumulative samples across all buckets
	DeltaCount   uint64 // samples added since last poll
	CountPerSec  float64
	P50Ns        uint64 // 50th percentile latency, nanoseconds
	P90Ns        uint64
	P99Ns        uint64
	MinNs        uint64 // lower bound of the first non-empty bucket
	MaxNs        uint64 // upper bound of the last non-empty bucket
	LastInterval time.Duration
}

// Total returns the cumulative sample count across all buckets in v.
func (v *Value) Total() uint64 {
	var sum uint64
	for i := 0; i < HistBuckets; i++ {
		sum += v.Buckets[i]
	}
	return sum
}

// Percentile returns the lower bound (in nanoseconds) of the bucket
// containing the p-th percentile sample. p is in [0.0, 1.0].
// Returns 0 when the histogram is empty or p is out of range.
//
// Uses the BCC convention of reporting the bucket lower bound 2^j.
func Percentile(buckets [HistBuckets]uint64, p float64) uint64 {
	if p < 0 || p > 1 {
		return 0
	}
	var total uint64
	for i := 0; i < HistBuckets; i++ {
		total += buckets[i]
	}
	if total == 0 {
		return 0
	}

	// target is the 1-based rank we're looking for.
	target := uint64(float64(total) * p)
	if target == 0 {
		target = 1
	}
	if target > total {
		target = total
	}

	var cum uint64
	for i := 0; i < HistBuckets; i++ {
		cum += buckets[i]
		if cum >= target {
			return uint64(1) << uint(i)
		}
	}
	return uint64(1) << (HistBuckets - 1)
}

// SubBuckets returns a per-bucket delta: cur[i] - prev[i]. If prev is
// zero-valued (i.e. no previous snapshot), SubBuckets returns cur.
// Assumes the BPF counters are monotonic (LRU eviction is the only way
// a bucket can decrease, which we treat as a reset for that entry).
func SubBuckets(cur, prev [HistBuckets]uint64) [HistBuckets]uint64 {
	var out [HistBuckets]uint64
	for i := 0; i < HistBuckets; i++ {
		if cur[i] >= prev[i] {
			out[i] = cur[i] - prev[i]
		}
		// else: cur went backwards (LRU replaced this entry with a
		// fresh one). Treat the current count as the new delta.
		// This can't be distinguished from a true regression, but it's
		// the least-bad option since the alternative is negative deltas.
	}
	return out
}

// BucketLowerNs returns the lower bound (inclusive) in nanoseconds of
// bucket i, which is 2^i.
func BucketLowerNs(i int) uint64 {
	if i < 0 || i >= HistBuckets {
		return 0
	}
	return uint64(1) << uint(i)
}

// BucketUpperNs returns the upper bound (exclusive) in nanoseconds of
// bucket i, which is 2^(i+1).
func BucketUpperNs(i int) uint64 {
	if i < 0 || i >= HistBuckets-1 {
		return 0
	}
	return uint64(1) << uint(i+1)
}

// FormatLatency renders a nanosecond latency as a human-readable string
// with a unit-appropriate scale (ns/µs/ms/s). Returns "-" for zero.
func FormatLatency(ns uint64) string {
	if ns == 0 {
		return "-"
	}
	switch {
	case ns < 1_000:
		return fmt.Sprintf("%dns", ns)
	case ns < 1_000_000:
		return fmt.Sprintf("%.1fµs", float64(ns)/1_000)
	case ns < 1_000_000_000:
		return fmt.Sprintf("%.1fms", float64(ns)/1_000_000)
	default:
		return fmt.Sprintf("%.2fs", float64(ns)/1_000_000_000)
	}
}

// FormatCount renders a count-per-second as a compact string.
func FormatCount(rate float64) string {
	switch {
	case rate >= 1_000_000:
		return fmt.Sprintf("%.2fM", rate/1_000_000)
	case rate >= 1_000:
		return fmt.Sprintf("%.1fk", rate/1_000)
	default:
		return fmt.Sprintf("%.0f", rate)
	}
}

// SyscallName returns a short name for syscall number nr (e.g. "read"),
// or "syscall_<nr>" when the number is unknown on the current arch.
func SyscallName(nr uint32) string {
	if name, ok := syscallNames[nr]; ok {
		return name
	}
	return fmt.Sprintf("syscall_%d", nr)
}
