package syscalls

import (
	"testing"
	"time"
)

func Test_buildRecord_FirstTickUsesCumulative(t *testing.T) {
	var cur Value
	cur.Buckets[5] = 100
	cur.Buckets[10] = 50
	var prev Value

	rec := buildRecord(Key{Pid: 1, Nr: 0}, cur, prev, 0)
	if rec.Count != 150 {
		t.Errorf("Count = %d, want 150", rec.Count)
	}
	if rec.DeltaCount != 0 {
		t.Errorf("DeltaCount = %d, want 0 (first tick)", rec.DeltaCount)
	}
	if rec.CountPerSec != 0 {
		t.Errorf("CountPerSec = %f, want 0", rec.CountPerSec)
	}
	// Percentiles are computed on cumulative when there's no delta.
	if rec.P50Ns == 0 {
		t.Error("P50Ns should be non-zero from cumulative histogram")
	}
}

func Test_buildRecord_DeltaDrivesRateAndPercentiles(t *testing.T) {
	var cur Value
	cur.Buckets[5] = 100 // 32ns bucket
	cur.Buckets[10] = 50 // 1024ns bucket

	var prev Value
	prev.Buckets[5] = 10
	prev.Buckets[10] = 40

	elapsed := 2 * time.Second
	rec := buildRecord(Key{Pid: 1, Nr: 1}, cur, prev, elapsed)

	// Delta: 90 in bucket 5, 10 in bucket 10 → total 100 over 2s = 50/s.
	if rec.DeltaCount != 100 {
		t.Errorf("DeltaCount = %d, want 100", rec.DeltaCount)
	}
	if rec.CountPerSec != 50.0 {
		t.Errorf("CountPerSec = %f, want 50.0", rec.CountPerSec)
	}
	// p50 falls in bucket 5 (first 90 of 100 samples) → 2^5 = 32.
	if rec.P50Ns != 32 {
		t.Errorf("P50Ns = %d, want 32", rec.P50Ns)
	}
	// p99 falls in bucket 10 (last 10 samples) → 2^10 = 1024.
	if rec.P99Ns != 1024 {
		t.Errorf("P99Ns = %d, want 1024", rec.P99Ns)
	}
}

func Test_buildRecord_NoDeltaFallsBackToCumulative(t *testing.T) {
	// Cumulative has samples but no activity in the last interval.
	// Percentiles should still report something useful from cumulative.
	var cur, prev Value
	cur.Buckets[7] = 200
	prev.Buckets[7] = 200

	rec := buildRecord(Key{Pid: 1, Nr: 2}, cur, prev, time.Second)
	if rec.DeltaCount != 0 {
		t.Errorf("DeltaCount = %d, want 0", rec.DeltaCount)
	}
	if rec.CountPerSec != 0 {
		t.Errorf("CountPerSec = %f, want 0", rec.CountPerSec)
	}
	if rec.P50Ns != 128 {
		t.Errorf("P50Ns = %d, want 128 (cumulative fallback)", rec.P50Ns)
	}
}

func Test_buildRecord_MinMaxFromBuckets(t *testing.T) {
	var cur Value
	cur.Buckets[3] = 5
	cur.Buckets[20] = 5
	var prev Value

	rec := buildRecord(Key{Pid: 1, Nr: 3}, cur, prev, 0)
	if rec.MinNs != (1 << 3) {
		t.Errorf("MinNs = %d, want %d", rec.MinNs, 1<<3)
	}
	if rec.MaxNs != (1 << 21) {
		t.Errorf("MaxNs = %d, want %d", rec.MaxNs, 1<<21)
	}
}

func Test_buildRecord_NameLookup(t *testing.T) {
	var cur, prev Value
	cur.Buckets[5] = 1
	// nr=60000 is guaranteed not to be in any arch syscall table.
	rec := buildRecord(Key{Pid: 1, Nr: 60000}, cur, prev, 0)
	if rec.Name == "" {
		t.Error("Name should never be empty")
	}
}
