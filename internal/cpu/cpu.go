// Package cpu aggregates per-process CPU time from the cpu_time BPF map
// populated by bpf/c/cpu_sample.c. It sums the PERCPU_HASH values across
// CPUs, computes per-interval deltas, and emits Records with user/kernel
// CPU percentages for display or export.
package cpu

import (
	"time"
	"unsafe"
)

// Key mirrors struct cpu_key in bpf/c/cpu_sample.c. The layout must
// match exactly — the BPF map stores raw bytes of this struct.
type Key struct {
	Pid uint32 // tgid (thread group id)
}

// Value mirrors struct cpu_val in bpf/c/cpu_sample.c. The map is a
// PERCPU_HASH, so each key maps to one Value per possible CPU; use
// SumCPUs to collapse them.
type Value struct {
	UserNs      uint64
	KernNs      uint64
	CtxSwitches uint64
}

// KeySize is the exact byte size of Key as seen by BPF.
const KeySize = int(unsafe.Sizeof(Key{}))

// ValueSize is the exact byte size of Value as seen by BPF.
const ValueSize = int(unsafe.Sizeof(Value{}))

// Record is the aggregated, per-interval view of one process. CPU
// percentages follow the htop convention: 100 means one full core, so
// values above 100 are possible on multi-threaded processes.
type Record struct {
	Pid          uint32
	Comm         string
	UserPct      float64
	KernPct      float64
	OnCPUPct     float64 // UserPct + KernPct
	CtxSwPerSec  float64
	UserNs       uint64 // cumulative sampled user time
	KernNs       uint64 // cumulative sampled kernel time
	CtxSwitches  uint64 // cumulative context switches
	LastInterval time.Duration
}

// SumCPUs collapses the per-CPU values returned by a PERCPU_HASH lookup
// into a single Value.
func SumCPUs(vals []Value) Value {
	var out Value
	for _, v := range vals {
		out.UserNs += v.UserNs
		out.KernNs += v.KernNs
		out.CtxSwitches += v.CtxSwitches
	}
	return out
}

// buildRecord is the pure per-key aggregation step, extracted so tests
// can exercise it without a BPF map.
//
// Deltas are clamped to 0 when a counter goes backwards: the only way
// that happens is a PID being recycled between polls, in which case the
// current cumulative counts belong to the new process and the next poll
// will produce correct deltas. On the first poll elapsed is 0 and all
// rates are reported as 0.
func buildRecord(key Key, cur, prev Value, elapsed time.Duration, comm string) Record {
	rec := Record{
		Pid:          key.Pid,
		Comm:         comm,
		UserNs:       cur.UserNs,
		KernNs:       cur.KernNs,
		CtxSwitches:  cur.CtxSwitches,
		LastInterval: elapsed,
	}

	if elapsed <= 0 {
		return rec
	}

	elapsedNs := float64(elapsed.Nanoseconds())
	rec.UserPct = float64(subClamp(cur.UserNs, prev.UserNs)) / elapsedNs * 100
	rec.KernPct = float64(subClamp(cur.KernNs, prev.KernNs)) / elapsedNs * 100
	rec.OnCPUPct = rec.UserPct + rec.KernPct
	rec.CtxSwPerSec = float64(subClamp(cur.CtxSwitches, prev.CtxSwitches)) / elapsed.Seconds()
	return rec
}

// subClamp returns cur - prev, clamped to 0 when cur went backwards.
func subClamp(cur, prev uint64) uint64 {
	if cur < prev {
		return 0
	}
	return cur - prev
}
