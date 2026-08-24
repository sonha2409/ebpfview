package cpu

import (
	"math"
	"testing"
	"time"
)

func Test_SumCPUs_AddsAllFields(t *testing.T) {
	tests := []struct {
		name string
		vals []Value
		want Value
	}{
		{
			name: "empty slice",
			vals: nil,
			want: Value{},
		},
		{
			name: "single cpu",
			vals: []Value{{UserNs: 10, KernNs: 20, CtxSwitches: 3}},
			want: Value{UserNs: 10, KernNs: 20, CtxSwitches: 3},
		},
		{
			name: "multiple cpus",
			vals: []Value{
				{UserNs: 10, KernNs: 20, CtxSwitches: 3},
				{UserNs: 5, KernNs: 0, CtxSwitches: 1},
				{UserNs: 0, KernNs: 7, CtxSwitches: 0},
			},
			want: Value{UserNs: 15, KernNs: 27, CtxSwitches: 4},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SumCPUs(tt.vals); got != tt.want {
				t.Errorf("SumCPUs() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func Test_BuildRecord_FirstTickHasNoRates(t *testing.T) {
	cur := Value{UserNs: 500_000_000, KernNs: 250_000_000, CtxSwitches: 42}

	rec := buildRecord(Key{Pid: 100}, cur, Value{}, 0, "nginx")

	if rec.UserPct != 0 || rec.KernPct != 0 || rec.OnCPUPct != 0 || rec.CtxSwPerSec != 0 {
		t.Errorf("first tick rates must be 0, got %+v", rec)
	}
	if rec.UserNs != cur.UserNs || rec.KernNs != cur.KernNs || rec.CtxSwitches != cur.CtxSwitches {
		t.Errorf("cumulative counters not carried through: %+v", rec)
	}
	if rec.Comm != "nginx" || rec.Pid != 100 {
		t.Errorf("identity fields wrong: %+v", rec)
	}
}

func Test_BuildRecord_SteadyStatePercentages(t *testing.T) {
	prev := Value{UserNs: 1_000_000_000, KernNs: 500_000_000, CtxSwitches: 100}
	cur := Value{UserNs: 1_500_000_000, KernNs: 750_000_000, CtxSwitches: 150}

	rec := buildRecord(Key{Pid: 1}, cur, prev, time.Second, "stress")

	// 500ms of user time over a 1s interval = 50% of one core.
	if !almostEqual(rec.UserPct, 50) {
		t.Errorf("UserPct = %v, want 50", rec.UserPct)
	}
	if !almostEqual(rec.KernPct, 25) {
		t.Errorf("KernPct = %v, want 25", rec.KernPct)
	}
	if !almostEqual(rec.OnCPUPct, 75) {
		t.Errorf("OnCPUPct = %v, want 75", rec.OnCPUPct)
	}
	if !almostEqual(rec.CtxSwPerSec, 50) {
		t.Errorf("CtxSwPerSec = %v, want 50", rec.CtxSwPerSec)
	}
}

func Test_BuildRecord_MultiCoreCanExceed100Pct(t *testing.T) {
	// 4 cores fully busy in user mode for the whole interval.
	cur := Value{UserNs: 4_000_000_000}

	rec := buildRecord(Key{Pid: 1}, cur, Value{}, time.Second, "burn")

	if !almostEqual(rec.UserPct, 400) {
		t.Errorf("UserPct = %v, want 400", rec.UserPct)
	}
}

func Test_BuildRecord_CounterRegressionClampsToZero(t *testing.T) {
	// PID recycled between polls: new process has smaller counters.
	prev := Value{UserNs: 9_000_000_000, KernNs: 5_000_000_000, CtxSwitches: 900}
	cur := Value{UserNs: 100_000_000, KernNs: 50_000_000, CtxSwitches: 10}

	rec := buildRecord(Key{Pid: 7}, cur, prev, time.Second, "fresh")

	if rec.UserPct != 0 || rec.KernPct != 0 || rec.CtxSwPerSec != 0 {
		t.Errorf("regressed counters must clamp rates to 0, got %+v", rec)
	}
	if rec.UserNs != cur.UserNs {
		t.Errorf("cumulative counters must reflect current value, got %d", rec.UserNs)
	}
}

func Test_BuildRecord_HalfSecondInterval(t *testing.T) {
	prev := Value{UserNs: 0}
	cur := Value{UserNs: 250_000_000} // 250ms user time over 500ms

	rec := buildRecord(Key{Pid: 1}, cur, prev, 500*time.Millisecond, "x")

	if !almostEqual(rec.UserPct, 50) {
		t.Errorf("UserPct = %v, want 50", rec.UserPct)
	}
}

func Test_StructSizes_MatchBPF(t *testing.T) {
	// Must match struct cpu_key / struct cpu_val in bpf/c/cpu_sample.c.
	if KeySize != 4 {
		t.Errorf("KeySize = %d, want 4", KeySize)
	}
	if ValueSize != 24 {
		t.Errorf("ValueSize = %d, want 24", ValueSize)
	}
}

func almostEqual(a, b float64) bool {
	return math.Abs(a-b) < 1e-9
}
