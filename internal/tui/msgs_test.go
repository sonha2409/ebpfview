package tui

import (
	"testing"

	"github.com/sonhathai/ebpfview/internal/cpu"
)

func Test_Listen_WrapsValue(t *testing.T) {
	ch := make(chan []cpu.Record, 1)
	ch <- []cpu.Record{{Pid: 42, Comm: "yes"}}

	msg := listen(ch, func(v []cpu.Record) CPUMsg { return CPUMsg(v) })()

	got, ok := msg.(CPUMsg)
	if !ok {
		t.Fatalf("msg = %T, want CPUMsg", msg)
	}
	if len(got) != 1 || got[0].Pid != 42 {
		t.Fatalf("msg = %+v, want one record with Pid 42", got)
	}
}

func Test_Listen_NoopOnClosedChannel(t *testing.T) {
	ch := make(chan []cpu.Record)
	close(ch)

	if msg := listen(ch, func(v []cpu.Record) CPUMsg { return CPUMsg(v) })(); msg != nil {
		t.Fatalf("msg = %v, want nil on closed channel", msg)
	}
}
