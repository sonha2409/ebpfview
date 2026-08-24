package tui

import (
	tea "github.com/charmbracelet/bubbletea"

	"github.com/sonhathai/ebpfview/internal/cpu"
	"github.com/sonhathai/ebpfview/internal/flows"
	"github.com/sonhathai/ebpfview/internal/syscalls"
)

// Aggregator snapshots delivered to the dashboard as bubbletea messages.
// The cmd layer bridges each aggregator's output channel with listen; tabs
// consume whichever message types they render.
type (
	// FlowsMsg is one interval of network flow records.
	FlowsMsg []flows.FlowRecord
	// SyscallsMsg is one interval of syscall latency records.
	SyscallsMsg []syscalls.Record
	// CPUMsg is one interval of per-process CPU records.
	CPUMsg []cpu.Record
)

// listen returns a Cmd that receives one value from ch and wraps it via mk.
// The caller re-arms it by returning listen again from Update after
// handling the message. A closed channel (aggregator shut down) yields a
// nil no-op message, so quit ordering cannot panic or deadlock the TUI.
func listen[T any, M tea.Msg](ch <-chan T, mk func(T) M) tea.Cmd {
	return func() tea.Msg {
		v, ok := <-ch
		if !ok {
			return nil
		}
		return mk(v)
	}
}
