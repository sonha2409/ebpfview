// Package pipeline decodes, enriches, and routes BPF events.
// It is BPF-unaware — it consumes raw bytes from the loader's EventReader
// and produces typed events for TUI and export sinks.
package pipeline

// Event is the common envelope for all decoded BPF events.
type Event struct {
	// Type identifies the event kind (e.g., "flow", "syscall_lat", "cpu_sample").
	Type string

	// Timestamp is the kernel timestamp in nanoseconds.
	Timestamp uint64

	// PID is the process ID that generated the event.
	PID uint32

	// Comm is the process name (populated by enrichment).
	Comm string

	// Data holds the typed payload. Sinks cast this to the expected type
	// based on Event.Type.
	Data any
}
