package pipeline

// Decoder turns raw BPF event bytes into typed Event structs.
// Each BPF program type provides its own Decoder implementation.
type Decoder interface {
	// Decode parses raw bytes into an Event. Returns an error if the bytes
	// are malformed or too short.
	Decode(raw []byte) (Event, error)

	// EventType returns the type string for events this decoder produces
	// (e.g., "flow", "syscall_lat").
	EventType() string
}
