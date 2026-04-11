package loader

import (
	"testing"
)

func Test_HelloProbe_Close_nil(t *testing.T) {
	// Closing a HelloProbe with nil fields should not panic.
	h := &HelloProbe{}
	if err := h.Close(); err != nil {
		t.Fatalf("Close on empty HelloProbe: %v", err)
	}
}

func Test_Handle_Close_nil(t *testing.T) {
	// Closing a Handle with nil fields should not panic.
	h := &Handle{}
	if err := h.Close(); err != nil {
		t.Fatalf("Close on empty Handle: %v", err)
	}
}

func Test_Handle_Status_String(t *testing.T) {
	tests := []struct {
		status Status
		want   string
	}{
		{StatusLoaded, "loaded"},
		{StatusAttached, "attached"},
		{StatusDetached, "detached"},
		{StatusError, "error"},
		{Status(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.status.String(); got != tt.want {
			t.Errorf("Status(%d).String() = %q, want %q", tt.status, got, tt.want)
		}
	}
}

func Test_ReaderStats_Snapshot(t *testing.T) {
	var s ReaderStats
	s.EventsRead.Add(10)
	s.EventsLost.Add(2)
	s.BytesRead.Add(1024)

	snap := s.Snapshot()
	if snap.EventsRead != 10 {
		t.Errorf("EventsRead = %d, want 10", snap.EventsRead)
	}
	if snap.EventsLost != 2 {
		t.Errorf("EventsLost = %d, want 2", snap.EventsLost)
	}
	if snap.BytesRead != 1024 {
		t.Errorf("BytesRead = %d, want 1024", snap.BytesRead)
	}
}

func Test_ReaderOpts_defaults(t *testing.T) {
	var opts *ReaderOpts
	if got := opts.perCPUBufferOrDefault(); got != 32*1024 {
		t.Errorf("perCPUBufferOrDefault() = %d, want %d", got, 32*1024)
	}

	opts = &ReaderOpts{PerCPUBuffer: 16384}
	if got := opts.perCPUBufferOrDefault(); got != 16384 {
		t.Errorf("perCPUBufferOrDefault() = %d, want 16384", got)
	}
}
