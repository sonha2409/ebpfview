package loader

import (
	"fmt"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/sonhathai/ebpfview/internal/feature"
)

// RawEvent is a single event read from a BPF ring/perf buffer.
type RawEvent struct {
	Data []byte
	CPU  int // only meaningful for perf buffer events
}

// ReaderStats tracks cumulative event reader statistics.
type ReaderStats struct {
	EventsRead atomic.Uint64
	EventsLost atomic.Uint64
	BytesRead  atomic.Uint64
}

// Snapshot returns a point-in-time copy of the stats.
func (s *ReaderStats) Snapshot() ReaderStatsSnapshot {
	return ReaderStatsSnapshot{
		EventsRead: s.EventsRead.Load(),
		EventsLost: s.EventsLost.Load(),
		BytesRead:  s.BytesRead.Load(),
	}
}

// ReaderStatsSnapshot is an immutable copy of ReaderStats.
type ReaderStatsSnapshot struct {
	EventsRead uint64
	EventsLost uint64
	BytesRead  uint64
}

// EventReader reads raw events from a BPF map (ring buffer or perf buffer).
// Implementations are safe for use from a single goroutine.
type EventReader interface {
	// Read blocks until at least one event is available or ctx is done.
	// Returns a batch of events. The caller must not retain the Data slices
	// beyond the next call to Read.
	Read() ([]RawEvent, error)

	// Stats returns cumulative reader statistics.
	Stats() ReaderStatsSnapshot

	// Close releases the reader resources. After Close, Read returns an error.
	Close() error
}

// ReaderOpts configures event reader behavior.
type ReaderOpts struct {
	// PerCPUBuffer is the per-CPU ring size for perf buffers (default 8 pages = 32KB).
	// Ignored for ring buffers.
	PerCPUBuffer int

	// Watermark is the wakeup watermark for perf buffers (default 1 byte).
	// Ignored for ring buffers.
	Watermark int
}

func (o *ReaderOpts) perCPUBufferOrDefault() int {
	if o != nil && o.PerCPUBuffer > 0 {
		return o.PerCPUBuffer
	}
	return 32 * 1024 // 32KB = 8 pages
}

// NewEventReader creates an EventReader for the named map in the handle.
// It automatically selects ring buffer or perf buffer based on the map type
// and kernel feature support.
func NewEventReader(h *Handle, mapName string, features *feature.Features, opts *ReaderOpts) (EventReader, error) {
	m, ok := h.Maps[mapName]
	if !ok {
		return nil, fmt.Errorf("loader.NewEventReader: %w: %s", ErrMapNotFound, mapName)
	}

	mapInfo, err := m.Info()
	if err != nil {
		return nil, fmt.Errorf("loader.NewEventReader: map info: %w", err)
	}

	if mapInfo.Type == ebpf.RingBuf && features.RingBuffer == feature.Available {
		return newRingBufReader(m)
	}

	return newPerfBufReader(m, opts)
}
