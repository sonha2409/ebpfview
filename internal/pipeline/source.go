package pipeline

import (
	"fmt"
	"log/slog"

	"github.com/sonhathai/ebpfview/internal/loader"
)

// Source produces decoded events from a BPF event reader.
type Source interface {
	// Read blocks until events are available, decodes them, and returns
	// a batch. Returns error on reader failure or context cancellation.
	Read() ([]Event, error)

	// Close releases the underlying reader.
	Close() error
}

// SourceStats tracks cumulative source statistics.
type SourceStats struct {
	EventsRead   uint64
	EventsLost   uint64
	DecodeErrors uint64
}

// ReaderSource wraps a loader.EventReader and Decoder into a Source.
type ReaderSource struct {
	reader  loader.EventReader
	decoder Decoder
	logger  *slog.Logger
	stats   SourceStats
}

// NewReaderSource creates a Source that reads from the given EventReader
// and decodes events using the given Decoder.
func NewReaderSource(reader loader.EventReader, decoder Decoder, logger *slog.Logger) *ReaderSource {
	return &ReaderSource{
		reader:  reader,
		decoder: decoder,
		logger:  logger,
	}
}

// Read blocks until raw events are available, decodes them, and returns
// the successfully decoded events. Decode errors are logged and counted
// but do not stop the pipeline.
func (s *ReaderSource) Read() ([]Event, error) {
	rawEvents, err := s.reader.Read()
	if err != nil {
		return nil, fmt.Errorf("pipeline.ReaderSource.Read: %w", err)
	}

	events := make([]Event, 0, len(rawEvents))
	for _, raw := range rawEvents {
		evt, err := s.decoder.Decode(raw.Data)
		if err != nil {
			s.stats.DecodeErrors++
			s.logger.Debug("decode error",
				"type", s.decoder.EventType(),
				"error", err,
				"data_len", len(raw.Data),
			)
			continue
		}
		events = append(events, evt)
	}

	s.stats.EventsRead += uint64(len(events))

	// Update lost count from reader stats.
	rStats := s.reader.Stats()
	s.stats.EventsLost = rStats.EventsLost

	return events, nil
}

// Stats returns a snapshot of source statistics.
func (s *ReaderSource) Stats() SourceStats {
	return s.stats
}

// Close releases the underlying reader.
func (s *ReaderSource) Close() error {
	return s.reader.Close()
}
