package pipeline

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/sonhathai/ebpfview/internal/loader"
)

// --- mock reader ---

type mockReader struct {
	events [][]loader.RawEvent
	idx    int
	mu     sync.Mutex
	closed bool
}

func (m *mockReader) Read() ([]loader.RawEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil, errors.New("reader closed")
	}
	if m.idx >= len(m.events) {
		return nil, errors.New("reader closed")
	}
	batch := m.events[m.idx]
	m.idx++
	return batch, nil
}

func (m *mockReader) Stats() loader.ReaderStatsSnapshot {
	return loader.ReaderStatsSnapshot{}
}

func (m *mockReader) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

// --- mock decoder ---

type mockDecoder struct {
	eventType string
}

func (d *mockDecoder) Decode(raw []byte) (Event, error) {
	if len(raw) == 0 {
		return Event{}, errors.New("empty data")
	}
	return Event{
		Type: d.eventType,
		PID:  uint32(raw[0]),
		Data: raw,
	}, nil
}

func (d *mockDecoder) EventType() string {
	return d.eventType
}

// --- mock sink ---

type mockSink struct {
	mu     sync.Mutex
	events []Event
}

func (s *mockSink) Send(_ context.Context, events []Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, events...)
	return nil
}

func (s *mockSink) Close() error { return nil }

func (s *mockSink) received() []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]Event, len(s.events))
	copy(cp, s.events)
	return cp
}

// --- tests ---

func Test_NoopEnricher(t *testing.T) {
	e := NoopEnricher{}
	evt := &Event{Type: "test"}
	if err := e.Enrich(context.Background(), evt); err != nil {
		t.Errorf("NoopEnricher.Enrich() = %v, want nil", err)
	}
}

func Test_ReaderSource_decodes_events(t *testing.T) {
	reader := &mockReader{
		events: [][]loader.RawEvent{
			{{Data: []byte{1, 2, 3}}, {Data: []byte{4, 5, 6}}},
		},
	}
	dec := &mockDecoder{eventType: "test"}
	src := NewReaderSource(reader, dec, slog.Default())

	events, err := src.Read()
	if err != nil {
		t.Fatalf("Read() error: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("Read() returned %d events, want 2", len(events))
	}
	if events[0].PID != 1 {
		t.Errorf("events[0].PID = %d, want 1", events[0].PID)
	}
	if events[1].PID != 4 {
		t.Errorf("events[1].PID = %d, want 4", events[1].PID)
	}
}

func Test_ReaderSource_skips_decode_errors(t *testing.T) {
	reader := &mockReader{
		events: [][]loader.RawEvent{
			{{Data: []byte{}}, {Data: []byte{7}}}, // first is empty → decode error
		},
	}
	dec := &mockDecoder{eventType: "test"}
	src := NewReaderSource(reader, dec, slog.Default())

	events, err := src.Read()
	if err != nil {
		t.Fatalf("Read() error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("Read() returned %d events, want 1", len(events))
	}
	if src.Stats().DecodeErrors != 1 {
		t.Errorf("DecodeErrors = %d, want 1", src.Stats().DecodeErrors)
	}
}

func Test_Pipeline_no_sources_error(t *testing.T) {
	p := New(slog.Default())
	err := p.Run(context.Background())
	if err == nil {
		t.Fatal("Run() with no sources should return error")
	}
}

func Test_Pipeline_processes_events(t *testing.T) {
	reader := &mockReader{
		events: [][]loader.RawEvent{
			{{Data: []byte{42}}},
		},
	}
	dec := &mockDecoder{eventType: "test"}
	src := NewReaderSource(reader, dec, slog.Default())
	sink := &mockSink{}

	p := New(slog.Default(),
		WithSource(src),
		WithSink(sink),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_ = p.Run(ctx)

	received := sink.received()
	if len(received) < 1 {
		t.Fatal("sink received no events")
	}
	if received[0].PID != 42 {
		t.Errorf("received[0].PID = %d, want 42", received[0].PID)
	}
}

func Test_Pipeline_Close(t *testing.T) {
	reader := &mockReader{}
	dec := &mockDecoder{eventType: "test"}
	src := NewReaderSource(reader, dec, slog.Default())
	sink := &mockSink{}

	p := New(slog.Default(),
		WithSource(src),
		WithSink(sink),
	)

	if err := p.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}
}
