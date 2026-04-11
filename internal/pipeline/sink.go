package pipeline

import "context"

// Sink consumes processed events. Implementations include TUI updates,
// Prometheus metric pushes, OTLP export, and JSON streaming.
type Sink interface {
	// Send delivers a batch of events to the sink. Implementations should
	// be non-blocking or have bounded latency — a slow sink must not stall
	// the pipeline.
	Send(ctx context.Context, events []Event) error

	// Close releases any resources held by the sink.
	Close() error
}
