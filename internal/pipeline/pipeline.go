package pipeline

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
)

// Pipeline reads events from sources, enriches them, and fans out to sinks.
type Pipeline struct {
	sources  []Source
	enricher Enricher
	sinks    []Sink
	logger   *slog.Logger
}

// Option configures a Pipeline.
type Option func(*Pipeline)

// WithSource adds an event source to the pipeline.
func WithSource(s Source) Option {
	return func(p *Pipeline) {
		p.sources = append(p.sources, s)
	}
}

// WithEnricher sets the event enricher. If not set, NoopEnricher is used.
func WithEnricher(e Enricher) Option {
	return func(p *Pipeline) {
		p.enricher = e
	}
}

// WithSink adds an event sink to the pipeline.
func WithSink(s Sink) Option {
	return func(p *Pipeline) {
		p.sinks = append(p.sinks, s)
	}
}

// New creates a Pipeline with the given options.
func New(logger *slog.Logger, opts ...Option) *Pipeline {
	p := &Pipeline{
		enricher: NoopEnricher{},
		logger:   logger,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Run starts the pipeline and blocks until ctx is cancelled. Each source
// runs in its own goroutine. Events are enriched and fanned out to all sinks.
// Returns the first non-context error encountered.
func (p *Pipeline) Run(ctx context.Context) error {
	if len(p.sources) == 0 {
		return fmt.Errorf("pipeline.Run: no sources configured")
	}

	var wg sync.WaitGroup
	errCh := make(chan error, len(p.sources))

	for _, src := range p.sources {
		wg.Add(1)
		go func(s Source) {
			defer wg.Done()
			if err := p.runSource(ctx, s); err != nil {
				errCh <- err
			}
		}(src)
	}

	// Wait for all sources to finish (context cancelled or error).
	wg.Wait()
	close(errCh)

	// Return the first error, if any.
	for err := range errCh {
		return err
	}
	return nil
}

// runSource reads from a single source in a loop until ctx is done.
func (p *Pipeline) runSource(ctx context.Context, src Source) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		events, err := src.Read()
		if err != nil {
			// Check if context was cancelled during read.
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("pipeline.runSource: %w", err)
		}

		if len(events) == 0 {
			continue
		}

		// Enrich events.
		for i := range events {
			if err := p.enricher.Enrich(ctx, &events[i]); err != nil {
				p.logger.Debug("enrichment error", "error", err, "type", events[i].Type)
			}
		}

		// Fan out to sinks.
		for _, sink := range p.sinks {
			if err := sink.Send(ctx, events); err != nil {
				p.logger.Warn("sink error", "error", err)
			}
		}
	}
}

// Close releases all sources and sinks.
func (p *Pipeline) Close() error {
	var firstErr error

	for _, src := range p.sources {
		if err := src.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for _, sink := range p.sinks {
		if err := sink.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	return firstErr
}
