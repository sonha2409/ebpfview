package pipeline

import "context"

// Enricher adds metadata to events (e.g., PID → process name, container info).
type Enricher interface {
	// Enrich populates metadata fields on the event in-place.
	Enrich(ctx context.Context, e *Event) error
}

// NoopEnricher is a placeholder that performs no enrichment.
// It will be replaced by container/k8s-aware enrichers in Phase 9.
type NoopEnricher struct{}

// Enrich is a no-op.
func (NoopEnricher) Enrich(_ context.Context, _ *Event) error {
	return nil
}
