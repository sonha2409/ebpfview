// Package loader manages BPF program lifecycle.
// All BPF operations go through this package — no direct cilium/ebpf calls
// from TUI, CLI, or export code.
package loader

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/sonhathai/ebpfview/internal/feature"
)

// Manager tracks all loaded BPF programs and provides lifecycle operations.
// It is the single entry point for BPF operations — no other package should
// call cilium/ebpf directly.
type Manager struct {
	features *feature.Features
	handles  map[HandleID]*Handle
	nextID   HandleID
	mu       sync.Mutex
	logger   *slog.Logger
}

// NewManager creates a Manager that uses the given feature set to decide
// attach strategies and fallbacks.
func NewManager(features *feature.Features, logger *slog.Logger) *Manager {
	return &Manager{
		features: features,
		handles:  make(map[HandleID]*Handle),
		nextID:   1,
		logger:   logger,
	}
}

// Features returns the runtime feature set this manager was created with.
func (m *Manager) Features() *feature.Features {
	return m.features
}

// Load loads a BPF collection from the given spec and registers it with
// the manager. The returned Handle can be used to attach programs.
func (m *Manager) Load(ctx context.Context, name string, spec *ebpf.CollectionSpec) (*Handle, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("loader.Load: remove memlock: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("loader.Load: %w", err)
	}

	// Build the maps index from the loaded collection.
	maps := make(map[string]*ebpf.Map, len(coll.Maps))
	for k, v := range coll.Maps {
		maps[k] = v
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	id := m.nextID
	m.nextID++

	h := &Handle{
		ID:         id,
		Name:       name,
		Collection: coll,
		Maps:       maps,
		Status:     StatusLoaded,
	}
	m.handles[id] = h

	m.logger.Info("BPF collection loaded",
		"handle", id,
		"name", name,
		"programs", len(coll.Programs),
		"maps", len(coll.Maps),
	)

	return h, nil
}

// Handle returns the handle for the given ID, or false if not found.
func (m *Manager) Handle(id HandleID) (*Handle, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.handles[id]
	return h, ok
}

// Close releases all handles in reverse registration order.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var firstErr error

	// Collect IDs and close in reverse order.
	ids := make([]HandleID, 0, len(m.handles))
	for id := range m.handles {
		ids = append(ids, id)
	}

	// Sort descending for reverse order.
	for i, j := 0, len(ids)-1; i < j; i, j = i+1, j-1 {
		ids[i], ids[j] = ids[j], ids[i]
	}

	for _, id := range ids {
		h := m.handles[id]
		m.logger.Info("closing BPF handle", "handle", id, "name", h.Name)
		if err := h.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("loader.Close: handle %d (%s): %w", id, h.Name, err)
		}
		delete(m.handles, id)
	}

	return firstErr
}
