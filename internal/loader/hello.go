package loader

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf"
)

// HelloProbe wraps the hello-world kprobe using the Manager for lifecycle.
// This is a convenience type for the Phase 0 proof-of-concept program.
type HelloProbe struct {
	handle   *Handle
	manager  *Manager
	countMap *ebpf.Map
}

// LoadHello loads the hello BPF program and attaches a kprobe to do_sys_openat2
// using the given manager for lifecycle management.
func LoadHello(ctx context.Context, mgr *Manager, spec *ebpf.CollectionSpec) (*HelloProbe, error) {
	h, err := mgr.Load(ctx, "hello", spec)
	if err != nil {
		return nil, fmt.Errorf("loader.LoadHello: %w", err)
	}

	if err := mgr.AttachKprobe(h, "kprobe_do_sys_openat2", "do_sys_openat2"); err != nil {
		return nil, fmt.Errorf("loader.LoadHello: %w", err)
	}

	countMap, ok := h.Maps["event_count"]
	if !ok {
		return nil, fmt.Errorf("loader.LoadHello: %w: event_count", ErrMapNotFound)
	}

	return &HelloProbe{
		handle:   h,
		manager:  mgr,
		countMap: countMap,
	}, nil
}

// ReadCount reads the current event count from the BPF map.
func (h *HelloProbe) ReadCount() (uint64, error) {
	var key uint32
	var value uint64

	if err := h.countMap.Lookup(&key, &value); err != nil {
		// Fall back to raw bytes if direct lookup fails.
		var buf [8]byte
		if err := h.countMap.Lookup(&key, &buf); err != nil {
			return 0, fmt.Errorf("loader.ReadCount: %w", err)
		}
		value = binary.LittleEndian.Uint64(buf[:])
	}

	return value, nil
}

// Close detaches the kprobe and frees all BPF resources via the manager.
func (h *HelloProbe) Close() error {
	if h.handle == nil {
		return nil
	}
	return h.handle.Close()
}
