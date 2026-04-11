// Package loader manages BPF program lifecycle.
// All BPF operations go through this package — no direct cilium/ebpf calls
// from TUI, CLI, or export code.
package loader

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// HelloProbe holds a loaded hello-world kprobe and its resources.
type HelloProbe struct {
	coll *ebpf.Collection
	link link.Link
	countMap *ebpf.Map
}

// LoadHello loads the hello BPF program and attaches a kprobe to do_sys_openat2.
func LoadHello(ctx context.Context, spec *ebpf.CollectionSpec) (*HelloProbe, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("loader.LoadHello: remove memlock: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("loader.LoadHello: load collection: %w", err)
	}

	prog := coll.Programs["kprobe_do_sys_openat2"]
	if prog == nil {
		coll.Close()
		return nil, fmt.Errorf("loader.LoadHello: program kprobe_do_sys_openat2 not found in collection")
	}

	kp, err := link.Kprobe("do_sys_openat2", prog, nil)
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("loader.LoadHello: attach kprobe: %w", err)
	}

	countMap := coll.Maps["event_count"]
	if countMap == nil {
		kp.Close()
		coll.Close()
		return nil, fmt.Errorf("loader.LoadHello: map event_count not found in collection")
	}

	return &HelloProbe{
		coll:     coll,
		link:     kp,
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

// Close detaches the kprobe and frees all BPF resources.
func (h *HelloProbe) Close() error {
	var firstErr error

	if h.link != nil {
		if err := h.link.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("loader.Close: detach kprobe: %w", err)
		}
	}

	if h.coll != nil {
		h.coll.Close()
	}

	return firstErr
}
