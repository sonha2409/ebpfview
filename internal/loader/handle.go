package loader

import (
	"io"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// HandleID uniquely identifies a loaded BPF program set within a Manager.
type HandleID uint64

// Status represents the lifecycle state of a Handle.
type Status int

const (
	// StatusLoaded means the BPF collection is loaded but not yet attached.
	StatusLoaded Status = iota
	// StatusAttached means at least one program is attached to a hook point.
	StatusAttached
	// StatusDetached means all programs have been detached (resources still held).
	StatusDetached
	// StatusError means the handle encountered an error during attach/detach.
	StatusError
)

// String returns a human-readable status name.
func (s Status) String() string {
	switch s {
	case StatusLoaded:
		return "loaded"
	case StatusAttached:
		return "attached"
	case StatusDetached:
		return "detached"
	case StatusError:
		return "error"
	default:
		return "unknown"
	}
}

// Handle tracks a loaded BPF collection and its attached programs.
type Handle struct {
	ID         HandleID
	Name       string // human-readable, e.g. "hello", "flows"
	Collection *ebpf.Collection
	Links      []link.Link
	Closers    []io.Closer // non-link resources (e.g. perf event fds)
	Maps       map[string]*ebpf.Map
	Status     Status
	Error      error // last error if StatusError
}

// Close releases all resources held by this handle: links, closers, then collection.
func (h *Handle) Close() error {
	var firstErr error

	for _, l := range h.Links {
		if l == nil {
			continue
		}
		if err := l.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	h.Links = nil

	for _, c := range h.Closers {
		if c == nil {
			continue
		}
		if err := c.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	h.Closers = nil

	if h.Collection != nil {
		h.Collection.Close()
		h.Collection = nil
	}

	h.Maps = nil
	h.Status = StatusDetached
	return firstErr
}
