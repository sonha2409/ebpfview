// Package netns provides discovery, tracking, and entry into Linux
// network namespaces. It is Linux-only; non-Linux builds fall back
// to stubs that return ErrNotSupported.
package netns

import (
	"errors"
	"fmt"
)

// ErrNotSupported is returned by netns operations on non-Linux platforms.
var ErrNotSupported = errors.New("netns: only supported on linux")

// Handle represents a network namespace. Inode is the unique identifier
// (from stat on /proc/<pid>/ns/net); Path is a stable path that can be
// opened with setns; Name is a best-effort human-readable label.
type Handle struct {
	Inode uint64
	Path  string
	Name  string
}

// String returns a short representation suitable for logging.
func (h Handle) String() string {
	if h.Name != "" {
		return fmt.Sprintf("netns(%s, inode=%d)", h.Name, h.Inode)
	}
	return fmt.Sprintf("netns(inode=%d)", h.Inode)
}

// EventType is the kind of namespace lifecycle change observed.
type EventType int

const (
	// EventAdded means a netns was observed for the first time.
	EventAdded EventType = iota + 1
	// EventRemoved means a previously observed netns no longer exists.
	EventRemoved
)

// String returns a human-readable event name.
func (e EventType) String() string {
	switch e {
	case EventAdded:
		return "added"
	case EventRemoved:
		return "removed"
	default:
		return "unknown"
	}
}

// Event is a single namespace lifecycle change.
type Event struct {
	Type   EventType
	Handle Handle
}
