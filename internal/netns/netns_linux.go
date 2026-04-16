//go:build linux

package netns

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Enumerate walks /proc/*/ns/net and returns one Handle per distinct
// netns inode. Requires read access to /proc — typically root.
func Enumerate() ([]Handle, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("netns.Enumerate: read /proc: %w", err)
	}

	seen := make(map[uint64]Handle)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		// Only numeric PID directories.
		pid := e.Name()
		if pid == "" || pid[0] < '0' || pid[0] > '9' {
			continue
		}
		path := filepath.Join("/proc", pid, "ns", "net")
		var st syscall.Stat_t
		if err := syscall.Stat(path, &st); err != nil {
			// Process likely exited between readdir and stat — ignore.
			continue
		}
		if _, ok := seen[st.Ino]; ok {
			continue
		}
		seen[st.Ino] = Handle{
			Inode: st.Ino,
			Path:  path,
			Name:  fmt.Sprintf("pid%s", pid),
		}
	}

	// Also pick up named namespaces under /var/run/netns (populated by
	// `ip netns add`). Named entries take precedence for the Name field.
	if named, err := os.ReadDir("/var/run/netns"); err == nil {
		for _, e := range named {
			path := filepath.Join("/var/run/netns", e.Name())
			var st syscall.Stat_t
			if err := syscall.Stat(path, &st); err != nil {
				continue
			}
			h := seen[st.Ino]
			h.Inode = st.Ino
			h.Name = e.Name()
			// Prefer the stable named path over the /proc one — /proc
			// paths disappear when the holding process exits.
			h.Path = path
			seen[st.Ino] = h
		}
	}

	out := make([]Handle, 0, len(seen))
	for _, h := range seen {
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Inode < out[j].Inode })
	return out, nil
}

// Self returns a Handle for the caller's current network namespace.
func Self() (Handle, error) {
	path := "/proc/self/ns/net"
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return Handle{}, fmt.Errorf("netns.Self: stat: %w", err)
	}
	return Handle{Inode: st.Ino, Path: path, Name: "self"}, nil
}

// Enter runs fn on a locked OS thread after switching into the target
// namespace. On return, the thread is intentionally not unlocked and the
// goroutine exits — the Go runtime then destroys the tainted thread so
// no other goroutine ever inherits its netns. fn should capture any
// results via closure variables.
//
// Enter runs fn synchronously and returns its error.
func Enter(h Handle, fn func() error) error {
	// Run on a dedicated goroutine so we can lock its OS thread and then
	// abandon that thread on exit.
	type result struct{ err error }
	done := make(chan result, 1)

	go func() {
		runtime.LockOSThread()
		// Deliberately do NOT UnlockOSThread — by leaving the thread
		// locked and returning from the goroutine, the Go runtime kills
		// the thread rather than recycling it with mutated netns state.

		f, err := os.Open(h.Path)
		if err != nil {
			done <- result{fmt.Errorf("netns.Enter: open %s: %w", h.Path, err)}
			return
		}
		defer f.Close()

		if err := unix.Setns(int(f.Fd()), unix.CLONE_NEWNET); err != nil {
			done <- result{fmt.Errorf("netns.Enter: setns: %w", err)}
			return
		}

		done <- result{fn()}
	}()

	r := <-done
	return r.err
}

// Watcher polls the set of observed netns at a fixed interval and emits
// EventAdded / EventRemoved events. It is a simple poller because /proc
// does not support inotify and RTNLGRP_NSID only covers nsid assignments,
// not creation. Interval should typically be 1–3s.
type Watcher struct {
	interval time.Duration
	logger   *slog.Logger
}

// NewWatcher creates a Watcher that polls at the given interval.
func NewWatcher(interval time.Duration, logger *slog.Logger) *Watcher {
	if interval <= 0 {
		interval = 2 * time.Second
	}
	return &Watcher{interval: interval, logger: logger}
}

// Run emits events on out until ctx is cancelled. The initial snapshot
// is emitted as a burst of EventAdded events. The output channel is not
// closed by Run — the caller owns its lifecycle.
func (w *Watcher) Run(ctx context.Context, out chan<- Event) error {
	known := make(map[uint64]Handle)

	// Initial snapshot.
	initial, err := Enumerate()
	if err != nil {
		return fmt.Errorf("netns.Watcher: initial enumerate: %w", err)
	}
	for _, h := range initial {
		known[h.Inode] = h
		if err := send(ctx, out, Event{Type: EventAdded, Handle: h}); err != nil {
			return err
		}
	}

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			current, err := Enumerate()
			if err != nil {
				w.logger.Warn("netns enumerate failed", "error", err)
				continue
			}
			// Build current set for diffing.
			currentSet := make(map[uint64]Handle, len(current))
			for _, h := range current {
				currentSet[h.Inode] = h
			}
			// Emit added.
			for ino, h := range currentSet {
				if _, ok := known[ino]; !ok {
					known[ino] = h
					if err := send(ctx, out, Event{Type: EventAdded, Handle: h}); err != nil {
						return err
					}
				}
			}
			// Emit removed.
			for ino, h := range known {
				if _, ok := currentSet[ino]; !ok {
					delete(known, ino)
					if err := send(ctx, out, Event{Type: EventRemoved, Handle: h}); err != nil {
						return err
					}
				}
			}
		}
	}
}

func send(ctx context.Context, out chan<- Event, ev Event) error {
	select {
	case out <- ev:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
