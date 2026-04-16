//go:build !linux

package netns

import (
	"context"
	"log/slog"
	"time"
)

// Enumerate is not supported on non-Linux platforms.
func Enumerate() ([]Handle, error) {
	return nil, ErrNotSupported
}

// Self is not supported on non-Linux platforms.
func Self() (Handle, error) {
	return Handle{}, ErrNotSupported
}

// Enter is not supported on non-Linux platforms.
func Enter(h Handle, fn func() error) error {
	return ErrNotSupported
}

// Watcher stub — Run always returns ErrNotSupported.
type Watcher struct{}

// NewWatcher returns a stub Watcher on non-Linux platforms.
func NewWatcher(_ time.Duration, _ *slog.Logger) *Watcher {
	return &Watcher{}
}

// Run returns ErrNotSupported on non-Linux platforms.
func (w *Watcher) Run(_ context.Context, _ chan<- Event) error {
	return ErrNotSupported
}
