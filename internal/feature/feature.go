// Package feature provides runtime detection of kernel BPF capabilities.
// Call Detect once at startup to probe what the running kernel supports.
// Results drive fallback decisions throughout the loader and pipeline.
package feature

import (
	"context"
	"fmt"
	"log/slog"
)

// Level indicates whether a kernel capability is available.
type Level int

const (
	// Unavailable means the kernel does not support the capability.
	Unavailable Level = iota
	// Available means the kernel supports the capability.
	Available
)

// String returns a human-readable representation of the level.
func (l Level) String() string {
	switch l {
	case Available:
		return "available"
	default:
		return "unavailable"
	}
}

// Features holds the results of runtime capability detection.
type Features struct {
	BTF           Level  // Kernel BTF type information
	RingBuffer    Level  // BPF_MAP_TYPE_RINGBUF support (5.8+)
	Trampoline    Level  // fentry/fexit BPF trampolines (5.5+)
	BatchMapOps   Level  // BPF_MAP_LOOKUP_BATCH (5.6+)
	BPFLink       Level  // link-based program attachment (5.7+)
	KernelVersion string // uname -r for logging
}

// Detect probes the running kernel for BPF capabilities. Each probe is
// independent — a failure in one does not affect others. Returns error
// only if we cannot determine the kernel version (considered fatal).
func Detect(ctx context.Context, logger *slog.Logger) (*Features, error) {
	f := &Features{}

	kver, err := detectKernelVersion()
	if err != nil {
		return nil, fmt.Errorf("feature.Detect: kernel version: %w", err)
	}
	f.KernelVersion = kver

	f.BTF = probeBTF(logger)
	f.RingBuffer = probeRingBuffer(logger)
	f.Trampoline = probeTrampoline(logger)
	f.BatchMapOps = probeBatchMapOps(logger)
	f.BPFLink = probeBPFLink(logger)

	return f, nil
}

// Log emits a structured summary of detected features at Info level.
func (f *Features) Log(logger *slog.Logger) {
	logger.Info("runtime feature detection complete",
		"kernel", f.KernelVersion,
		"btf", f.BTF,
		"ring_buffer", f.RingBuffer,
		"trampoline", f.Trampoline,
		"batch_map_ops", f.BatchMapOps,
		"bpf_link", f.BPFLink,
	)
}
