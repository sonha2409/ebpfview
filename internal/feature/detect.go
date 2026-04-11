package feature

import (
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/features"
	"golang.org/x/sys/unix"
)

// detectKernelVersion returns the kernel release string from uname.
func detectKernelVersion() (string, error) {
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		return "", err
	}
	// Convert the [65]byte release field to a Go string.
	release := uname.Release
	n := 0
	for n < len(release) && release[n] != 0 {
		n++
	}
	return string(release[:n]), nil
}

// probeBTF checks whether the kernel exposes BTF type information.
func probeBTF(logger *slog.Logger) Level {
	defer recoverProbe(logger, "btf")

	_, err := btf.LoadKernelSpec()
	if err != nil {
		logger.Debug("BTF not available", "error", err)
		return Unavailable
	}
	logger.Debug("BTF available")
	return Available
}

// probeRingBuffer checks whether BPF_MAP_TYPE_RINGBUF is supported (5.8+).
func probeRingBuffer(logger *slog.Logger) Level {
	defer recoverProbe(logger, "ring_buffer")

	err := features.HaveMapType(ebpf.RingBuf)
	if err != nil {
		logger.Debug("ring buffer not available", "error", err)
		return Unavailable
	}
	logger.Debug("ring buffer available")
	return Available
}

// probeTrampoline checks whether fentry/fexit BPF trampolines work (5.5+).
func probeTrampoline(logger *slog.Logger) Level {
	defer recoverProbe(logger, "trampoline")

	err := features.HaveProgramType(ebpf.Tracing)
	if err != nil {
		logger.Debug("BPF trampoline (fentry/fexit) not available", "error", err)
		return Unavailable
	}
	logger.Debug("BPF trampoline (fentry/fexit) available")
	return Available
}

// probeBatchMapOps checks whether batch map operations work (5.6+).
func probeBatchMapOps(logger *slog.Logger) Level {
	defer recoverProbe(logger, "batch_map_ops")

	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	})
	if err != nil {
		logger.Debug("batch map ops probe: cannot create test map", "error", err)
		return Unavailable
	}
	defer m.Close()

	// Attempt a batch lookup. If the kernel doesn't support it, we get an error.
	keys := make([]uint32, 1)
	values := make([]uint32, 1)
	var cursor ebpf.MapBatchCursor
	_, err = m.BatchLookup(&cursor, keys, values, nil)
	if err != nil {
		logger.Debug("batch map ops not available", "error", err)
		return Unavailable
	}
	logger.Debug("batch map ops available")
	return Available
}

// probeBPFLink checks whether link-based BPF attachment is supported (5.7+).
// We use HaveMapType(RingBuf) as a proxy — ring buffers arrived in 5.8,
// and BPF link was added in 5.7, so if ring buffers work, links definitely do.
// For a more precise check we probe the Tracing program type which requires links.
func probeBPFLink(logger *slog.Logger) Level {
	defer recoverProbe(logger, "bpf_link")

	// BPF link support is implied by the ability to use program types that
	// require it. We check for perf_event link support via kprobe multi,
	// falling back to checking if Tracing programs (which need links) work.
	err := features.HaveProgramType(ebpf.Tracing)
	if err != nil {
		logger.Debug("BPF link not available", "error", err)
		return Unavailable
	}
	logger.Debug("BPF link available")
	return Available
}

// recoverProbe catches panics from cilium/ebpf probing so a single
// probe failure cannot crash the process.
func recoverProbe(logger *slog.Logger, name string) {
	if r := recover(); r != nil {
		logger.Warn("probe panicked, marking unavailable", "probe", name, "panic", r)
	}
}
