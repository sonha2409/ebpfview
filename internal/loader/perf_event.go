//go:build linux

package loader

import (
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// perfEventFd wraps a perf event file descriptor as an io.Closer.
type perfEventFd struct {
	fd int
}

func (p *perfEventFd) Close() error {
	return unix.Close(p.fd)
}

// AttachPerfEventAllCPUs attaches the named BPF program to a software perf
// event (PERF_COUNT_SW_CPU_CLOCK) on every online CPU at the given sample
// frequency. One closer per CPU is appended to the handle.
func (m *Manager) AttachPerfEventAllCPUs(h *Handle, progName string, sampleFreq uint64) error {
	prog := h.Collection.Programs[progName]
	if prog == nil {
		return fmt.Errorf("loader.AttachPerfEventAllCPUs: %w: %s", ErrProgNotFound, progName)
	}

	nCPU, err := onlineCPUs()
	if err != nil {
		return fmt.Errorf("loader.AttachPerfEventAllCPUs: %w", err)
	}

	var opened []*perfEventFd
	for cpu := 0; cpu < nCPU; cpu++ {
		attr := unix.PerfEventAttr{
			Type:   unix.PERF_TYPE_SOFTWARE,
			Config: unix.PERF_COUNT_SW_CPU_CLOCK,
			Size:   uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
			Sample: sampleFreq,
			Bits:   unix.PerfBitFreq,
		}

		fd, err := unix.PerfEventOpen(&attr, -1, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
		if err != nil {
			closeAll(opened)
			return fmt.Errorf("loader.AttachPerfEventAllCPUs: cpu %d: perf_event_open: %w", cpu, err)
		}

		pe := &perfEventFd{fd: fd}
		opened = append(opened, pe)

		if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_SET_BPF, prog.FD()); err != nil {
			closeAll(opened)
			return fmt.Errorf("loader.AttachPerfEventAllCPUs: cpu %d: ioctl SET_BPF: %w", cpu, err)
		}

		if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
			closeAll(opened)
			return fmt.Errorf("loader.AttachPerfEventAllCPUs: cpu %d: ioctl ENABLE: %w", cpu, err)
		}
	}

	m.mu.Lock()
	for _, pe := range opened {
		h.Closers = append(h.Closers, pe)
	}
	h.Status = StatusAttached
	m.mu.Unlock()

	m.logger.Info("perf event attached on all CPUs",
		"handle", h.ID,
		"program", progName,
		"cpus", nCPU,
		"freq", sampleFreq,
	)
	return nil
}

func closeAll(fds []*perfEventFd) {
	for _, pe := range fds {
		pe.Close()
	}
}

func onlineCPUs() (int, error) {
	data, err := os.ReadFile("/sys/devices/system/cpu/online")
	if err != nil {
		return runtime.NumCPU(), nil
	}
	return parseCPURange(string(data))
}

// parseCPURange parses the kernel CPU range format (e.g. "0-7" or "0-3,5,7-9")
// and returns the count of CPUs.
func parseCPURange(s string) (int, error) {
	count := 0
	for _, r := range splitTrim(s) {
		var lo, hi int
		n, _ := fmt.Sscanf(r, "%d-%d", &lo, &hi)
		if n == 2 {
			count += hi - lo + 1
		} else if n, _ = fmt.Sscanf(r, "%d", &lo); n == 1 {
			count++
		}
	}
	if count == 0 {
		return runtime.NumCPU(), nil
	}
	return count, nil
}

func splitTrim(s string) []string {
	var parts []string
	cur := ""
	for _, c := range s {
		if c == ',' || c == '\n' {
			if cur != "" {
				parts = append(parts, cur)
			}
			cur = ""
		} else if c != ' ' {
			cur += string(c)
		}
	}
	if cur != "" {
		parts = append(parts, cur)
	}
	return parts
}
