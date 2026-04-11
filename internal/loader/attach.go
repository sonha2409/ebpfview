package loader

import (
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/sonhathai/ebpfview/internal/feature"
)

// AttachKprobe attaches a kprobe to the named kernel symbol.
// progName must exist in the handle's loaded collection.
func (m *Manager) AttachKprobe(h *Handle, progName, symbol string) error {
	prog := h.Collection.Programs[progName]
	if prog == nil {
		return fmt.Errorf("loader.AttachKprobe: %w: %s", ErrProgNotFound, progName)
	}

	kp, err := link.Kprobe(symbol, prog, nil)
	if err != nil {
		h.Status = StatusError
		h.Error = err
		return fmt.Errorf("loader.AttachKprobe: attach to %s: %w", symbol, err)
	}

	m.mu.Lock()
	h.Links = append(h.Links, kp)
	h.Status = StatusAttached
	m.mu.Unlock()

	m.logger.Info("kprobe attached", "handle", h.ID, "program", progName, "symbol", symbol)
	return nil
}

// AttachKretprobe attaches a kretprobe (return probe) to the named kernel symbol.
func (m *Manager) AttachKretprobe(h *Handle, progName, symbol string) error {
	prog := h.Collection.Programs[progName]
	if prog == nil {
		return fmt.Errorf("loader.AttachKretprobe: %w: %s", ErrProgNotFound, progName)
	}

	kp, err := link.Kretprobe(symbol, prog, nil)
	if err != nil {
		h.Status = StatusError
		h.Error = err
		return fmt.Errorf("loader.AttachKretprobe: attach to %s: %w", symbol, err)
	}

	m.mu.Lock()
	h.Links = append(h.Links, kp)
	h.Status = StatusAttached
	m.mu.Unlock()

	m.logger.Info("kretprobe attached", "handle", h.ID, "program", progName, "symbol", symbol)
	return nil
}

// AttachTracepoint attaches a BPF program to a kernel tracepoint.
// group and name identify the tracepoint (e.g., "syscalls", "sys_enter_openat").
func (m *Manager) AttachTracepoint(h *Handle, progName, group, name string) error {
	prog := h.Collection.Programs[progName]
	if prog == nil {
		return fmt.Errorf("loader.AttachTracepoint: %w: %s", ErrProgNotFound, progName)
	}

	tp, err := link.Tracepoint(group, name, prog, nil)
	if err != nil {
		h.Status = StatusError
		h.Error = err
		return fmt.Errorf("loader.AttachTracepoint: attach to %s/%s: %w", group, name, err)
	}

	m.mu.Lock()
	h.Links = append(h.Links, tp)
	h.Status = StatusAttached
	m.mu.Unlock()

	m.logger.Info("tracepoint attached", "handle", h.ID, "program", progName, "group", group, "name", name)
	return nil
}

// AttachXDP attaches an XDP program to the given network interface.
func (m *Manager) AttachXDP(h *Handle, progName string, ifindex int) error {
	prog := h.Collection.Programs[progName]
	if prog == nil {
		return fmt.Errorf("loader.AttachXDP: %w: %s", ErrProgNotFound, progName)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: ifindex,
	})
	if err != nil {
		h.Status = StatusError
		h.Error = err
		return fmt.Errorf("loader.AttachXDP: attach to ifindex %d: %w", ifindex, err)
	}

	m.mu.Lock()
	h.Links = append(h.Links, l)
	h.Status = StatusAttached
	m.mu.Unlock()

	m.logger.Info("XDP attached", "handle", h.ID, "program", progName, "ifindex", ifindex)
	return nil
}

// AttachFentry attaches a BPF trampoline (fentry) program. Requires
// kernel trampoline support (detected at startup).
func (m *Manager) AttachFentry(h *Handle, progName string) error {
	if m.features.Trampoline == feature.Unavailable {
		return fmt.Errorf("loader.AttachFentry: %w: BPF trampoline", ErrNotSupported)
	}

	prog := h.Collection.Programs[progName]
	if prog == nil {
		return fmt.Errorf("loader.AttachFentry: %w: %s", ErrProgNotFound, progName)
	}

	l, err := link.AttachTracing(link.TracingOptions{
		Program: prog,
	})
	if err != nil {
		h.Status = StatusError
		h.Error = err
		return fmt.Errorf("loader.AttachFentry: %w", err)
	}

	m.mu.Lock()
	h.Links = append(h.Links, l)
	h.Status = StatusAttached
	m.mu.Unlock()

	m.logger.Info("fentry attached", "handle", h.ID, "program", progName)
	return nil
}

// Detach closes all links for the given handle, but keeps the collection
// loaded (programs and maps remain accessible for reads).
func (m *Manager) Detach(id HandleID) error {
	m.mu.Lock()
	h, ok := m.handles[id]
	m.mu.Unlock()

	if !ok {
		return fmt.Errorf("loader.Detach: %w: %d", ErrNotFound, id)
	}

	if h.Status == StatusDetached {
		return fmt.Errorf("loader.Detach: %w: %d", ErrAlreadyDetached, id)
	}

	var firstErr error
	for _, l := range h.Links {
		if l == nil {
			continue
		}
		if err := l.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("loader.Detach: %w", err)
		}
	}

	m.mu.Lock()
	h.Links = nil
	h.Status = StatusDetached
	m.mu.Unlock()

	m.logger.Info("handle detached", "handle", id, "name", h.Name)
	return firstErr
}
