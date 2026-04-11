package loader

// Pin and Unpin are stubs for Phase 1. Real BPF pinning to bpffs
// will be implemented in Phase 10 (Daemon Mode).

// Pin pins all programs and maps from the given handle to bpffs
// under basePath. This is a stub — full implementation in Phase 10.
func (m *Manager) Pin(id HandleID, basePath string) error {
	m.logger.Warn("Pin is not yet implemented", "handle", id, "path", basePath)
	return nil
}

// Unpin recovers a previously pinned handle from bpffs.
// This is a stub — full implementation in Phase 10.
func (m *Manager) Unpin(basePath string) (*Handle, error) {
	m.logger.Warn("Unpin is not yet implemented", "path", basePath)
	return nil, ErrNotSupported
}
