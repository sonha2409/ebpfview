//go:build linux

package bpf

import "github.com/cilium/ebpf"

// LoadSyscallLatSpec returns the CollectionSpec for the syscall latency
// BPF programs (raw tracepoints on sys_enter/sys_exit).
func LoadSyscallLatSpec() (*ebpf.CollectionSpec, error) {
	return loadSyscalllat()
}
