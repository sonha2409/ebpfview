//go:build linux

package bpf

import "github.com/cilium/ebpf"

// LoadCpuSampleSpec returns the CollectionSpec for the CPU sampling
// BPF programs (perf_event/cpu_sample + tp_btf/sched_switch).
func LoadCpuSampleSpec() (*ebpf.CollectionSpec, error) {
	return loadCpusample()
}
