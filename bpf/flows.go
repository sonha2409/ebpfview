//go:build linux

package bpf

import "github.com/cilium/ebpf"

// LoadFlowsSpec returns the CollectionSpec for the flows BPF programs.
// This wraps the bpf2go-generated loadFlows function to export it.
func LoadFlowsSpec() (*ebpf.CollectionSpec, error) {
	return loadFlows()
}
