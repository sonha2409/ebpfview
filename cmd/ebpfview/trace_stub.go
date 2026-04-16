//go:build !linux

package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newTraceCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "trace",
		Short: "Trace syscall latency per process",
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("ebpfview trace requires Linux")
		},
	}
}
