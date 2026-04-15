//go:build !linux

package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newFlowsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "flows",
		Short: "Stream real-time network flow data",
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("ebpfview flows requires Linux")
		},
	}
}
