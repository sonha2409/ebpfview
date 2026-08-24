//go:build !linux

package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newTopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "top",
		Short: "Live process-level CPU usage",
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("ebpfview top requires Linux")
		},
	}
}
