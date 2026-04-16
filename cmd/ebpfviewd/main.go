package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var version = "dev"

func newRootCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "ebpfviewd",
		Short:   "ebpfview daemon — privileged BPF program manager",
		Version: version,
		Long: `ebpfviewd runs as a privileged daemon that manages BPF program
lifecycle and exposes data to unprivileged ebpfview CLI clients
over a Unix domain socket.`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("ebpfviewd: not yet implemented")
			return nil
		},
	}
}

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}
