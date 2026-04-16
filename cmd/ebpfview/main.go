package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	version = "dev"
	cfgFile string
	verbose bool
)

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "ebpfview",
		Short: "Zero-instrumentation eBPF observability CLI",
		Long: `ebpfview attaches eBPF programs to a running Linux system and streams
real-time network flows, syscall latency heatmaps, per-process CPU
flamegraph data, and userspace function traces — with zero changes
to target applications.`,
		SilenceUsage: true,
	}

	root.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default $HOME/.ebpfview.toml)")
	root.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose output")

	root.AddCommand(
		newFlowsCmd(),
		newTraceCmd(),
		newTopCmd(),
		newFlamegraphCmd(),
		newUprobeCmd(),
		newVersionCmd(),
	)

	return root
}

// newFlowsCmd is defined in flows_run.go (linux) or flows_stub.go (other).
// newTraceCmd is defined in trace_run.go (linux) or trace_stub.go (other).

func newTopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "top",
		Short: "Live process-level resource usage",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("ebpfview top: not yet implemented")
			return nil
		},
	}
}

func newFlamegraphCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "flamegraph",
		Short: "Capture and render CPU flamegraphs",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("ebpfview flamegraph: not yet implemented")
			return nil
		},
	}
}

func newUprobeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "uprobe",
		Short: "Attach userspace function probes",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("ebpfview uprobe: not yet implemented")
			return nil
		},
	}
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("ebpfview %s\n", version)
		},
	}
}

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}
