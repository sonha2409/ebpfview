//go:build linux

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/sonhathai/ebpfview/bpf"
	"github.com/sonhathai/ebpfview/internal/feature"
	"github.com/sonhathai/ebpfview/internal/flows"
	"github.com/sonhathai/ebpfview/internal/loader"
)

func newFlowsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "flows",
		Short: "Stream real-time network flow data",
		Long: `Attach TC classifier BPF programs to a network interface and stream
a live table of network flows with packet/byte rate calculations.

Requires root or CAP_NET_ADMIN + CAP_BPF. Uses TCX (kernel 6.6+).`,
		RunE: runFlows,
	}

	cmd.Flags().StringP("iface", "i", "", "network interface to attach to (required)")
	cmd.Flags().DurationP("interval", "n", time.Second, "polling interval for flow table")
	_ = cmd.MarkFlagRequired("iface")

	return cmd
}

func runFlows(cmd *cobra.Command, args []string) error {
	ifaceName, _ := cmd.Flags().GetString("iface")
	interval, _ := cmd.Flags().GetDuration("interval")

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	if verbose {
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		}))
	}

	// Resolve interface name to index.
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("interface %q: %w", ifaceName, err)
	}
	logger.Info("resolved interface", "name", ifaceName, "index", iface.Index)

	// Detect kernel features.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	features, err := feature.Detect(ctx, logger)
	if err != nil {
		return fmt.Errorf("feature detection: %w", err)
	}
	features.Log(logger)

	// Load the flows BPF collection.
	mgr := loader.NewManager(features, logger)
	defer mgr.Close()

	spec, err := bpf.LoadFlowsSpec()
	if err != nil {
		return fmt.Errorf("load flows BPF spec: %w", err)
	}

	handle, err := mgr.Load(ctx, "flows", spec)
	if err != nil {
		return fmt.Errorf("load flows BPF programs: %w", err)
	}

	// Attach TCX ingress and egress.
	if err := mgr.AttachTCXIngress(handle, "flows_ingress", iface.Index); err != nil {
		return fmt.Errorf("attach TCX ingress: %w", err)
	}
	if err := mgr.AttachTCXEgress(handle, "flows_egress", iface.Index); err != nil {
		return fmt.Errorf("attach TCX egress: %w", err)
	}

	logger.Info("flow tracking active", "iface", ifaceName)

	// Get the flow_table map from the loaded collection.
	flowMap, ok := handle.Maps["flow_table"]
	if !ok {
		return fmt.Errorf("flow_table map not found in BPF collection")
	}

	// Start the aggregator.
	ch := make(chan []flows.FlowRecord, 4)
	agg := flows.NewAggregator(flowMap, features, interval, logger)

	go func() {
		if err := agg.Run(ctx, ch); err != nil && ctx.Err() == nil {
			logger.Error("aggregator stopped", "error", err)
		}
	}()

	fmt.Fprintf(os.Stderr, "Streaming flows on %s (Ctrl+C to stop)...\n\n", ifaceName)

	// Render flow records as a refreshing table.
	for {
		select {
		case <-ctx.Done():
			fmt.Fprintln(os.Stderr, "\nDetaching...")
			return nil
		case records := <-ch:
			renderFlows(records)
		}
	}
}

func renderFlows(records []flows.FlowRecord) {
	// Sort by bytes/s descending.
	sort.Slice(records, func(i, j int) bool {
		return records[i].BytesPerSec > records[j].BytesPerSec
	})

	// Clear screen and move cursor to top.
	fmt.Print("\033[2J\033[H")

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintf(w, "SRC\tDST\tPROTO\tPKTS/s\tBYTES/s\tPKTS\tBYTES\n")
	fmt.Fprintf(w, "---\t---\t-----\t------\t-------\t----\t-----\n")

	for _, r := range records {
		fmt.Fprintf(w, "%s\t%s\t%s\t%.0f\t%s\t%d\t%s\n",
			flows.FormatAddr(r.SrcAddr, r.SrcPort),
			flows.FormatAddr(r.DstAddr, r.DstPort),
			flows.ProtoName(r.Proto),
			r.PacketsPerSec,
			flows.FormatBytes(r.BytesPerSec),
			r.Packets,
			flows.FormatBytes(float64(r.Bytes)),
		)
	}
	w.Flush()

	fmt.Printf("\n%d flows\n", len(records))
}
