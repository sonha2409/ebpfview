//go:build linux

package main

import (
	"context"
	"errors"
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
	"github.com/sonhathai/ebpfview/internal/netns"
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

	cmd.Flags().StringP("iface", "i", "", "network interface to attach to (required unless --all-netns)")
	cmd.Flags().DurationP("interval", "n", time.Second, "polling interval for flow table")
	cmd.Flags().Bool("all-netns", false, "enumerate network namespaces and attach --iface inside each")
	cmd.Flags().Duration("netns-scan", 2*time.Second, "interval at which to rescan for new/removed netns")

	return cmd
}

func runFlows(cmd *cobra.Command, args []string) error {
	ifaceName, _ := cmd.Flags().GetString("iface")
	interval, _ := cmd.Flags().GetDuration("interval")
	allNetns, _ := cmd.Flags().GetBool("all-netns")
	netnsScan, _ := cmd.Flags().GetDuration("netns-scan")

	if ifaceName == "" {
		return fmt.Errorf("--iface is required")
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	if verbose {
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		}))
	}

	// Resolve interface name to index in the current (root) namespace. When
	// --all-netns is set, the same name is re-resolved inside each netns.
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil && !allNetns {
		return fmt.Errorf("interface %q: %w", ifaceName, err)
	}
	if iface != nil {
		logger.Info("resolved interface", "name", ifaceName, "index", iface.Index)
	}

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

	// Attach TCX in the root namespace (always) unless --all-netns is set
	// with no root-level iface — in that case, defer to the watcher.
	if iface != nil {
		if err := mgr.AttachTCXIngress(handle, "flows_ingress", iface.Index); err != nil {
			return fmt.Errorf("attach TCX ingress: %w", err)
		}
		if err := mgr.AttachTCXEgress(handle, "flows_egress", iface.Index); err != nil {
			return fmt.Errorf("attach TCX egress: %w", err)
		}
	}

	// --all-netns: discover other network namespaces and attach inside each.
	if allNetns {
		if err := startNetnsWatcher(ctx, logger, mgr, handle, ifaceName, netnsScan); err != nil {
			return fmt.Errorf("start netns watcher: %w", err)
		}
	}

	// Attach RTT fentry probe when the kernel supports trampolines.
	// Degrade gracefully: RTT is an optional column, not core flow tracking.
	if features.Trampoline == feature.Available {
		if err := mgr.AttachFentry(handle, "flows_rtt_v4"); err != nil {
			logger.Warn("RTT fentry probe unavailable — continuing without RTT", "error", err)
		} else {
			logger.Info("RTT probe attached (fentry/tcp_rcv_established)")
		}
	} else {
		logger.Info("kernel lacks BPF trampolines — RTT column disabled")
	}

	logger.Info("flow tracking active", "iface", ifaceName)

	// Get the flow_table map from the loaded collection.
	flowMap, ok := handle.Maps["flow_table"]
	if !ok {
		return fmt.Errorf("flow_table map not found in BPF collection")
	}
	// rtt_samples is populated only when the fentry probe is attached, but
	// the map is always present in the collection — safe to pass unconditionally.
	rttMap := handle.Maps["rtt_samples"]

	// Start the aggregator.
	ch := make(chan []flows.FlowRecord, 4)
	agg := flows.NewAggregator(flowMap, rttMap, features, interval, logger)

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

// startNetnsWatcher enumerates existing network namespaces and attaches
// the flow programs to ifaceName inside each, then watches for newly-created
// namespaces and attaches to them on the fly. The root namespace (which the
// caller already handled) is skipped by inode comparison.
func startNetnsWatcher(
	ctx context.Context,
	logger *slog.Logger,
	mgr *loader.Manager,
	handle *loader.Handle,
	ifaceName string,
	scan time.Duration,
) error {
	self, err := netns.Self()
	if err != nil {
		return err
	}

	watcher := netns.NewWatcher(scan, logger)
	events := make(chan netns.Event, 16)
	go func() {
		if err := watcher.Run(ctx, events); err != nil && ctx.Err() == nil {
			logger.Error("netns watcher stopped", "error", err)
		}
	}()

	// Track which inodes we've attached to (best-effort — we do not
	// currently detach on removal since the link holds a reference that
	// the kernel releases automatically when the netns goes away).
	attached := make(map[uint64]bool)
	attached[self.Inode] = true

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case ev := <-events:
				if ev.Type != netns.EventAdded {
					if ev.Type == netns.EventRemoved {
						delete(attached, ev.Handle.Inode)
						logger.Info("netns removed", "ns", ev.Handle.String())
					}
					continue
				}
				if attached[ev.Handle.Inode] {
					continue
				}
				err := mgr.AttachTCXInNs(
					handle,
					"flows_ingress", "flows_egress",
					ev.Handle.String(),
					func(fn func() error) error { return netns.Enter(ev.Handle, fn) },
					func() (int, error) {
						i, err := net.InterfaceByName(ifaceName)
						if err != nil {
							return 0, err
						}
						return i.Index, nil
					},
				)
				if err != nil {
					// Not every ns has the named iface — demote to debug.
					if errors.Is(err, syscall.ENODEV) {
						logger.Debug("iface not present in netns", "ns", ev.Handle.String(), "iface", ifaceName)
					} else {
						logger.Warn("attach in netns failed", "ns", ev.Handle.String(), "error", err)
					}
					continue
				}
				attached[ev.Handle.Inode] = true
			}
		}
	}()

	return nil
}

func renderFlows(records []flows.FlowRecord) {
	// Sort by bytes/s descending.
	sort.Slice(records, func(i, j int) bool {
		return records[i].BytesPerSec > records[j].BytesPerSec
	})

	// Clear screen and move cursor to top.
	fmt.Print("\033[2J\033[H")

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintf(w, "SRC\tDST\tPROTO\tPKTS/s\tBYTES/s\tPKTS\tBYTES\tRTT\n")
	fmt.Fprintf(w, "---\t---\t-----\t------\t-------\t----\t-----\t---\n")

	for _, r := range records {
		fmt.Fprintf(w, "%s\t%s\t%s\t%.0f\t%s\t%d\t%s\t%s\n",
			flows.FormatAddr(r.SrcAddr, r.SrcPort),
			flows.FormatAddr(r.DstAddr, r.DstPort),
			flows.ProtoName(r.Proto),
			r.PacketsPerSec,
			flows.FormatBytes(r.BytesPerSec),
			r.Packets,
			flows.FormatBytes(float64(r.Bytes)),
			flows.FormatRTT(r.SRTTUs),
		)
	}
	w.Flush()

	fmt.Printf("\n%d flows\n", len(records))
}
