//go:build linux

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/sonhathai/ebpfview/bpf"
	"github.com/sonhathai/ebpfview/internal/feature"
	"github.com/sonhathai/ebpfview/internal/loader"
	"github.com/sonhathai/ebpfview/internal/syscalls"
)

func newTraceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "trace",
		Short: "Trace syscall latency per process",
		Long: `Attach raw tracepoints to sys_enter/sys_exit and stream a live
per-(pid, syscall) latency histogram. Each row shows call rate and
p50/p99/min/max latency computed over the last interval.

Requires root or CAP_BPF + CAP_PERFMON. Uses raw tracepoints (4.17+).`,
		RunE: runTrace,
	}

	cmd.Flags().DurationP("interval", "n", time.Second, "polling interval for the histogram table")
	cmd.Flags().IntP("top", "N", 20, "show only the top N rows by call rate (0 = all)")
	cmd.Flags().Uint32("pid", 0, "only show syscalls from this pid (0 = all)")

	return cmd
}

func runTrace(cmd *cobra.Command, args []string) error {
	interval, _ := cmd.Flags().GetDuration("interval")
	topN, _ := cmd.Flags().GetInt("top")
	filterPid, _ := cmd.Flags().GetUint32("pid")

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	if verbose {
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		}))
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	features, err := feature.Detect(ctx, logger)
	if err != nil {
		return fmt.Errorf("feature detection: %w", err)
	}
	features.Log(logger)

	mgr := loader.NewManager(features, logger)
	defer mgr.Close()

	spec, err := bpf.LoadSyscallLatSpec()
	if err != nil {
		return fmt.Errorf("load syscall_lat BPF spec: %w", err)
	}

	handle, err := mgr.Load(ctx, "syscall_lat", spec)
	if err != nil {
		return fmt.Errorf("load syscall_lat BPF programs: %w", err)
	}

	if err := mgr.AttachRawTracepoint(handle, "raw_tp_sys_enter", "sys_enter"); err != nil {
		return fmt.Errorf("attach sys_enter: %w", err)
	}
	if err := mgr.AttachRawTracepoint(handle, "raw_tp_sys_exit", "sys_exit"); err != nil {
		return fmt.Errorf("attach sys_exit: %w", err)
	}

	latMap, ok := handle.Maps["syscall_lat"]
	if !ok {
		return fmt.Errorf("syscall_lat map not found in BPF collection")
	}

	ch := make(chan []syscalls.Record, 4)
	agg := syscalls.NewAggregator(latMap, features, interval, logger)

	go func() {
		if err := agg.Run(ctx, ch); err != nil && ctx.Err() == nil {
			logger.Error("syscall aggregator stopped", "error", err)
		}
	}()

	fmt.Fprintf(os.Stderr, "Tracing syscall latency (Ctrl+C to stop)...\n\n")

	for {
		select {
		case <-ctx.Done():
			fmt.Fprintln(os.Stderr, "\nDetaching...")
			return nil
		case records := <-ch:
			renderTrace(records, filterPid, topN)
		}
	}
}

func renderTrace(records []syscalls.Record, filterPid uint32, topN int) {
	if filterPid != 0 {
		filtered := records[:0]
		for _, r := range records {
			if r.Pid == filterPid {
				filtered = append(filtered, r)
			}
		}
		records = filtered
	}

	// Surface rows with any activity first, then by cumulative count as a
	// tiebreaker so idle entries sort to the bottom but remain visible.
	sort.Slice(records, func(i, j int) bool {
		if records[i].CountPerSec != records[j].CountPerSec {
			return records[i].CountPerSec > records[j].CountPerSec
		}
		return records[i].Count > records[j].Count
	})

	total := len(records)
	if topN > 0 && len(records) > topN {
		records = records[:topN]
	}

	// Clear screen and move cursor to top.
	fmt.Print("\033[2J\033[H")

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintf(w, "PID\tSYSCALL\tCOUNT/s\tP50\tP99\tMIN\tMAX\n")
	fmt.Fprintf(w, "---\t-------\t-------\t---\t---\t---\t---\n")

	for _, r := range records {
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\t%s\n",
			r.Pid,
			r.Name,
			syscalls.FormatCount(r.CountPerSec),
			syscalls.FormatLatency(r.P50Ns),
			syscalls.FormatLatency(r.P99Ns),
			syscalls.FormatLatency(r.MinNs),
			syscalls.FormatLatency(r.MaxNs),
		)
	}
	w.Flush()

	if topN > 0 && total > topN {
		fmt.Printf("\n%d entries (showing top %d)\n", total, topN)
	} else {
		fmt.Printf("\n%d entries\n", total)
	}
}
