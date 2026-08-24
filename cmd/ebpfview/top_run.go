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
	"github.com/sonhathai/ebpfview/internal/cpu"
	"github.com/sonhathai/ebpfview/internal/feature"
	"github.com/sonhathai/ebpfview/internal/loader"
	"github.com/sonhathai/ebpfview/internal/syscalls"
)

func newTopCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "top",
		Short: "Live process-level CPU usage",
		Long: `Sample on-CPU time on every CPU via perf events and stream an
htop-style per-process table. USER%/KERN% follow the htop convention:
100% is one full core, so multi-threaded processes can exceed 100%.

CSW/s (context switches per second) requires BPF trampoline support
(kernel 5.5+); the column shows "-" when unavailable.

Requires root or CAP_BPF + CAP_PERFMON.`,
		RunE: runTop,
	}

	cmd.Flags().DurationP("interval", "n", 2*time.Second, "polling interval for the table")
	cmd.Flags().IntP("top", "N", 20, "show only the top N rows by CPU%% (0 = all)")
	cmd.Flags().Uint32("pid", 0, "only show this pid (0 = all)")
	cmd.Flags().Uint64("freq", 99, "sampling frequency in Hz (1-10000)")

	return cmd
}

func runTop(cmd *cobra.Command, args []string) error {
	interval, _ := cmd.Flags().GetDuration("interval")
	topN, _ := cmd.Flags().GetInt("top")
	filterPid, _ := cmd.Flags().GetUint32("pid")
	freq, _ := cmd.Flags().GetUint64("freq")

	if freq < 1 || freq > 10000 {
		return fmt.Errorf("invalid --freq %d: must be between 1 and 10000 Hz", freq)
	}
	if interval <= 0 {
		return fmt.Errorf("invalid --interval %s: must be positive", interval)
	}

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

	spec, err := bpf.LoadCpuSampleSpec()
	if err != nil {
		return fmt.Errorf("load cpusample BPF spec: %w", err)
	}

	handle, err := mgr.Load(ctx, "cpusample", spec)
	if err != nil {
		return fmt.Errorf("load cpusample BPF programs: %w", err)
	}

	if err := mgr.AttachPerfEventAllCPUs(handle, "cpu_sample", freq); err != nil {
		return fmt.Errorf("attach cpu_sample perf event: %w", err)
	}

	// Context switch counting needs a BPF trampoline (kernel 5.5+).
	// Degrade to sampling-only when unavailable instead of failing.
	ctxSwAvailable := false
	if features.Trampoline == feature.Available {
		if err := mgr.AttachBTFTracepoint(handle, "sched_switch_count"); err != nil {
			logger.Warn("sched_switch attach failed, CSW/s disabled", "error", err)
		} else {
			ctxSwAvailable = true
		}
	} else {
		logger.Warn("BPF trampoline unavailable, CSW/s disabled", "kernel", "needs 5.5+")
	}

	cpuMap, ok := handle.Maps["cpu_time"]
	if !ok {
		return fmt.Errorf("cpu_time map not found in BPF collection")
	}

	ch := make(chan []cpu.Record, 4)
	agg := cpu.NewAggregator(cpuMap, features, interval, logger)

	go func() {
		if err := agg.Run(ctx, ch); err != nil && ctx.Err() == nil {
			logger.Error("cpu aggregator stopped", "error", err)
		}
	}()

	fmt.Fprintf(os.Stderr, "Sampling CPU usage at %dHz (Ctrl+C to stop)...\n\n", freq)

	for {
		select {
		case <-ctx.Done():
			fmt.Fprintln(os.Stderr, "\nDetaching...")
			return nil
		case records := <-ch:
			renderTop(records, filterPid, topN, ctxSwAvailable)
		}
	}
}

func renderTop(records []cpu.Record, filterPid uint32, topN int, ctxSwAvailable bool) {
	if filterPid != 0 {
		filtered := records[:0]
		for _, r := range records {
			if r.Pid == filterPid {
				filtered = append(filtered, r)
			}
		}
		records = filtered
	}

	// Active rows first; cumulative on-CPU time as tiebreaker so idle
	// entries sort to the bottom but remain visible.
	sort.Slice(records, func(i, j int) bool {
		if records[i].OnCPUPct != records[j].OnCPUPct {
			return records[i].OnCPUPct > records[j].OnCPUPct
		}
		return records[i].UserNs+records[i].KernNs > records[j].UserNs+records[j].KernNs
	})

	total := len(records)
	if topN > 0 && len(records) > topN {
		records = records[:topN]
	}

	// Clear screen and move cursor to top.
	fmt.Print("\033[2J\033[H")

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintf(w, "PID\tCOMM\tUSER%%\tKERN%%\tCPU%%\tCSW/s\n")
	fmt.Fprintf(w, "---\t----\t-----\t-----\t----\t-----\n")

	for _, r := range records {
		csw := "-"
		if ctxSwAvailable {
			csw = syscalls.FormatCount(r.CtxSwPerSec)
		}
		fmt.Fprintf(w, "%d\t%s\t%.1f\t%.1f\t%.1f\t%s\n",
			r.Pid,
			r.Comm,
			r.UserPct,
			r.KernPct,
			r.OnCPUPct,
			csw,
		)
	}
	w.Flush()

	if topN > 0 && total > topN {
		fmt.Printf("\n%d processes (showing top %d)\n", total, topN)
	} else {
		fmt.Printf("\n%d processes\n", total)
	}
}
