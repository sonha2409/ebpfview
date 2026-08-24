package cpu

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/cilium/ebpf"
	"github.com/sonhathai/ebpfview/internal/feature"
)

// Aggregator periodically reads the BPF cpu_time PERCPU_HASH, sums
// values across CPUs, computes per-interval deltas against the previous
// snapshot, and emits []Record batches on its output channel.
//
// Because cpu_time is a plain (non-LRU) hash map, the Aggregator also
// reaps entries for processes that no longer exist so the map cannot
// fill up with dead PIDs. A process that exited during the interval is
// emitted one final time before its entry is deleted.
type Aggregator struct {
	cpuMap   *ebpf.Map
	interval time.Duration
	prev     map[Key]Value
	prevTime time.Time
	features *feature.Features
	proc     *commReader
	log      *slog.Logger
}

// NewAggregator creates an Aggregator that polls cpuMap at the given interval.
func NewAggregator(cpuMap *ebpf.Map, features *feature.Features, interval time.Duration, logger *slog.Logger) *Aggregator {
	return &Aggregator{
		cpuMap:   cpuMap,
		interval: interval,
		prev:     make(map[Key]Value),
		features: features,
		proc:     newCommReader("/proc"),
		log:      logger,
	}
}

// Run polls the cpu_time map on each tick and sends Records to out.
// It blocks until ctx is cancelled. The output channel is NOT closed by
// Run — the caller owns the channel lifecycle.
func (a *Aggregator) Run(ctx context.Context, out chan<- []Record) error {
	ticker := time.NewTicker(a.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			records, err := a.poll()
			if err != nil {
				a.log.Warn("cpu poll failed", "error", err)
				continue
			}
			if len(records) == 0 {
				continue
			}
			select {
			case out <- records:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}

// Poll reads one snapshot and returns the aggregated Records. Exposed
// for tests and for callers that want to drive the aggregator manually.
func (a *Aggregator) Poll() ([]Record, error) {
	return a.poll()
}

func (a *Aggregator) poll() ([]Record, error) {
	now := time.Now()
	current, err := a.readMap()
	if err != nil {
		return nil, fmt.Errorf("cpu.poll: %w", err)
	}

	var elapsed time.Duration
	if !a.prevTime.IsZero() {
		elapsed = now.Sub(a.prevTime)
	}

	records := make([]Record, 0, len(current))
	var dead []Key
	for key, val := range current {
		records = append(records, buildRecord(key, val, a.prev[key], elapsed, a.proc.comm(key.Pid)))
		if !a.proc.alive(key.Pid) {
			dead = append(dead, key)
		}
	}

	a.reap(dead, current)

	a.prev = current
	a.prevTime = now
	return records, nil
}

// reap deletes map entries for exited processes and drops them from the
// snapshot so a recycled PID starts from a clean baseline next poll.
func (a *Aggregator) reap(dead []Key, current map[Key]Value) {
	for _, key := range dead {
		if err := a.cpuMap.Delete(&key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			a.log.Warn("cpu reap failed", "pid", key.Pid, "error", err)
			continue
		}
		delete(current, key)
		a.proc.forget(key.Pid)
	}
}

func (a *Aggregator) readMap() (map[Key]Value, error) {
	ncpu, err := ebpf.PossibleCPU()
	if err != nil {
		return nil, fmt.Errorf("cpu.readMap: possible CPUs: %w", err)
	}
	if a.features.BatchMapOps == feature.Available {
		return a.readMapBatch(ncpu)
	}
	return a.readMapIter(ncpu)
}

func (a *Aggregator) readMapBatch(ncpu int) (map[Key]Value, error) {
	result := make(map[Key]Value, len(a.prev))

	const batchSize = 256
	keys := make([]Key, batchSize)
	// Per-CPU batch lookups return a flat slice with ncpu values per key.
	vals := make([]Value, batchSize*ncpu)
	var cursor ebpf.MapBatchCursor

	for {
		n, err := a.cpuMap.BatchLookup(&cursor, keys, vals, nil)
		for i := 0; i < n; i++ {
			result[keys[i]] = SumCPUs(vals[i*ncpu : (i+1)*ncpu])
		}
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			break
		}
		if err != nil {
			return result, fmt.Errorf("cpu.readMapBatch: %w", err)
		}
	}

	return result, nil
}

func (a *Aggregator) readMapIter(ncpu int) (map[Key]Value, error) {
	result := make(map[Key]Value, len(a.prev))
	var key Key
	vals := make([]Value, ncpu)
	iter := a.cpuMap.Iterate()
	for iter.Next(&key, vals) {
		result[key] = SumCPUs(vals)
	}
	if err := iter.Err(); err != nil {
		return result, fmt.Errorf("cpu.readMapIter: %w", err)
	}
	return result, nil
}
