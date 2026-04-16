package syscalls

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/cilium/ebpf"
	"github.com/sonhathai/ebpfview/internal/feature"
)

// Aggregator periodically reads the BPF syscall_lat map, computes per-
// interval deltas against the previous snapshot, and emits []Record
// batches on its output channel.
type Aggregator struct {
	latMap   *ebpf.Map
	interval time.Duration
	prev     map[Key]Value
	prevTime time.Time
	features *feature.Features
	log      *slog.Logger
}

// NewAggregator creates an Aggregator that polls latMap at the given interval.
func NewAggregator(latMap *ebpf.Map, features *feature.Features, interval time.Duration, logger *slog.Logger) *Aggregator {
	return &Aggregator{
		latMap:   latMap,
		interval: interval,
		prev:     make(map[Key]Value),
		features: features,
		log:      logger,
	}
}

// Run polls the syscall_lat map on each tick and sends Records to out.
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
				a.log.Warn("syscall poll failed", "error", err)
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
		return nil, fmt.Errorf("syscalls.poll: %w", err)
	}

	var elapsed time.Duration
	if !a.prevTime.IsZero() {
		elapsed = now.Sub(a.prevTime)
	}

	records := make([]Record, 0, len(current))
	for key, val := range current {
		rec := buildRecord(key, val, a.prev[key], elapsed)
		records = append(records, rec)
	}

	a.prev = current
	a.prevTime = now
	return records, nil
}

// buildRecord is the pure function version of the per-key aggregation
// step. Extracted so tests can exercise it without a BPF map.
func buildRecord(key Key, cur, prev Value, elapsed time.Duration) Record {
	total := cur.Total()

	// For percentiles, prefer the per-interval delta so we surface
	// recent activity. Fall back to cumulative when no prev is known
	// (first tick, or the entry just appeared).
	hist := cur.Buckets
	var delta uint64
	if elapsed > 0 {
		d := SubBuckets(cur.Buckets, prev.Buckets)
		for _, c := range d {
			delta += c
		}
		if delta > 0 {
			hist = d
		}
	}

	rec := Record{
		Pid:          key.Pid,
		Nr:           key.Nr,
		Name:         SyscallName(key.Nr),
		Count:        total,
		DeltaCount:   delta,
		LastInterval: elapsed,
		P50Ns:        Percentile(hist, 0.5),
		P90Ns:        Percentile(hist, 0.9),
		P99Ns:        Percentile(hist, 0.99),
		MinNs:        minNsFromBuckets(hist),
		MaxNs:        maxNsFromBuckets(hist),
	}

	if elapsed > 0 {
		rec.CountPerSec = float64(delta) / elapsed.Seconds()
	}

	return rec
}

func minNsFromBuckets(b [HistBuckets]uint64) uint64 {
	for i := 0; i < HistBuckets; i++ {
		if b[i] > 0 {
			return BucketLowerNs(i)
		}
	}
	return 0
}

func maxNsFromBuckets(b [HistBuckets]uint64) uint64 {
	for i := HistBuckets - 1; i >= 0; i-- {
		if b[i] > 0 {
			if i == HistBuckets-1 {
				return BucketLowerNs(i)
			}
			return BucketUpperNs(i)
		}
	}
	return 0
}

func (a *Aggregator) readMap() (map[Key]Value, error) {
	if a.features.BatchMapOps == feature.Available {
		return a.readMapBatch()
	}
	return a.readMapIter()
}

func (a *Aggregator) readMapBatch() (map[Key]Value, error) {
	result := make(map[Key]Value, len(a.prev))

	const batchSize = 256
	keys := make([]Key, batchSize)
	vals := make([]Value, batchSize)
	var cursor ebpf.MapBatchCursor

	for {
		n, err := a.latMap.BatchLookup(&cursor, keys, vals, nil)
		for i := 0; i < n; i++ {
			result[keys[i]] = vals[i]
		}
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			break
		}
		if err != nil {
			return result, fmt.Errorf("syscalls.readMapBatch: %w", err)
		}
	}

	return result, nil
}

func (a *Aggregator) readMapIter() (map[Key]Value, error) {
	result := make(map[Key]Value, len(a.prev))
	var key Key
	var val Value
	iter := a.latMap.Iterate()
	for iter.Next(&key, &val) {
		result[key] = val
	}
	if err := iter.Err(); err != nil {
		return result, fmt.Errorf("syscalls.readMapIter: %w", err)
	}
	return result, nil
}
