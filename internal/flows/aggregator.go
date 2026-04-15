package flows

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/cilium/ebpf"
	"github.com/sonhathai/ebpfview/internal/feature"
)

// Aggregator periodically reads the BPF flow_table map, computes
// per-second rates by diffing against the previous snapshot, and
// emits []FlowRecord batches on its output channel.
type Aggregator struct {
	flowMap  *ebpf.Map
	interval time.Duration
	prev     map[FlowKey]FlowValue
	prevTime time.Time
	features *feature.Features
	log      *slog.Logger
}

// NewAggregator creates an Aggregator that polls flowMap at the given interval.
func NewAggregator(flowMap *ebpf.Map, features *feature.Features, interval time.Duration, logger *slog.Logger) *Aggregator {
	return &Aggregator{
		flowMap:  flowMap,
		interval: interval,
		prev:     make(map[FlowKey]FlowValue),
		features: features,
		log:      logger,
	}
}

// Run polls the flow map on each tick and sends flow records to out.
// It blocks until ctx is cancelled. The output channel is NOT closed
// by Run — the caller owns the channel lifecycle.
func (a *Aggregator) Run(ctx context.Context, out chan<- []FlowRecord) error {
	ticker := time.NewTicker(a.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			records, err := a.poll()
			if err != nil {
				a.log.Warn("flow poll failed", "error", err)
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

// poll reads the entire flow_table, computes deltas vs. previous
// snapshot, and returns enriched FlowRecords.
func (a *Aggregator) poll() ([]FlowRecord, error) {
	now := time.Now()
	current, err := a.readMap()
	if err != nil {
		return nil, fmt.Errorf("flows.poll: %w", err)
	}

	var elapsed time.Duration
	if !a.prevTime.IsZero() {
		elapsed = now.Sub(a.prevTime)
	}

	records := make([]FlowRecord, 0, len(current))
	for key, val := range current {
		rec := FlowRecord{
			SrcAddr:   key.SrcAddr(),
			DstAddr:   key.DstAddr(),
			SrcPort:   key.SrcPort(),
			DstPort:   key.DstPort(),
			Proto:     key.Proto,
			Packets:   val.Packets,
			Bytes:     val.Bytes,
			TCPFlags:  val.TCPFlags,
		}

		// Compute rates from delta if we have a previous snapshot.
		if elapsed > 0 {
			if prev, ok := a.prev[key]; ok {
				secs := elapsed.Seconds()
				dPkts := val.Packets - prev.Packets
				dBytes := val.Bytes - prev.Bytes
				rec.PacketsPerSec = float64(dPkts) / secs
				rec.BytesPerSec = float64(dBytes) / secs
			}
			// No prev entry means this flow is new — rates stay 0 for
			// the first interval.
		}

		records = append(records, rec)
	}

	// Replace previous snapshot. Only keep keys that exist in current
	// to prevent unbounded growth from LRU evictions.
	a.prev = current
	a.prevTime = now

	return records, nil
}

// readMap reads all entries from the BPF flow_table. Uses batch
// operations when available, falling back to per-key iteration.
func (a *Aggregator) readMap() (map[FlowKey]FlowValue, error) {
	if a.features.BatchMapOps == feature.Available {
		return a.readMapBatch()
	}
	return a.readMapIter()
}

// readMapBatch uses BatchLookup to read flows in bulk.
func (a *Aggregator) readMapBatch() (map[FlowKey]FlowValue, error) {
	result := make(map[FlowKey]FlowValue, len(a.prev))

	const batchSize = 256
	keys := make([]FlowKey, batchSize)
	vals := make([]FlowValue, batchSize)
	var cursor ebpf.MapBatchCursor

	for {
		n, err := a.flowMap.BatchLookup(&cursor, keys, vals, nil)
		for i := 0; i < n; i++ {
			result[keys[i]] = vals[i]
		}
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			// End of map.
			break
		}
		if err != nil {
			return result, fmt.Errorf("flows.readMapBatch: %w", err)
		}
	}

	return result, nil
}

// readMapIter uses per-key iteration as a fallback.
func (a *Aggregator) readMapIter() (map[FlowKey]FlowValue, error) {
	result := make(map[FlowKey]FlowValue, len(a.prev))

	var key FlowKey
	var val FlowValue
	iter := a.flowMap.Iterate()
	for iter.Next(&key, &val) {
		result[key] = val
	}
	if err := iter.Err(); err != nil {
		return result, fmt.Errorf("flows.readMapIter: %w", err)
	}

	return result, nil
}
