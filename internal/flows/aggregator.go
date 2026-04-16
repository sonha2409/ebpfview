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
//
// If rttMap is non-nil, each flow record is joined with the matching
// RTT sample (checking both forward and reverse 5-tuples since the
// fentry probe keys on the socket's local→peer orientation).
type Aggregator struct {
	flowMap  *ebpf.Map
	rttMap   *ebpf.Map
	interval time.Duration
	prev     map[FlowKey]FlowValue
	prevTime time.Time
	features *feature.Features
	log      *slog.Logger
}

// NewAggregator creates an Aggregator that polls flowMap at the given interval.
// rttMap may be nil — when provided, RTT samples are joined into each record.
func NewAggregator(flowMap, rttMap *ebpf.Map, features *feature.Features, interval time.Duration, logger *slog.Logger) *Aggregator {
	return &Aggregator{
		flowMap:  flowMap,
		rttMap:   rttMap,
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

	rtt, err := a.readRTTMap()
	if err != nil {
		// RTT is best-effort — log and continue without it.
		a.log.Debug("rtt map read failed", "error", err)
		rtt = nil
	}

	var elapsed time.Duration
	if !a.prevTime.IsZero() {
		elapsed = now.Sub(a.prevTime)
	}

	records := make([]FlowRecord, 0, len(current))
	for key, val := range current {
		rec := FlowRecord{
			SrcAddr:  key.SrcAddr(),
			DstAddr:  key.DstAddr(),
			SrcPort:  key.SrcPort(),
			DstPort:  key.DstPort(),
			Proto:    key.Proto,
			Packets:  val.Packets,
			Bytes:    val.Bytes,
			TCPFlags: val.TCPFlags,
		}

		// Join RTT — the fentry probe stores under the socket's local→peer
		// orientation, which may match either direction of the TC-observed
		// flow. Try forward first, then swap.
		if rtt != nil && key.Proto == 6 {
			if sample, ok := rtt[key]; ok {
				rec.SRTTUs = sample.SRTTUs
				rec.MDevUs = sample.MDevUs
			} else {
				reverse := FlowKey{
					Family: key.Family,
					Proto:  key.Proto,
					SPort:  key.DPort,
					DPort:  key.SPort,
					SAddr:  key.DAddr,
					DAddr:  key.SAddr,
				}
				if sample, ok := rtt[reverse]; ok {
					rec.SRTTUs = sample.SRTTUs
					rec.MDevUs = sample.MDevUs
				}
			}
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

// readRTTMap reads all entries from the rtt_samples map. Returns nil
// when no map is configured. Iteration is sufficient here since the
// map is expected to be small relative to the flow table.
func (a *Aggregator) readRTTMap() (map[FlowKey]RTTSample, error) {
	if a.rttMap == nil {
		return nil, nil
	}
	result := make(map[FlowKey]RTTSample)
	var key FlowKey
	var val RTTSample
	iter := a.rttMap.Iterate()
	for iter.Next(&key, &val) {
		result[key] = val
	}
	if err := iter.Err(); err != nil {
		return result, fmt.Errorf("flows.readRTTMap: %w", err)
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
