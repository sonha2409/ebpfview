package loader

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
)

// perfBufReader wraps cilium/ebpf's perf.Reader into our EventReader interface.
type perfBufReader struct {
	reader *perf.Reader
	stats  ReaderStats
}

func newPerfBufReader(m *ebpf.Map, opts *ReaderOpts) (*perfBufReader, error) {
	bufSize := opts.perCPUBufferOrDefault()

	r, err := perf.NewReader(m, bufSize)
	if err != nil {
		return nil, fmt.Errorf("loader.newPerfBufReader: %w", err)
	}
	return &perfBufReader{reader: r}, nil
}

// Read blocks until at least one record is available, then returns a batch
// of up to maxBatchSize records. Lost samples are tracked in stats.
func (r *perfBufReader) Read() ([]RawEvent, error) {
	var rec perf.Record

	// Block on the first record.
	if err := r.reader.ReadInto(&rec); err != nil {
		if errors.Is(err, perf.ErrClosed) {
			return nil, err
		}
		return nil, fmt.Errorf("loader.perfBufReader.Read: %w", err)
	}

	batch := make([]RawEvent, 0, maxBatchSize)

	if rec.LostSamples > 0 {
		r.stats.EventsLost.Add(rec.LostSamples)
	} else {
		batch = append(batch, RawEvent{Data: rec.RawSample, CPU: rec.CPU})
		r.stats.EventsRead.Add(1)
		r.stats.BytesRead.Add(uint64(len(rec.RawSample)))
	}

	// Drain additional available records without blocking.
	for len(batch) < maxBatchSize {
		if err := r.reader.ReadInto(&rec); err != nil {
			break
		}
		if rec.LostSamples > 0 {
			r.stats.EventsLost.Add(rec.LostSamples)
			continue
		}
		batch = append(batch, RawEvent{Data: rec.RawSample, CPU: rec.CPU})
		r.stats.EventsRead.Add(1)
		r.stats.BytesRead.Add(uint64(len(rec.RawSample)))
	}

	return batch, nil
}

func (r *perfBufReader) Stats() ReaderStatsSnapshot {
	return r.stats.Snapshot()
}

func (r *perfBufReader) Close() error {
	return r.reader.Close()
}
