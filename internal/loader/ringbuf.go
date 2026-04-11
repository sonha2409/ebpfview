package loader

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

const maxBatchSize = 64

// ringBufReader wraps cilium/ebpf's ringbuf.Reader into our EventReader interface.
type ringBufReader struct {
	reader *ringbuf.Reader
	stats  ReaderStats
}

func newRingBufReader(m *ebpf.Map) (*ringBufReader, error) {
	r, err := ringbuf.NewReader(m)
	if err != nil {
		return nil, fmt.Errorf("loader.newRingBufReader: %w", err)
	}
	return &ringBufReader{reader: r}, nil
}

// Read blocks until at least one record is available, then returns a batch
// of up to maxBatchSize records.
func (r *ringBufReader) Read() ([]RawEvent, error) {
	var rec ringbuf.Record

	// Block on the first record.
	if err := r.reader.ReadInto(&rec); err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return nil, err
		}
		return nil, fmt.Errorf("loader.ringBufReader.Read: %w", err)
	}

	batch := make([]RawEvent, 0, maxBatchSize)
	batch = append(batch, RawEvent{Data: rec.RawSample})
	r.stats.EventsRead.Add(1)
	r.stats.BytesRead.Add(uint64(len(rec.RawSample)))

	// Drain any additional available records without blocking.
	for len(batch) < maxBatchSize {
		if r.reader.AvailableBytes() == 0 {
			break
		}
		if err := r.reader.ReadInto(&rec); err != nil {
			break
		}
		batch = append(batch, RawEvent{Data: rec.RawSample})
		r.stats.EventsRead.Add(1)
		r.stats.BytesRead.Add(uint64(len(rec.RawSample)))
	}

	return batch, nil
}

func (r *ringBufReader) Stats() ReaderStatsSnapshot {
	return r.stats.Snapshot()
}

func (r *ringBufReader) Close() error {
	return r.reader.Close()
}
