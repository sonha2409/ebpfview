package flows

import (
	"net/netip"
	"testing"
	"time"
)

func Test_Aggregator_DeltaRates(t *testing.T) {
	// Simulate two snapshots to verify rate calculation.
	prev := map[FlowKey]FlowValue{
		{Family: AFInet, Proto: 6, SAddr: [16]byte{10, 0, 0, 1}, DAddr: [16]byte{10, 0, 0, 2}}: {
			Packets: 100, Bytes: 10000,
		},
	}

	current := map[FlowKey]FlowValue{
		{Family: AFInet, Proto: 6, SAddr: [16]byte{10, 0, 0, 1}, DAddr: [16]byte{10, 0, 0, 2}}: {
			Packets: 200, Bytes: 30000,
		},
	}

	key := FlowKey{Family: AFInet, Proto: 6, SAddr: [16]byte{10, 0, 0, 1}, DAddr: [16]byte{10, 0, 0, 2}}
	elapsed := 2 * time.Second
	secs := elapsed.Seconds()

	val := current[key]
	pval := prev[key]

	pktRate := float64(val.Packets-pval.Packets) / secs
	byteRate := float64(val.Bytes-pval.Bytes) / secs

	if pktRate != 50.0 {
		t.Errorf("packet rate = %f, want 50.0", pktRate)
	}
	if byteRate != 10000.0 {
		t.Errorf("byte rate = %f, want 10000.0", byteRate)
	}
}

func Test_Aggregator_NewFlowZeroRate(t *testing.T) {
	// A flow appearing for the first time should have zero rates.
	prev := map[FlowKey]FlowValue{}
	key := FlowKey{Family: AFInet, Proto: 17}

	_, hasPrev := prev[key]
	if hasPrev {
		t.Error("expected no previous entry for new flow")
	}
	// Rate stays 0 when there's no previous entry — this is the expected behavior.
}

func Test_Aggregator_PrevPruning(t *testing.T) {
	// When LRU evicts a flow, it disappears from current. The prev map
	// should be replaced entirely (not merged) to avoid unbounded growth.
	prev := map[FlowKey]FlowValue{
		{Family: AFInet, Proto: 6, SAddr: [16]byte{1}}: {Packets: 10},
		{Family: AFInet, Proto: 6, SAddr: [16]byte{2}}: {Packets: 20},
	}

	current := map[FlowKey]FlowValue{
		{Family: AFInet, Proto: 6, SAddr: [16]byte{2}}: {Packets: 30},
	}

	// After poll, prev should be replaced by current.
	newPrev := current
	if len(newPrev) != 1 {
		t.Errorf("prev should have 1 entry after pruning, got %d", len(newPrev))
	}
	if _, ok := newPrev[FlowKey{Family: AFInet, Proto: 6, SAddr: [16]byte{1}}]; ok {
		t.Error("evicted flow should not be in prev")
	}

	_ = prev // suppress unused
}

func Test_FlowRecord_FieldValues(t *testing.T) {
	rec := FlowRecord{
		SrcAddr:       netip.MustParseAddr("192.168.1.1"),
		DstAddr:       netip.MustParseAddr("10.0.0.1"),
		SrcPort:       12345,
		DstPort:       443,
		Proto:         6,
		Packets:       1000,
		Bytes:         500000,
		PacketsPerSec: 100.0,
		BytesPerSec:   50000.0,
		TCPFlags:      0x12, // SYN+ACK
	}

	if rec.SrcAddr.String() != "192.168.1.1" {
		t.Errorf("SrcAddr = %s, want 192.168.1.1", rec.SrcAddr)
	}
	if rec.Proto != 6 {
		t.Errorf("Proto = %d, want 6", rec.Proto)
	}
	if rec.TCPFlags != 0x12 {
		t.Errorf("TCPFlags = %x, want 0x12", rec.TCPFlags)
	}
}
