// Package flows implements network flow tracking using TC classifier BPF
// programs. It manages attachment, aggregation, and rate calculation for
// 5-tuple flow entries stored in a BPF LRU hash map.
package flows

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"time"
	"unsafe"
)

// Address family constants matching kernel AF_INET/AF_INET6.
const (
	AFInet  = 2
	AFInet6 = 10
)

// FlowKey mirrors the BPF struct flow_key. It is a 5-tuple flow identifier
// with support for both IPv4 and IPv6.
//
// The struct layout must match bpf/c/flows.c exactly.
type FlowKey struct {
	Family uint8     // AF_INET or AF_INET6
	Proto  uint8     // IPPROTO_TCP, UDP, ICMP, etc.
	SPort  uint16    // source port (network byte order)
	DPort  uint16    // dest port (network byte order)
	SAddr  [16]byte  // source address
	DAddr  [16]byte  // dest address
}

// FlowValue mirrors the BPF struct flow_value. Counters are updated
// atomically by the BPF program.
type FlowValue struct {
	Packets   uint64
	Bytes     uint64
	TSFirstNs uint64
	TSLastNs  uint64
	TCPFlags  uint32
	_         uint32 // pad to match C struct
}

// RTTSample mirrors the BPF struct rtt_sample written by the
// fentry/tcp_rcv_established probe. srtt_us and mdev_us are already
// shifted to real microsecond values in the BPF program.
type RTTSample struct {
	SRTTUs   uint32
	MDevUs   uint32
	TSLastNs uint64
	Samples  uint64
}

// FlowRecord is the enriched, human-friendly representation of a flow
// with computed rate fields. Produced by the Aggregator.
type FlowRecord struct {
	SrcAddr       netip.Addr
	DstAddr       netip.Addr
	SrcPort       uint16
	DstPort       uint16
	Proto         uint8
	Packets       uint64
	Bytes         uint64
	PacketsPerSec float64
	BytesPerSec   float64
	FirstSeen     time.Time
	LastSeen      time.Time
	TCPFlags      uint32
	// RTT fields — zero if no sample available (non-TCP, or fentry probe
	// unavailable). SRTT is the kernel's smoothed RTT estimate.
	SRTTUs uint32
	MDevUs uint32
}

// FlowKeySize is the exact byte size of FlowKey as seen by BPF.
const FlowKeySize = int(unsafe.Sizeof(FlowKey{}))

// FlowValueSize is the exact byte size of FlowValue as seen by BPF.
const FlowValueSize = int(unsafe.Sizeof(FlowValue{}))

// SrcAddr returns the source address from the flow key as a netip.Addr.
func (k *FlowKey) SrcAddr() netip.Addr {
	return addrFromBytes(k.Family, k.SAddr)
}

// DstAddr returns the destination address from the flow key as a netip.Addr.
func (k *FlowKey) DstAddr() netip.Addr {
	return addrFromBytes(k.Family, k.DAddr)
}

// SrcPort returns the source port in host byte order.
func (k *FlowKey) SrcPort() uint16 {
	return ntohs(k.SPort)
}

// DstPort returns the destination port in host byte order.
func (k *FlowKey) DstPort() uint16 {
	return ntohs(k.DPort)
}

// ProtoName returns a human-readable protocol name.
func ProtoName(proto uint8) string {
	switch proto {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 1:
		return "ICMP"
	case 58:
		return "ICMPv6"
	default:
		return fmt.Sprintf("%d", proto)
	}
}

// FormatRTT renders a microsecond RTT as a human-readable string. Returns
// "-" when the sample is zero (no RTT data available).
func FormatRTT(srttUs uint32) string {
	if srttUs == 0 {
		return "-"
	}
	if srttUs < 1000 {
		return fmt.Sprintf("%dµs", srttUs)
	}
	return fmt.Sprintf("%.2fms", float64(srttUs)/1000.0)
}

// FormatBytes formats a byte count as a human-readable string with units.
func FormatBytes(b float64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", b/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", b/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KB", b/(1<<10))
	default:
		return fmt.Sprintf("%.0f B", b)
	}
}

func addrFromBytes(family uint8, raw [16]byte) netip.Addr {
	switch family {
	case AFInet:
		return netip.AddrFrom4([4]byte(raw[:4]))
	case AFInet6:
		return netip.AddrFrom16(raw)
	default:
		return netip.Addr{}
	}
}

func ntohs(v uint16) uint16 {
	b := [2]byte{}
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}

// FormatAddr formats an address with port for display. IPv6 addresses
// are wrapped in brackets.
func FormatAddr(addr netip.Addr, port uint16) string {
	if !addr.IsValid() {
		return "?"
	}
	ap := netip.AddrPortFrom(addr, port)
	if addr.Is4() {
		return fmt.Sprintf("%s:%d", addr, port)
	}
	_ = ap // suppress unused — using manual format for consistency
	return net.JoinHostPort(addr.String(), fmt.Sprintf("%d", port))
}
