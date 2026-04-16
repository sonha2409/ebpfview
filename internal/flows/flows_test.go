package flows

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func Test_FlowKey_SrcAddr_IPv4(t *testing.T) {
	key := FlowKey{
		Family: AFInet,
		SAddr:  [16]byte{10, 0, 0, 1},
	}
	got := key.SrcAddr()
	want := netip.AddrFrom4([4]byte{10, 0, 0, 1})
	if got != want {
		t.Errorf("SrcAddr() = %v, want %v", got, want)
	}
}

func Test_FlowKey_DstAddr_IPv6(t *testing.T) {
	key := FlowKey{
		Family: AFInet6,
		DAddr:  [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
	}
	got := key.DstAddr()
	want := netip.MustParseAddr("2001:db8::1")
	if got != want {
		t.Errorf("DstAddr() = %v, want %v", got, want)
	}
}

func Test_FlowKey_Ports_NetworkByteOrder(t *testing.T) {
	// Port 80 in network byte order (big-endian) = 0x0050
	var portBE [2]byte
	binary.BigEndian.PutUint16(portBE[:], 80)
	port := binary.NativeEndian.Uint16(portBE[:])

	key := FlowKey{
		SPort: port,
		DPort: port,
	}
	if key.SrcPort() != 80 {
		t.Errorf("SrcPort() = %d, want 80", key.SrcPort())
	}
	if key.DstPort() != 80 {
		t.Errorf("DstPort() = %d, want 80", key.DstPort())
	}
}

func Test_ProtoName(t *testing.T) {
	tests := []struct {
		proto uint8
		want  string
	}{
		{6, "TCP"},
		{17, "UDP"},
		{1, "ICMP"},
		{58, "ICMPv6"},
		{47, "47"},
	}
	for _, tt := range tests {
		got := ProtoName(tt.proto)
		if got != tt.want {
			t.Errorf("ProtoName(%d) = %q, want %q", tt.proto, got, tt.want)
		}
	}
}

func Test_FormatBytes(t *testing.T) {
	tests := []struct {
		bytes float64
		want  string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1048576, "1.0 MB"},
		{1073741824, "1.0 GB"},
	}
	for _, tt := range tests {
		got := FormatBytes(tt.bytes)
		if got != tt.want {
			t.Errorf("FormatBytes(%v) = %q, want %q", tt.bytes, got, tt.want)
		}
	}
}

func Test_FormatAddr_IPv4(t *testing.T) {
	addr := netip.MustParseAddr("10.0.0.1")
	got := FormatAddr(addr, 8080)
	want := "10.0.0.1:8080"
	if got != want {
		t.Errorf("FormatAddr() = %q, want %q", got, want)
	}
}

func Test_FormatAddr_IPv6(t *testing.T) {
	addr := netip.MustParseAddr("2001:db8::1")
	got := FormatAddr(addr, 443)
	want := "[2001:db8::1]:443"
	if got != want {
		t.Errorf("FormatAddr() = %q, want %q", got, want)
	}
}

func Test_FormatRTT(t *testing.T) {
	tests := []struct {
		us   uint32
		want string
	}{
		{0, "-"},
		{42, "42µs"},
		{999, "999µs"},
		{1000, "1.00ms"},
		{12345, "12.35ms"},
	}
	for _, tt := range tests {
		got := FormatRTT(tt.us)
		if got != tt.want {
			t.Errorf("FormatRTT(%d) = %q, want %q", tt.us, got, tt.want)
		}
	}
}

func Test_FormatAddr_Invalid(t *testing.T) {
	got := FormatAddr(netip.Addr{}, 0)
	if got != "?" {
		t.Errorf("FormatAddr(invalid) = %q, want %q", got, "?")
	}
}
