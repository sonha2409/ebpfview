// flows.c — TC classifier BPF program for network flow tracking.
// Attaches to ingress and egress on a clsact qdisc, tracks 5-tuple
// flows in an LRU hash map with packet/byte counters and TCP flags.

#include "common.h"

// Address family constants — vmlinux.h provides these but in case
// of minimal BTF, define fallbacks.
#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

// Ethernet header length (no VLAN).
#define ETH_HLEN 14

// IP protocol numbers.
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMP 1
#define IPPROTO_ICMPV6 58

// Ethernet type constants (network byte order on little-endian).
#define ETH_P_IP_BE __bpf_constant_htons(0x0800)
#define ETH_P_IPV6_BE __bpf_constant_htons(0x86DD)

// TC_ACT_OK passes the packet through.
#define TC_ACT_OK 0

// --- Shared structures (mirrored in Go) ---

struct flow_key {
	__u8 family;  // AF_INET or AF_INET6
	__u8 proto;   // IPPROTO_TCP, UDP, ICMP, etc.
	__u16 sport;  // source port (network byte order)
	__u16 dport;  // dest port (network byte order)
	__u8 saddr[16]; // source address (IPv4 uses bytes 0-3)
	__u8 daddr[16]; // dest address (IPv4 uses bytes 0-3)
};

struct flow_value {
	__u64 packets;
	__u64 bytes;
	__u64 ts_first_ns; // bpf_ktime_get_ns at first packet
	__u64 ts_last_ns;  // bpf_ktime_get_ns at last packet
	__u32 tcp_flags;   // OR of all observed TCP flags
	__u32 _pad;
};

// --- Maps ---

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct flow_key);
	__type(value, struct flow_value);
	__uint(max_entries, 65536);
} flow_table SEC(".maps");

// --- Packet parsing helpers ---

// Parse TCP/UDP ports from L4 header. Returns 0 on success, -1 if
// the packet is too short.
static __always_inline int
parse_l4(struct __sk_buff *skb, __u32 l4_off, __u8 proto,
	 __u16 *sport, __u16 *dport, __u32 *tcp_flags)
{
	switch (proto) {
	case IPPROTO_TCP: {
		// TCP header: src port (2), dst port (2), seq (4), ack (4), doff+flags (2)
		__u16 src, dst;

		if (bpf_skb_load_bytes(skb, l4_off, &src, 2) < 0)
			return -1;
		if (bpf_skb_load_bytes(skb, l4_off + 2, &dst, 2) < 0)
			return -1;

		// TCP flags are at offset 12 (data offset + flags), read 2 bytes.
		__u16 doff_flags;
		if (bpf_skb_load_bytes(skb, l4_off + 12, &doff_flags, 2) < 0)
			return -1;
		// Flags are the lower 8 bits of the second byte in network order.
		// On little-endian: after load, doff_flags has bytes swapped.
		// Use bpf_ntohs to normalize.
		doff_flags = bpf_ntohs(doff_flags);
		*tcp_flags = doff_flags & 0x3F; // SYN, ACK, FIN, RST, PSH, URG

		*sport = src; // keep network byte order
		*dport = dst;
		return 0;
	}
	case IPPROTO_UDP: {
		__u16 src, dst;
		if (bpf_skb_load_bytes(skb, l4_off, &src, 2) < 0)
			return -1;
		if (bpf_skb_load_bytes(skb, l4_off + 2, &dst, 2) < 0)
			return -1;
		*sport = src;
		*dport = dst;
		*tcp_flags = 0;
		return 0;
	}
	default:
		// ICMP and others: no ports.
		*sport = 0;
		*dport = 0;
		*tcp_flags = 0;
		return 0;
	}
}

// Core packet processing logic shared by ingress and egress.
static __always_inline int process_packet(struct __sk_buff *skb)
{
	struct flow_key key = {};
	__u16 sport = 0, dport = 0;
	__u32 tcp_flags = 0;
	__u32 l4_off;

	// Read ethertype from sk_buff. TC provides L2 headers.
	__u16 h_proto;
	if (bpf_skb_load_bytes(skb, 12, &h_proto, 2) < 0)
		return TC_ACT_OK;

	if (h_proto == ETH_P_IP_BE) {
		// IPv4
		key.family = AF_INET;

		__u8 ihl_ver;
		if (bpf_skb_load_bytes(skb, ETH_HLEN, &ihl_ver, 1) < 0)
			return TC_ACT_OK;
		__u8 ihl = (ihl_ver & 0x0F) * 4;
		if (ihl < 20)
			return TC_ACT_OK;

		// Protocol at offset 9 in IP header.
		if (bpf_skb_load_bytes(skb, ETH_HLEN + 9, &key.proto, 1) < 0)
			return TC_ACT_OK;

		// Source address at offset 12, dest at 16 (4 bytes each).
		if (bpf_skb_load_bytes(skb, ETH_HLEN + 12, key.saddr, 4) < 0)
			return TC_ACT_OK;
		if (bpf_skb_load_bytes(skb, ETH_HLEN + 16, key.daddr, 4) < 0)
			return TC_ACT_OK;

		l4_off = ETH_HLEN + ihl;

	} else if (h_proto == ETH_P_IPV6_BE) {
		// IPv6
		key.family = AF_INET6;

		// Next header at offset 6 in IPv6 header.
		if (bpf_skb_load_bytes(skb, ETH_HLEN + 6, &key.proto, 1) < 0)
			return TC_ACT_OK;

		// Source address at offset 8 (16 bytes), dest at 24 (16 bytes).
		if (bpf_skb_load_bytes(skb, ETH_HLEN + 8, key.saddr, 16) < 0)
			return TC_ACT_OK;
		if (bpf_skb_load_bytes(skb, ETH_HLEN + 24, key.daddr, 16) < 0)
			return TC_ACT_OK;

		// Fixed IPv6 header is 40 bytes.
		l4_off = ETH_HLEN + 40;

	} else {
		// Not IP — skip.
		return TC_ACT_OK;
	}

	// Parse L4 ports and flags.
	if (parse_l4(skb, l4_off, key.proto, &sport, &dport, &tcp_flags) < 0)
		return TC_ACT_OK;

	key.sport = sport;
	key.dport = dport;

	// Update or insert flow entry.
	__u64 now = bpf_ktime_get_ns();
	__u64 pkt_len = skb->len;

	struct flow_value *val = bpf_map_lookup_elem(&flow_table, &key);
	if (val) {
		__sync_fetch_and_add(&val->packets, 1);
		__sync_fetch_and_add(&val->bytes, pkt_len);
		val->ts_last_ns = now;
		val->tcp_flags |= tcp_flags;
	} else {
		struct flow_value new_val = {
			.packets = 1,
			.bytes = pkt_len,
			.ts_first_ns = now,
			.ts_last_ns = now,
			.tcp_flags = tcp_flags,
		};
		bpf_map_update_elem(&flow_table, &key, &new_val, BPF_NOEXIST);
	}

	return TC_ACT_OK;
}

SEC("classifier/ingress")
int flows_ingress(struct __sk_buff *skb)
{
	return process_packet(skb);
}

SEC("classifier/egress")
int flows_egress(struct __sk_buff *skb)
{
	return process_packet(skb);
}

LICENSE_DEF;
