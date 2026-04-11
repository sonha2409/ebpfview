// hello.c — minimal kprobe that proves bpf2go + cilium/ebpf pipeline works.
// Attaches to do_sys_openat2 and counts invocations in a BPF array map.

#include "common.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} event_count SEC(".maps");

SEC("kprobe/do_sys_openat2")
int kprobe_do_sys_openat2(struct pt_regs *ctx)
{
	__u32 key = 0;
	__u64 *count;

	count = bpf_map_lookup_elem(&event_count, &key);
	if (count)
		__sync_fetch_and_add(count, 1);

	return 0;
}

LICENSE_DEF;
