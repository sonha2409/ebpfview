// cpu_sample.c — perf event CPU sampling + context switch counting.
//
// Two programs:
//   1. perf_event/cpu_sample: attached to PERF_COUNT_SW_CPU_CLOCK at 99Hz
//      on every CPU. Each sample increments user_ns or kern_ns in a
//      PERCPU_HASH keyed by tgid, using the sample_period as the time
//      quantum. User/kernel is discriminated by checking bit 63 of the
//      interrupted IP (works on x86_64 and arm64).
//
//   2. tp_btf/sched_switch: increments ctx_switches for the prev task's
//      tgid. Only updates existing entries (created by the sampling path)
//      so idle kernel threads don't pollute the map.
//
// Userspace reads cpu_time on interval to compute per-process CPU %.

#include "common.h"

// --- Shared structures (mirrored in Go) ---

struct cpu_key {
	__u32 pid; // tgid (thread group id)
};

struct cpu_val {
	__u64 user_ns;
	__u64 kern_ns;
	__u64 ctx_switches;
};

// --- Maps ---

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__type(key, struct cpu_key);
	__type(value, struct cpu_val);
	__uint(max_entries, 65536);
} cpu_time SEC(".maps");

// Zero-initialized per-cpu template for inserting new entries without
// a stack variable (keeps BPF stack usage minimal).
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct cpu_val);
	__uint(max_entries, 1);
} cpu_time_zero SEC(".maps");

// --- Programs ---

SEC("perf_event")
int cpu_sample(struct bpf_perf_event_data *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;
	if (tgid == 0)
		return 0;

	struct cpu_key key = { .pid = tgid };
	struct cpu_val *val = bpf_map_lookup_elem(&cpu_time, &key);
	if (!val) {
		__u32 zero_idx = 0;
		struct cpu_val *z = bpf_map_lookup_elem(&cpu_time_zero, &zero_idx);
		if (!z)
			return 0;
		bpf_map_update_elem(&cpu_time, &key, z, BPF_NOEXIST);
		val = bpf_map_lookup_elem(&cpu_time, &key);
		if (!val)
			return 0;
	}

	// Discriminate user vs kernel by checking bit 63 of the interrupted IP.
	// On x86_64 and arm64, kernel addresses have the high bit set.
	__u64 ip = 0;
	bpf_probe_read_kernel(&ip, sizeof(ip), &ctx->regs.ip);
	if (ip >> 63)
		__sync_fetch_and_add(&val->kern_ns, ctx->sample_period);
	else
		__sync_fetch_and_add(&val->user_ns, ctx->sample_period);

	return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch_count,
	bool preempt,
	struct task_struct *prev,
	struct task_struct *next)
{
	__u32 prev_tgid = BPF_CORE_READ(prev, tgid);
	if (prev_tgid == 0)
		return 0;

	struct cpu_key key = { .pid = prev_tgid };
	struct cpu_val *val = bpf_map_lookup_elem(&cpu_time, &key);
	if (val)
		__sync_fetch_and_add(&val->ctx_switches, 1);
	return 0;
}

LICENSE_DEF;
