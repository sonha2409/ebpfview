// syscall_lat.c — raw tracepoint syscall latency histograms.
//
// Attaches to raw_tracepoint/sys_enter and raw_tracepoint/sys_exit.
// sys_enter stashes a timestamp + syscall number keyed by pid_tgid.
// sys_exit joins against that entry, computes delta_ns, and increments
// a log2 histogram bucket keyed by (tgid, syscall_nr).
//
// Userspace reads the syscall_lat map on interval to compute percentiles.

#include "common.h"

// Safety bound — Linux has ~450 syscalls today; reject anything higher
// to avoid wild values from corrupted registers.
#define MAX_SYSCALL_NR 512

// Number of log2 buckets. bucket i covers [2^i, 2^(i+1)) nanoseconds.
// 64 covers up to ~584 years, more than enough for any single syscall.
#define HIST_BUCKETS 64

// --- Shared structures (mirrored in Go) ---

struct syscall_key {
	__u32 pid;  // tgid (thread group id, i.e. userspace "pid")
	__u32 nr;   // syscall number
};

struct syscall_lat_val {
	__u64 buckets[HIST_BUCKETS];
};

struct syscall_start_val {
	__u64 ts_ns;
	__u32 nr;
	__u32 _pad;
};

// --- Maps ---

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct syscall_key);
	__type(value, struct syscall_lat_val);
	__uint(max_entries, 65536);
} syscall_lat SEC(".maps");

// Per-thread scratch: records the start timestamp of the in-flight syscall.
// Keyed by full pid_tgid so distinct threads of the same process don't collide.
// LRU keeps this bounded if sys_exit is missed (e.g. thread dies mid-syscall).
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u64);
	__type(value, struct syscall_start_val);
	__uint(max_entries, 10240);
} syscall_start SEC(".maps");

// Zero-initialized per-cpu template used to insert new syscall_lat entries
// without burning 512 bytes of BPF stack on a local zero-struct.
// The entry is never written to; it stays all-zeros for the program's lifetime.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct syscall_lat_val);
	__uint(max_entries, 1);
} syscall_lat_zero SEC(".maps");

// --- Helpers ---

// Integer log2 of a u64. Standard branchless 6-step reduction.
// Returns 0 for v == 0 (caller must guard) and 63 for the top bit.
static __always_inline __u32 log2_u64(__u64 v)
{
	__u32 r, shift;

	r     = (v > 0xFFFFFFFFULL) << 5; v >>= r;
	shift = (v > 0xFFFFULL)     << 4; v >>= shift; r |= shift;
	shift = (v > 0xFFULL)       << 3; v >>= shift; r |= shift;
	shift = (v > 0xFULL)        << 2; v >>= shift; r |= shift;
	shift = (v > 0x3ULL)        << 1; v >>= shift; r |= shift;
	r    |= (__u32)(v >> 1);
	return r;
}

// --- Programs ---

// raw_tracepoint/sys_enter: ctx->args = (struct pt_regs *regs, long id).
SEC("raw_tracepoint/sys_enter")
int raw_tp_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
	long id = (long)ctx->args[1];
	if (id < 0 || id >= MAX_SYSCALL_NR)
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct syscall_start_val v = {
		.ts_ns = bpf_ktime_get_ns(),
		.nr = (__u32)id,
	};
	bpf_map_update_elem(&syscall_start, &pid_tgid, &v, BPF_ANY);
	return 0;
}

// raw_tracepoint/sys_exit: ctx->args = (struct pt_regs *regs, long ret).
SEC("raw_tracepoint/sys_exit")
int raw_tp_sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct syscall_start_val *start = bpf_map_lookup_elem(&syscall_start, &pid_tgid);
	if (!start)
		return 0;

	__u64 now = bpf_ktime_get_ns();
	__u64 delta = now - start->ts_ns;
	__u32 nr = start->nr;

	// Scratch entry consumed — delete so stale starts don't linger.
	bpf_map_delete_elem(&syscall_start, &pid_tgid);

	if ((__s64)delta <= 0)
		return 0;

	__u32 bucket = log2_u64(delta);
	if (bucket >= HIST_BUCKETS)
		bucket = HIST_BUCKETS - 1;

	struct syscall_key key = {
		.pid = (__u32)(pid_tgid >> 32),
		.nr = nr,
	};

	struct syscall_lat_val *val = bpf_map_lookup_elem(&syscall_lat, &key);
	if (!val) {
		// Seed the entry with an all-zero template from the per-cpu map.
		// Avoids a 512-byte stack variable (exceeds BPF stack limit).
		__u32 zero_idx = 0;
		struct syscall_lat_val *zero = bpf_map_lookup_elem(&syscall_lat_zero, &zero_idx);
		if (!zero)
			return 0;
		bpf_map_update_elem(&syscall_lat, &key, zero, BPF_NOEXIST);
		val = bpf_map_lookup_elem(&syscall_lat, &key);
		if (!val)
			return 0;
	}
	__sync_fetch_and_add(&val->buckets[bucket], 1);
	return 0;
}

LICENSE_DEF;
