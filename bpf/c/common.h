#ifndef __EBPFVIEW_COMMON_H
#define __EBPFVIEW_COMMON_H

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define LICENSE_DEF char LICENSE[] SEC("license") = "Dual MIT/GPL"

#endif /* __EBPFVIEW_COMMON_H */
