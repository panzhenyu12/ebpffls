#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} chain_guard_tgid SEC(".maps");

SEC("lsm/file_open")
int BPF_PROG(chain_deny_file_open, struct file *file, int ret)
{
	__u32 key = 0;
	__u32 *tgid;

	if (ret)
		return ret;
	tgid = bpf_map_lookup_elem(&chain_guard_tgid, &key);
	if (tgid && *tgid && *tgid == (__u32)(bpf_get_current_pid_tgid() >> 32))
		return -13;
	return 0;
}
