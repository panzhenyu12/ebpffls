#define __u8 unsigned char
#define __u16 unsigned short
#define __u32 unsigned int
#define __u64 unsigned long long
#define __s32 int
#define __s64 long long
#define __be16 unsigned short
#define __be32 unsigned int
#define __wsum unsigned int

#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_PERF_EVENT_ARRAY 4
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#define BPF_ANY 0
#define BPF_F_CURRENT_CPU 0xffffffffULL
#define EPERM 1
#define O_ACCMODE 00000003
#define O_WRONLY 00000001
#define O_RDWR 00000002
#define O_TRUNC 00001000
#define F_DUPFD 0
#define F_DUPFD_CLOEXEC 1030
#define PROT_WRITE 0x2
#define MAP_SHARED 0x01
#define MAP_SHARED_VALIDATE 0x03

#include <bpf/bpf_helpers.h>
#include "events.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

struct pt_regs;

struct trace_event_raw_sys_enter {
	__u64 unused;
	long id;
	unsigned long args[6];
};

struct trace_event_raw_sys_exit {
	__u64 unused;
	long id;
	long ret;
};

struct dir_key {
	__u64 dev;
	__u64 ino;
};

struct pending_open {
	__s32 dirfd;
	__s32 flags;
	char path[PATH_MAX_LEN];
};

struct pending_dup {
	__s32 oldfd;
	__s32 newfd;
};

struct bpf_map_def SEC("maps") events = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 256,
};

struct bpf_map_def SEC("maps") scratch_events = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct event),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") ringbuf_drops = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u64),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") blocked_tgids = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct block_entry),
	.max_entries = 16384,
};

struct bpf_map_def SEC("maps") ioc_extensions = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(__u8),
	.max_entries = 256,
};

struct bpf_map_def SEC("maps") ioc_ransom_notes = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(__u8),
	.max_entries = 256,
};

struct bpf_map_def SEC("maps") protected_dirs = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct dir_key),
	.value_size = sizeof(__u8),
	.max_entries = 256,
};

struct bpf_map_def SEC("maps") allowed_cgroups = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(__u8),
	.max_entries = 1024,
};

struct bpf_map_def SEC("maps") cgroup_scope_enabled = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u8),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") pending_opens = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(struct pending_open),
	.max_entries = 16384,
};

struct bpf_map_def SEC("maps") pending_dups = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(struct pending_dup),
	.max_entries = 16384,
};

static __always_inline struct event *new_event(__u32 type)
{
	__u32 key = 0;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 uid_gid = bpf_get_current_uid_gid();
	struct event *e = bpf_map_lookup_elem(&scratch_events, &key);

	if (!e)
		return 0;
	__builtin_memset(e, 0, sizeof(*e));
	e->ts_ns = bpf_ktime_get_ns();
	e->pid = (__u32)pid_tgid;
	e->tgid = (__u32)(pid_tgid >> 32);
	e->uid = (__u32)uid_gid;
	e->type = type;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	return e;
}

static __always_inline int emit_event(void *ctx, struct event *e)
{
	if (!e)
		return 0;
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, sizeof(*e));
	return 0;
}

static __always_inline struct block_entry *current_block_entry(void)
{
	__u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	return bpf_map_lookup_elem(&blocked_tgids, &tgid);
}

static __always_inline int enforce_blocked_syscall(struct pt_regs *ctx)
{
	struct block_entry *entry = current_block_entry();

	if (!entry)
		return 0;
	if (entry->action == BLOCK_ACTION_KILL)
		return 0;
	return bpf_override_return(ctx, -EPERM);
}

SEC("kprobe/__x64_sys_openat")
int kp_override_openat(struct pt_regs *ctx) { return enforce_blocked_syscall(ctx); }
SEC("kprobe/__x64_sys_openat2")
int kp_override_openat2(struct pt_regs *ctx) { return enforce_blocked_syscall(ctx); }
SEC("kprobe/__x64_sys_rename")
int kp_override_rename(struct pt_regs *ctx) { return enforce_blocked_syscall(ctx); }
SEC("kprobe/__x64_sys_renameat")
int kp_override_renameat(struct pt_regs *ctx) { return enforce_blocked_syscall(ctx); }
SEC("kprobe/__x64_sys_renameat2")
int kp_override_renameat2(struct pt_regs *ctx) { return enforce_blocked_syscall(ctx); }
SEC("kprobe/__x64_sys_link")
int kp_override_link(struct pt_regs *ctx) { return enforce_blocked_syscall(ctx); }
SEC("kprobe/__x64_sys_linkat")
int kp_override_linkat(struct pt_regs *ctx) { return enforce_blocked_syscall(ctx); }
SEC("kprobe/__x64_sys_symlink")
int kp_override_symlink(struct pt_regs *ctx) { return enforce_blocked_syscall(ctx); }
SEC("kprobe/__x64_sys_symlinkat")
int kp_override_symlinkat(struct pt_regs *ctx) { return enforce_blocked_syscall(ctx); }
SEC("kprobe/__x64_sys_unlink")
int kp_override_unlink(struct pt_regs *ctx) { return enforce_blocked_syscall(ctx); }
SEC("kprobe/__x64_sys_unlinkat")
int kp_override_unlinkat(struct pt_regs *ctx) { return enforce_blocked_syscall(ctx); }
SEC("kprobe/__x64_sys_truncate")
int kp_override_truncate(struct pt_regs *ctx) { return enforce_blocked_syscall(ctx); }
SEC("kprobe/__x64_sys_ftruncate")
int kp_override_ftruncate(struct pt_regs *ctx) { return enforce_blocked_syscall(ctx); }
SEC("kprobe/__x64_sys_execve")
int kp_override_execve(struct pt_regs *ctx) { return enforce_blocked_syscall(ctx); }
SEC("kprobe/__x64_sys_write")
int kp_override_write(struct pt_regs *ctx) { return enforce_blocked_syscall(ctx); }
SEC("kprobe/__x64_sys_pwrite64")
int kp_override_pwrite64(struct pt_regs *ctx) { return enforce_blocked_syscall(ctx); }
SEC("kprobe/__x64_sys_writev")
int kp_override_writev(struct pt_regs *ctx) { return enforce_blocked_syscall(ctx); }
SEC("kprobe/__x64_sys_copy_file_range")
int kp_override_copy_file_range(struct pt_regs *ctx) { return enforce_blocked_syscall(ctx); }
SEC("kprobe/__x64_sys_getdents64")
int kp_override_getdents64(struct pt_regs *ctx) { return enforce_blocked_syscall(ctx); }
SEC("kprobe/__x64_sys_mmap")
int kp_override_mmap(struct pt_regs *ctx) { return enforce_blocked_syscall(ctx); }
SEC("kprobe/__x64_sys_io_uring_enter")
int kp_override_io_uring_enter(struct pt_regs *ctx) { return enforce_blocked_syscall(ctx); }

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = new_event(EVENT_EXEC);
	if (!e)
		return 0;
	bpf_probe_read_str(e->path, sizeof(e->path), (const void *)ctx->args[0]);
	return emit_event(ctx, e);
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
	struct pending_open pending = {};
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	pending.dirfd = (__s32)ctx->args[0];
	pending.flags = (__s32)ctx->args[2];
	bpf_probe_read_str(pending.path, sizeof(pending.path), (const void *)ctx->args[1]);
	bpf_map_update_elem(&pending_opens, &pid_tgid, &pending, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int trace_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct pending_open *pending = bpf_map_lookup_elem(&pending_opens, &pid_tgid);
	int fd = (__s32)ctx->ret;
	struct event *e;

	if (!pending)
		return 0;
	if (fd >= 0) {
		e = new_event(EVENT_OPEN);
		if (e) {
			e->arg0 = pending->flags;
			e->arg1 = fd;
			e->size = (__u64)(__u32)pending->dirfd;
			__builtin_memcpy(e->path, pending->path, sizeof(e->path));
			emit_event(ctx, e);
		}
	}
	bpf_map_delete_elem(&pending_opens, &pid_tgid);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int trace_openat2(struct trace_event_raw_sys_enter *ctx)
{
	struct pending_open pending = {};
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	pending.dirfd = (__s32)ctx->args[0];
	bpf_probe_read_str(pending.path, sizeof(pending.path), (const void *)ctx->args[1]);
	bpf_probe_read(&pending.flags, sizeof(pending.flags), (const void *)(ctx->args[2] + 8));
	bpf_map_update_elem(&pending_opens, &pid_tgid, &pending, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat2")
int trace_openat2_exit(struct trace_event_raw_sys_exit *ctx)
{
	return trace_openat_exit(ctx);
}

SEC("tracepoint/syscalls/sys_enter_write")
int trace_write(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = new_event(EVENT_WRITE);
	if (!e)
		return 0;
	e->arg0 = (__s32)ctx->args[0];
	e->size = (__u64)ctx->args[2];
	return emit_event(ctx, e);
}

SEC("tracepoint/syscalls/sys_enter_pwrite64")
int trace_pwrite64(struct trace_event_raw_sys_enter *ctx)
{
	return trace_write(ctx);
}

SEC("tracepoint/syscalls/sys_enter_writev")
int trace_writev(struct trace_event_raw_sys_enter *ctx)
{
	return trace_write(ctx);
}

SEC("tracepoint/syscalls/sys_enter_copy_file_range")
int trace_copy_file_range(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = new_event(EVENT_WRITE);
	if (!e)
		return 0;
	e->arg0 = (__s32)ctx->args[2];
	e->size = (__u64)ctx->args[4];
	return emit_event(ctx, e);
}

SEC("tracepoint/syscalls/sys_enter_close")
int trace_close(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = new_event(EVENT_CLOSE);
	if (!e)
		return 0;
	e->arg0 = (__s32)ctx->args[0];
	return emit_event(ctx, e);
}

SEC("tracepoint/syscalls/sys_enter_getdents64")
int trace_getdents64(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = new_event(EVENT_SCAN);
	if (!e)
		return 0;
	e->arg0 = (__s32)ctx->args[0];
	e->size = (__u64)ctx->args[2];
	return emit_event(ctx, e);
}

SEC("tracepoint/syscalls/sys_enter_mmap")
int trace_mmap(struct trace_event_raw_sys_enter *ctx)
{
	int prot = (__s32)ctx->args[2];
	int flags = (__s32)ctx->args[3];
	struct event *e;

	if (!(prot & PROT_WRITE))
		return 0;
	if ((flags & MAP_SHARED_VALIDATE) != MAP_SHARED && (flags & MAP_SHARED_VALIDATE) != MAP_SHARED_VALIDATE)
		return 0;
	e = new_event(EVENT_MMAP);
	if (!e)
		return 0;
	e->arg0 = (__s32)ctx->args[4];
	e->arg1 = prot;
	e->size = (__u64)ctx->args[1];
	return emit_event(ctx, e);
}

SEC("tracepoint/syscalls/sys_enter_io_uring_enter")
int trace_io_uring_enter(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = new_event(EVENT_IO_URING);
	if (!e)
		return 0;
	e->arg0 = (__s32)ctx->args[0];
	e->arg1 = (__s32)ctx->args[2];
	e->size = (__u64)ctx->args[1];
	return emit_event(ctx, e);
}

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = new_event(EVENT_CONNECT);
	if (!e)
		return 0;
	e->arg0 = (__s32)ctx->args[0];
	e->size = (__u64)ctx->args[2];
	return emit_event(ctx, e);
}

SEC("tracepoint/syscalls/sys_enter_dup")
int trace_dup(struct trace_event_raw_sys_enter *ctx)
{
	struct pending_dup pending = {};
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	pending.oldfd = (__s32)ctx->args[0];
	pending.newfd = -1;
	bpf_map_update_elem(&pending_dups, &pid_tgid, &pending, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_dup")
int trace_dup_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct pending_dup *pending = bpf_map_lookup_elem(&pending_dups, &pid_tgid);
	int newfd = (__s32)ctx->ret;
	struct event *e;

	if (!pending)
		return 0;
	if (newfd >= 0) {
		e = new_event(EVENT_DUP);
		if (e) {
			e->arg0 = pending->oldfd;
			e->arg1 = newfd;
			emit_event(ctx, e);
		}
	}
	bpf_map_delete_elem(&pending_dups, &pid_tgid);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_dup2")
int trace_dup2(struct trace_event_raw_sys_enter *ctx)
{
	struct pending_dup pending = {};
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	pending.oldfd = (__s32)ctx->args[0];
	pending.newfd = (__s32)ctx->args[1];
	bpf_map_update_elem(&pending_dups, &pid_tgid, &pending, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_dup2")
int trace_dup2_exit(struct trace_event_raw_sys_exit *ctx)
{
	return trace_dup_exit(ctx);
}

SEC("tracepoint/syscalls/sys_enter_dup3")
int trace_dup3(struct trace_event_raw_sys_enter *ctx)
{
	return trace_dup2(ctx);
}

SEC("tracepoint/syscalls/sys_exit_dup3")
int trace_dup3_exit(struct trace_event_raw_sys_exit *ctx)
{
	return trace_dup_exit(ctx);
}

SEC("tracepoint/syscalls/sys_enter_fcntl")
int trace_fcntl(struct trace_event_raw_sys_enter *ctx)
{
	struct pending_dup pending = {};
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	int cmd = (__s32)ctx->args[1];

	if (cmd != F_DUPFD && cmd != F_DUPFD_CLOEXEC)
		return 0;
	pending.oldfd = (__s32)ctx->args[0];
	pending.newfd = -1;
	bpf_map_update_elem(&pending_dups, &pid_tgid, &pending, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_fcntl")
int trace_fcntl_exit(struct trace_event_raw_sys_exit *ctx)
{
	return trace_dup_exit(ctx);
}

SEC("tracepoint/syscalls/sys_enter_rename")
int trace_rename(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = new_event(EVENT_RENAME);
	if (!e)
		return 0;
	bpf_probe_read_str(e->path, sizeof(e->path), (const void *)ctx->args[0]);
	bpf_probe_read_str(e->path2, sizeof(e->path2), (const void *)ctx->args[1]);
	return emit_event(ctx, e);
}

SEC("tracepoint/syscalls/sys_enter_renameat")
int trace_renameat(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = new_event(EVENT_RENAME);
	if (!e)
		return 0;
	bpf_probe_read_str(e->path, sizeof(e->path), (const void *)ctx->args[1]);
	bpf_probe_read_str(e->path2, sizeof(e->path2), (const void *)ctx->args[3]);
	return emit_event(ctx, e);
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int trace_renameat2(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = new_event(EVENT_RENAME);
	if (!e)
		return 0;
	e->arg0 = (__s32)ctx->args[4];
	bpf_probe_read_str(e->path, sizeof(e->path), (const void *)ctx->args[1]);
	bpf_probe_read_str(e->path2, sizeof(e->path2), (const void *)ctx->args[3]);
	return emit_event(ctx, e);
}

SEC("tracepoint/syscalls/sys_enter_link")
int trace_link(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = new_event(EVENT_LINK);
	if (!e)
		return 0;
	bpf_probe_read_str(e->path, sizeof(e->path), (const void *)ctx->args[0]);
	bpf_probe_read_str(e->path2, sizeof(e->path2), (const void *)ctx->args[1]);
	return emit_event(ctx, e);
}

SEC("tracepoint/syscalls/sys_enter_linkat")
int trace_linkat(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = new_event(EVENT_LINK);
	if (!e)
		return 0;
	e->arg0 = (__s32)ctx->args[4];
	bpf_probe_read_str(e->path, sizeof(e->path), (const void *)ctx->args[1]);
	bpf_probe_read_str(e->path2, sizeof(e->path2), (const void *)ctx->args[3]);
	return emit_event(ctx, e);
}

SEC("tracepoint/syscalls/sys_enter_symlink")
int trace_symlink(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = new_event(EVENT_LINK);
	if (!e)
		return 0;
	e->arg0 = 1;
	bpf_probe_read_str(e->path, sizeof(e->path), (const void *)ctx->args[0]);
	bpf_probe_read_str(e->path2, sizeof(e->path2), (const void *)ctx->args[1]);
	return emit_event(ctx, e);
}

SEC("tracepoint/syscalls/sys_enter_symlinkat")
int trace_symlinkat(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = new_event(EVENT_LINK);
	if (!e)
		return 0;
	e->arg0 = 1;
	bpf_probe_read_str(e->path, sizeof(e->path), (const void *)ctx->args[0]);
	bpf_probe_read_str(e->path2, sizeof(e->path2), (const void *)ctx->args[2]);
	return emit_event(ctx, e);
}

SEC("tracepoint/syscalls/sys_enter_unlink")
int trace_unlink(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = new_event(EVENT_UNLINK);
	if (!e)
		return 0;
	bpf_probe_read_str(e->path, sizeof(e->path), (const void *)ctx->args[0]);
	return emit_event(ctx, e);
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = new_event(EVENT_UNLINK);
	if (!e)
		return 0;
	e->arg0 = (__s32)ctx->args[2];
	bpf_probe_read_str(e->path, sizeof(e->path), (const void *)ctx->args[1]);
	return emit_event(ctx, e);
}

SEC("tracepoint/syscalls/sys_enter_truncate")
int trace_truncate(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = new_event(EVENT_TRUNCATE);
	if (!e)
		return 0;
	e->size = (__u64)ctx->args[1];
	bpf_probe_read_str(e->path, sizeof(e->path), (const void *)ctx->args[0]);
	return emit_event(ctx, e);
}

SEC("tracepoint/syscalls/sys_enter_ftruncate")
int trace_ftruncate(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = new_event(EVENT_TRUNCATE);
	if (!e)
		return 0;
	e->arg0 = (__s32)ctx->args[0];
	e->size = (__u64)ctx->args[1];
	return emit_event(ctx, e);
}
