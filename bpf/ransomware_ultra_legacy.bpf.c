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
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#define BPF_ANY 0
#define O_ACCMODE 00000003
#define O_WRONLY 00000001
#define O_RDWR 00000002
#define O_TRUNC 00001000

#include <bpf/bpf_helpers.h>
#include "events.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

struct pt_regs {
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long bp;
	unsigned long bx;
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long ax;
	unsigned long cx;
	unsigned long dx;
	unsigned long si;
	unsigned long di;
	unsigned long orig_ax;
	unsigned long ip;
	unsigned long cs;
	unsigned long flags;
	unsigned long sp;
	unsigned long ss;
};

#define ULTRA_EVENT_SLOTS 1024
#define AT_FDCWD -100

struct dir_key {
	__u64 dev;
	__u64 ino;
};

struct pending_open {
	__s32 dirfd;
	__s32 flags;
	char path[PATH_MAX_LEN];
};

struct event_slot {
	__u64 seq;
	struct event event;
};

struct bpf_map_def SEC("maps") events = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct event_slot),
	.max_entries = ULTRA_EVENT_SLOTS,
};

struct bpf_map_def SEC("maps") event_cursor = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u64),
	.max_entries = 1,
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

static __always_inline unsigned long direct_parm1(struct pt_regs *ctx)
{
	return ctx->di;
}

static __always_inline unsigned long direct_parm2(struct pt_regs *ctx)
{
	return ctx->si;
}

static __always_inline unsigned long direct_parm3(struct pt_regs *ctx)
{
	return ctx->dx;
}

static __always_inline unsigned long wrapped_parm1(struct pt_regs *ctx)
{
	struct pt_regs *sys = (struct pt_regs *)ctx->di;
	unsigned long v = 0;
	bpf_probe_read(&v, sizeof(v), &sys->di);
	return v;
}

static __always_inline unsigned long wrapped_parm2(struct pt_regs *ctx)
{
	struct pt_regs *sys = (struct pt_regs *)ctx->di;
	unsigned long v = 0;
	bpf_probe_read(&v, sizeof(v), &sys->si);
	return v;
}

static __always_inline unsigned long wrapped_parm3(struct pt_regs *ctx)
{
	struct pt_regs *sys = (struct pt_regs *)ctx->di;
	unsigned long v = 0;
	bpf_probe_read(&v, sizeof(v), &sys->dx);
	return v;
}

static __always_inline long retval(struct pt_regs *ctx)
{
	return ctx->ax;
}

static __always_inline int read_str_arg1(struct pt_regs *ctx, char *dst, __u32 size)
{
	int n = bpf_probe_read_str(dst, size, (const void *)direct_parm1(ctx));
	if (n > 1)
		return n;
	return bpf_probe_read_str(dst, size, (const void *)wrapped_parm1(ctx));
}

static __always_inline int read_str_arg2(struct pt_regs *ctx, char *dst, __u32 size)
{
	int n = bpf_probe_read_str(dst, size, (const void *)direct_parm2(ctx));
	if (n > 1)
		return n;
	return bpf_probe_read_str(dst, size, (const void *)wrapped_parm2(ctx));
}

static __always_inline int direct_first_arg_is_small(struct pt_regs *ctx)
{
	long v = (long)direct_parm1(ctx);
	return v > -4096 && v < 1048576;
}

static __always_inline unsigned long num_arg1(struct pt_regs *ctx)
{
	if (direct_first_arg_is_small(ctx))
		return direct_parm1(ctx);
	return wrapped_parm1(ctx);
}

static __always_inline unsigned long num_arg2(struct pt_regs *ctx)
{
	if (direct_first_arg_is_small(ctx))
		return direct_parm2(ctx);
	return wrapped_parm2(ctx);
}

static __always_inline unsigned long num_arg3(struct pt_regs *ctx)
{
	if (direct_first_arg_is_small(ctx))
		return direct_parm3(ctx);
	return wrapped_parm3(ctx);
}

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

static __always_inline int emit_event(struct event *e)
{
	__u32 key = 0;
	__u64 *head = bpf_map_lookup_elem(&event_cursor, &key);
	__u64 next;
	__u32 slot_key;
	struct event_slot *slot;

	if (!e || !head)
		return 0;
	next = *head + 1;
	slot_key = (__u32)((next - 1) & (ULTRA_EVENT_SLOTS - 1));
	slot = bpf_map_lookup_elem(&events, &slot_key);
	if (!slot)
		return 0;
	slot->event = *e;
	slot->seq = next;
	*head = next;
	return 0;
}

SEC("kprobe/__x64_sys_execve")
int kp_override_execve(struct pt_regs *ctx)
{
	struct event *e = new_event(EVENT_EXEC);
	if (!e)
		return 0;
	read_str_arg1(ctx, e->path, sizeof(e->path));
	return emit_event(e);
}

static __always_inline int remember_open(struct pt_regs *ctx, __s32 dirfd, const void *pathname, __s32 flags)
{
	struct pending_open pending = {};
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	pending.dirfd = dirfd;
	pending.flags = flags;
	bpf_probe_read_str(pending.path, sizeof(pending.path), pathname);
	bpf_map_update_elem(&pending_opens, &pid_tgid, &pending, BPF_ANY);
	return 0;
}

SEC("kprobe/__x64_sys_open")
int kp_override_open(struct pt_regs *ctx)
{
	struct pending_open pending = {};
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	pending.dirfd = AT_FDCWD;
	if (bpf_probe_read_str(pending.path, sizeof(pending.path), (const void *)direct_parm1(ctx)) > 1) {
		pending.flags = (__s32)direct_parm2(ctx);
	} else {
		bpf_probe_read_str(pending.path, sizeof(pending.path), (const void *)wrapped_parm1(ctx));
		pending.flags = (__s32)wrapped_parm2(ctx);
	}
	bpf_map_update_elem(&pending_opens, &pid_tgid, &pending, BPF_ANY);
	return 0;
}

SEC("kprobe/__x64_sys_openat")
int kp_override_openat(struct pt_regs *ctx)
{
	if (direct_first_arg_is_small(ctx))
		return remember_open(ctx, (__s32)direct_parm1(ctx), (const void *)direct_parm2(ctx), (__s32)direct_parm3(ctx));
	return remember_open(ctx, (__s32)wrapped_parm1(ctx), (const void *)wrapped_parm2(ctx), (__s32)wrapped_parm3(ctx));
}

static __always_inline int emit_open_ret(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct pending_open *pending = bpf_map_lookup_elem(&pending_opens, &pid_tgid);
	int fd = (__s32)retval(ctx);
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
			emit_event(e);
		}
	}
	bpf_map_delete_elem(&pending_opens, &pid_tgid);
	return 0;
}

SEC("kretprobe/__x64_sys_open")
int kp_ret_open(struct pt_regs *ctx)
{
	return emit_open_ret(ctx);
}

SEC("kretprobe/__x64_sys_openat")
int kp_ret_openat(struct pt_regs *ctx)
{
	return emit_open_ret(ctx);
}

SEC("kprobe/__x64_sys_write")
int kp_override_write(struct pt_regs *ctx)
{
	struct event *e = new_event(EVENT_WRITE);
	if (!e)
		return 0;
	e->arg0 = (__s32)num_arg1(ctx);
	e->size = (__u64)num_arg3(ctx);
	return emit_event(e);
}

SEC("kprobe/__x64_sys_pwrite64")
int kp_override_pwrite64(struct pt_regs *ctx)
{
	return kp_override_write(ctx);
}

SEC("kprobe/__x64_sys_writev")
int kp_override_writev(struct pt_regs *ctx)
{
	return kp_override_write(ctx);
}

SEC("kprobe/__x64_sys_rename")
int kp_override_rename(struct pt_regs *ctx)
{
	struct event *e = new_event(EVENT_RENAME);
	if (!e)
		return 0;
	read_str_arg1(ctx, e->path, sizeof(e->path));
	read_str_arg2(ctx, e->path2, sizeof(e->path2));
	return emit_event(e);
}

SEC("kprobe/__x64_sys_link")
int kp_override_link(struct pt_regs *ctx)
{
	struct event *e = new_event(EVENT_LINK);
	if (!e)
		return 0;
	read_str_arg1(ctx, e->path, sizeof(e->path));
	read_str_arg2(ctx, e->path2, sizeof(e->path2));
	return emit_event(e);
}

SEC("kprobe/__x64_sys_symlink")
int kp_override_symlink(struct pt_regs *ctx)
{
	struct event *e = new_event(EVENT_LINK);
	if (!e)
		return 0;
	e->arg0 = 1;
	read_str_arg1(ctx, e->path, sizeof(e->path));
	read_str_arg2(ctx, e->path2, sizeof(e->path2));
	return emit_event(e);
}

SEC("kprobe/__x64_sys_unlink")
int kp_override_unlink(struct pt_regs *ctx)
{
	struct event *e = new_event(EVENT_UNLINK);
	if (!e)
		return 0;
	read_str_arg1(ctx, e->path, sizeof(e->path));
	return emit_event(e);
}

SEC("kprobe/__x64_sys_truncate")
int kp_override_truncate(struct pt_regs *ctx)
{
	struct event *e = new_event(EVENT_TRUNCATE);
	if (!e)
		return 0;
	if (bpf_probe_read_str(e->path, sizeof(e->path), (const void *)direct_parm1(ctx)) > 1) {
		e->size = (__u64)direct_parm2(ctx);
	} else {
		bpf_probe_read_str(e->path, sizeof(e->path), (const void *)wrapped_parm1(ctx));
		e->size = (__u64)wrapped_parm2(ctx);
	}
	return emit_event(e);
}

SEC("kprobe/__x64_sys_ftruncate")
int kp_override_ftruncate(struct pt_regs *ctx)
{
	struct event *e = new_event(EVENT_TRUNCATE);
	if (!e)
		return 0;
	e->arg0 = (__s32)num_arg1(ctx);
	e->size = (__u64)num_arg2(ctx);
	return emit_event(e);
}
