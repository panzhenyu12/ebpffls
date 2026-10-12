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
#define BPF_ANY 0
#define O_ACCMODE 00000003
#define O_WRONLY 00000001
#define O_RDWR 00000002
#define O_TRUNC 00001000

#include <bpf/bpf_helpers.h>
#include "events.h"
#include "legacy_maps.h"

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

#define ULTRA_MAX_CPUS 256
#define ULTRA_SLOTS_PER_CPU 128
#define PENDING_WRITE_TTL_NS 60000000000ULL
#define AT_FDCWD -100

enum syscall_abi_op {
	ABI_OP_EXECVE = 1,
	ABI_OP_OPEN = 2,
	ABI_OP_OPENAT = 3,
	ABI_OP_WRITE = 4,
	ABI_OP_PWRITE64 = 5,
	ABI_OP_WRITEV = 6,
	ABI_OP_RENAME = 7,
	ABI_OP_LINK = 8,
	ABI_OP_SYMLINK = 9,
	ABI_OP_UNLINK = 10,
	ABI_OP_TRUNCATE = 11,
	ABI_OP_FTRUNCATE = 12,
};

enum syscall_abi_kind {
	SYSCALL_ABI_UNKNOWN = 0,
	SYSCALL_ABI_DIRECT = 1,
	SYSCALL_ABI_WRAPPED = 2,
};

struct syscall_args {
	__u64 arg1;
	__u64 arg2;
	__u64 arg3;
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

struct pending_write {
	__u64 operation_id;
	__u64 size;
	__s32 fd;
	__u32 kind;
};

enum write_kind {
	WRITE_SCALAR = 1,
	WRITE_POSITIONAL = 2,
	WRITE_VECTOR = 3,
};

struct event_slot {
	__u64 seq;
	struct event event;
	__u64 seq_end;
};

struct bpf_map_def SEC("maps") events = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct event_slot),
	.max_entries = ULTRA_MAX_CPUS * ULTRA_SLOTS_PER_CPU,
};

struct bpf_map_def SEC("maps") event_cursor = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u64),
	.max_entries = ULTRA_MAX_CPUS,
};

struct bpf_map_def SEC("maps") scratch_events = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct event),
	.max_entries = ULTRA_MAX_CPUS,
};

struct bpf_map_def SEC("maps") ringbuf_drops = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u64),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") capture_gaps = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u64),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") syscall_abi = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 13,
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

struct bpf_map_def SEC("maps") pending_writes = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(struct pending_write),
	.max_entries = 16384,
};

static __always_inline void count_event_drop(void)
{
	// Counts detected capture gaps, not an exact number of lost events.
	__u32 key = 0;
	__u64 *drops = bpf_map_lookup_elem(&capture_gaps, &key);

	if (drops)
		__sync_fetch_and_add(drops, 1);
}

static __always_inline int read_syscall_args(struct pt_regs *ctx, __u32 op, struct syscall_args *args)
{
	__u32 *abi = bpf_map_lookup_elem(&syscall_abi, &op);
	struct pt_regs *sys;

	if (!abi)
		goto missing;
	if (*abi == SYSCALL_ABI_DIRECT) {
		args->arg1 = ctx->di;
		args->arg2 = ctx->si;
		args->arg3 = ctx->dx;
		return 0;
	}
	if (*abi != SYSCALL_ABI_WRAPPED)
		goto missing;
	// The selected symbol, not the contents of its arguments, determines ABI.
	sys = (struct pt_regs *)ctx->di;
	if (bpf_probe_read(&args->arg1, sizeof(args->arg1), &sys->di) != 0 ||
	    bpf_probe_read(&args->arg2, sizeof(args->arg2), &sys->si) != 0 ||
	    bpf_probe_read(&args->arg3, sizeof(args->arg3), &sys->dx) != 0)
		goto missing;
	return 0;

missing:
	count_event_drop();
	return -1;
}

static __always_inline long retval(struct pt_regs *ctx)
{
	return ctx->ax;
}

static __always_inline int read_user_path(char *dst, __u32 size, const void *src)
{
	// The generic 4.1 helper also reads kernel addresses; syscall strings must
	// stay in the x86-64 user half of the address space.
	if (!src || ((__u64)src >> 63) || bpf_probe_read(dst, size, src) != 0) {
		count_event_drop();
		dst[0] = 0;
		return -1;
	}
	return 0;
}

static __always_inline struct event *new_event(__u32 type)
{
	__u32 key = bpf_get_smp_processor_id();
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 uid_gid = bpf_get_current_uid_gid();
	struct event *e;

	if (key >= ULTRA_MAX_CPUS) {
		count_event_drop();
		return 0;
	}
	e = bpf_map_lookup_elem(&scratch_events, &key);
	if (!e) {
		count_event_drop();
		return 0;
	}
	__builtin_memset(e, 0, sizeof(*e));
	e->ts_ns = bpf_ktime_get_ns();
	e->pid = (__u32)pid_tgid;
	e->tgid = (__u32)(pid_tgid >> 32);
	e->uid = (__u32)uid_gid;
	e->type = type;
	e->version = EVENT_VERSION;
	e->phase = EVENT_PHASE_ATTEMPT;
	e->source = EVENT_SOURCE_KPROBE;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	return e;
}

static __always_inline int emit_event(struct event *e)
{
	__u32 key = bpf_get_smp_processor_id();
	__u64 *head;
	__u64 next;
	__u32 slot_key;
	struct event_slot *slot;

	if (!e)
		return 0;
	if (key >= ULTRA_MAX_CPUS) {
		count_event_drop();
		return 0;
	}
	head = bpf_map_lookup_elem(&event_cursor, &key);
	if (!head) {
		count_event_drop();
		return 0;
	}
	next = *head + 1;
	slot_key = key * ULTRA_SLOTS_PER_CPU + (__u32)((next - 1) & (ULTRA_SLOTS_PER_CPU - 1));
	slot = bpf_map_lookup_elem(&events, &slot_key);
	if (!slot) {
		count_event_drop();
		return 0;
	}
	// Each CPU publishes independently; both sequence markers guard readers
	// against copying a slot while a later event is overwriting its payload.
	slot->seq = 0;
	slot->seq_end = 0;
	asm volatile("" ::: "memory");
	slot->event = *e;
	asm volatile("" ::: "memory");
	slot->seq_end = next;
	asm volatile("" ::: "memory");
	slot->seq = next;
	asm volatile("" ::: "memory");
	*head = next;
	return 0;
}

SEC("kprobe/__x64_sys_execve")
int kp_override_execve(struct pt_regs *ctx)
{
	struct syscall_args args = {};
	struct event *e;

	if (read_syscall_args(ctx, ABI_OP_EXECVE, &args) != 0)
		return 0;
	e = new_event(EVENT_EXEC);
	if (!e)
		return 0;
	read_user_path(e->path, sizeof(e->path), (const void *)args.arg1);
	return emit_event(e);
}

SEC("kprobe/do_exit")
int kp_process_exit(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	if (bpf_map_lookup_elem(&pending_writes, &pid_tgid))
		count_event_drop();
	bpf_map_delete_elem(&pending_writes, &pid_tgid);
	bpf_map_delete_elem(&pending_opens, &pid_tgid);
	return 0;
}

static __always_inline int remember_open(struct pt_regs *ctx, __u32 op)
{
	struct pending_open pending = {};
	struct syscall_args args = {};
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	const void *pathname;

	bpf_map_delete_elem(&pending_opens, &pid_tgid);
	if (read_syscall_args(ctx, op, &args) != 0)
		return 0;
	if (op == ABI_OP_OPEN) {
		pending.dirfd = AT_FDCWD;
		pending.flags = (__s32)args.arg2;
		pathname = (const void *)args.arg1;
	} else {
		pending.dirfd = (__s32)args.arg1;
		pending.flags = (__s32)args.arg3;
		pathname = (const void *)args.arg2;
	}
	read_user_path(pending.path, sizeof(pending.path), pathname);
	if (bpf_map_update_elem(&pending_opens, &pid_tgid, &pending, BPF_ANY) != 0)
		count_event_drop();
	return 0;
}

SEC("kprobe/__x64_sys_open")
int kp_override_open(struct pt_regs *ctx)
{
	return remember_open(ctx, ABI_OP_OPEN);
}

SEC("kprobe/__x64_sys_openat")
int kp_override_openat(struct pt_regs *ctx)
{
	return remember_open(ctx, ABI_OP_OPENAT);
}

static __always_inline int emit_open_ret(struct pt_regs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct pending_open *pending = bpf_map_lookup_elem(&pending_opens, &pid_tgid);
	int fd = (__s32)retval(ctx);
	struct event *e;

	if (!pending)
		return 0;
	e = new_event(EVENT_OPEN);
	if (e) {
		e->phase = fd >= 0 ? EVENT_PHASE_SUCCESS : EVENT_PHASE_FAILURE;
		e->result = retval(ctx);
		e->flags = EVENT_RESULT_VALID;
		e->arg0 = pending->flags;
		e->arg1 = fd;
		e->size = (__u64)(__u32)pending->dirfd;
		__builtin_memcpy(e->path, pending->path, sizeof(e->path));
		emit_event(e);
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

static __always_inline void write_metadata(struct event *e, struct pending_write *pending)
{
	e->arg0 = pending->fd;
	e->size = pending->size;
	e->operation_id = pending->operation_id;
	if (pending->kind == WRITE_VECTOR) {
		e->vector_count = (__u32)pending->size;
		e->flags = EVENT_VECTOR_COUNT_VALID;
	} else {
		e->requested_bytes = pending->size;
		e->flags = EVENT_REQUESTED_BYTES_VALID;
	}
}

static __always_inline int remember_write(struct pt_regs *ctx, __u32 kind, __u32 op)
{
	struct pending_write pending = {};
	struct syscall_args args = {};
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct pending_write *previous;
	struct event *e;

	previous = bpf_map_lookup_elem(&pending_writes, &pid_tgid);
	if (previous) {
		// A thread entering its next write has already left the earlier call.
		// Its unmatched record is a missed return, not a completed operation.
		count_event_drop();
		bpf_map_delete_elem(&pending_writes, &pid_tgid);
	}
	if (read_syscall_args(ctx, op, &args) != 0)
		return 0;
	pending.operation_id = bpf_ktime_get_ns();
	pending.size = args.arg3;
	pending.fd = (__s32)args.arg1;
	pending.kind = kind;
	if (bpf_map_update_elem(&pending_writes, &pid_tgid, &pending, BPF_ANY) != 0) {
		count_event_drop();
		bpf_map_delete_elem(&pending_writes, &pid_tgid);
	}
	e = new_event(EVENT_WRITE);
	if (e) {
		write_metadata(e, &pending);
		emit_event(e);
	}
	return 0;
}

static __always_inline int complete_write(struct pt_regs *ctx, __u32 kind)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct pending_write *pending = bpf_map_lookup_elem(&pending_writes, &pid_tgid);
	long result = retval(ctx);
	struct event *e;

	if (!pending)
		return 0;
	if (pending->kind != kind || bpf_ktime_get_ns() - pending->operation_id > PENDING_WRITE_TTL_NS) {
		count_event_drop();
		bpf_map_delete_elem(&pending_writes, &pid_tgid);
		return 0;
	}
	e = new_event(EVENT_WRITE);
	if (e) {
		write_metadata(e, pending);
		e->phase = result >= 0 ? EVENT_PHASE_SUCCESS : EVENT_PHASE_FAILURE;
		e->result = result;
		e->actual_bytes = result > 0 ? (__u64)result : 0;
		e->flags |= EVENT_RESULT_VALID | EVENT_ACTUAL_BYTES_VALID;
		emit_event(e);
	}
	bpf_map_delete_elem(&pending_writes, &pid_tgid);
	return 0;
}

SEC("kprobe/__x64_sys_write")
int kp_override_write(struct pt_regs *ctx)
{
	return remember_write(ctx, WRITE_SCALAR, ABI_OP_WRITE);
}

SEC("kretprobe/__x64_sys_write")
int kp_ret_write(struct pt_regs *ctx)
{
	return complete_write(ctx, WRITE_SCALAR);
}

SEC("kprobe/__x64_sys_pwrite64")
int kp_override_pwrite64(struct pt_regs *ctx)
{
	return remember_write(ctx, WRITE_POSITIONAL, ABI_OP_PWRITE64);
}

SEC("kretprobe/__x64_sys_pwrite64")
int kp_ret_pwrite64(struct pt_regs *ctx)
{
	return complete_write(ctx, WRITE_POSITIONAL);
}

SEC("kprobe/__x64_sys_writev")
int kp_override_writev(struct pt_regs *ctx)
{
	return remember_write(ctx, WRITE_VECTOR, ABI_OP_WRITEV);
}

SEC("kretprobe/__x64_sys_writev")
int kp_ret_writev(struct pt_regs *ctx)
{
	return complete_write(ctx, WRITE_VECTOR);
}

SEC("kprobe/__x64_sys_rename")
int kp_override_rename(struct pt_regs *ctx)
{
	struct syscall_args args = {};
	struct event *e;

	if (read_syscall_args(ctx, ABI_OP_RENAME, &args) != 0)
		return 0;
	e = new_event(EVENT_RENAME);
	if (!e)
		return 0;
	read_user_path(e->path, sizeof(e->path), (const void *)args.arg1);
	read_user_path(e->path2, sizeof(e->path2), (const void *)args.arg2);
	return emit_event(e);
}

SEC("kprobe/__x64_sys_link")
int kp_override_link(struct pt_regs *ctx)
{
	struct syscall_args args = {};
	struct event *e;

	if (read_syscall_args(ctx, ABI_OP_LINK, &args) != 0)
		return 0;
	e = new_event(EVENT_LINK);
	if (!e)
		return 0;
	read_user_path(e->path, sizeof(e->path), (const void *)args.arg1);
	read_user_path(e->path2, sizeof(e->path2), (const void *)args.arg2);
	return emit_event(e);
}

SEC("kprobe/__x64_sys_symlink")
int kp_override_symlink(struct pt_regs *ctx)
{
	struct syscall_args args = {};
	struct event *e;

	if (read_syscall_args(ctx, ABI_OP_SYMLINK, &args) != 0)
		return 0;
	e = new_event(EVENT_LINK);
	if (!e)
		return 0;
	e->arg0 = 1;
	read_user_path(e->path, sizeof(e->path), (const void *)args.arg1);
	read_user_path(e->path2, sizeof(e->path2), (const void *)args.arg2);
	return emit_event(e);
}

SEC("kprobe/__x64_sys_unlink")
int kp_override_unlink(struct pt_regs *ctx)
{
	struct syscall_args args = {};
	struct event *e;

	if (read_syscall_args(ctx, ABI_OP_UNLINK, &args) != 0)
		return 0;
	e = new_event(EVENT_UNLINK);
	if (!e)
		return 0;
	read_user_path(e->path, sizeof(e->path), (const void *)args.arg1);
	return emit_event(e);
}

SEC("kprobe/__x64_sys_truncate")
int kp_override_truncate(struct pt_regs *ctx)
{
	struct syscall_args args = {};
	struct event *e;

	if (read_syscall_args(ctx, ABI_OP_TRUNCATE, &args) != 0)
		return 0;
	e = new_event(EVENT_TRUNCATE);
	if (!e)
		return 0;
	read_user_path(e->path, sizeof(e->path), (const void *)args.arg1);
	e->size = args.arg2;
	return emit_event(e);
}

SEC("kprobe/__x64_sys_ftruncate")
int kp_override_ftruncate(struct pt_regs *ctx)
{
	struct syscall_args args = {};
	struct event *e;

	if (read_syscall_args(ctx, ABI_OP_FTRUNCATE, &args) != 0)
		return 0;
	e = new_event(EVENT_TRUNCATE);
	if (!e)
		return 0;
	e->arg0 = (__s32)args.arg1;
	e->size = args.arg2;
	return emit_event(e);
}
