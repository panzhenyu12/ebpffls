#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "events.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

#define EPERM 1
#define MAY_WRITE 2
#define O_ACCMODE 00000003
#define O_WRONLY 00000001
#define O_RDWR 00000002
#define O_TRUNC 00001000
#define SIGKILL 9
#define NAME_MAX_LEN 128

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, struct block_entry);
} blocked_tgids SEC(".maps");

static __always_inline __u32 current_ppid(void)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct task_struct *parent = BPF_CORE_READ(task, real_parent);
	return BPF_CORE_READ(parent, tgid);
}

static __always_inline struct event *new_event(__u32 type)
{
	struct event *e;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 uid_gid = bpf_get_current_uid_gid();

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->ts_ns = bpf_ktime_get_ns();
	e->pid = (__u32)pid_tgid;
	e->tgid = (__u32)(pid_tgid >> 32);
	e->ppid = current_ppid();
	e->uid = (__u32)uid_gid;
	e->type = type;
	e->arg0 = 0;
	e->arg1 = 0;
	e->size = 0;
	__builtin_memset(e->path, 0, sizeof(e->path));
	__builtin_memset(e->path2, 0, sizeof(e->path2));
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	return e;
}

static __always_inline struct block_entry *current_block_entry(void)
{
	__u64 now = bpf_ktime_get_ns();
	__u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	struct block_entry *entry = bpf_map_lookup_elem(&blocked_tgids, &tgid);

	if (!entry)
		return 0;
	if (entry->expires_ns != 0 && entry->expires_ns < now) {
		bpf_map_delete_elem(&blocked_tgids, &tgid);
		return 0;
	}
	return entry;
}

static __always_inline int deny_or_kill(struct block_entry *entry)
{
	if (!entry)
		return 0;
	if (entry->action == BLOCK_ACTION_KILL)
		bpf_send_signal(SIGKILL);
	return -EPERM;
}

static __always_inline int kill_blocked_syscall(void)
{
	struct block_entry *entry = current_block_entry();

	if (!entry)
		return 0;
	if (entry->action == BLOCK_ACTION_KILL) {
		bpf_send_signal(SIGKILL);
	}
	return 0;
}

static __always_inline int match_char(const unsigned char *name, __u32 off, char want)
{
	char got = 0;

	if (off >= NAME_MAX_LEN)
		return 0;
	if (bpf_probe_read_kernel(&got, sizeof(got), name + off) != 0)
		return 0;
	return got == want;
}

static __always_inline int suspicious_name(const unsigned char *name, __u32 len)
{
	__u32 start;

	if (len == 0 || len >= NAME_MAX_LEN)
		return 0;

	start = len - 7;
	if (len > 7 && match_char(name, start, '.') && match_char(name, start + 1, 'l') &&
	    match_char(name, start + 2, 'o') && match_char(name, start + 3, 'c') &&
	    match_char(name, start + 4, 'k') && match_char(name, start + 5, 'e') &&
	    match_char(name, start + 6, 'd'))
		return 1;

	start = len - 10;
	if (len > 10 && match_char(name, start, '.') && match_char(name, start + 1, 'e') &&
	    match_char(name, start + 2, 'n') && match_char(name, start + 3, 'c') &&
	    match_char(name, start + 4, 'r') && match_char(name, start + 5, 'y') &&
	    match_char(name, start + 6, 'p') && match_char(name, start + 7, 't') &&
	    match_char(name, start + 8, 'e') && match_char(name, start + 9, 'd'))
		return 1;

	start = len - 6;
	if (len > 6 && match_char(name, start, '.') && match_char(name, start + 1, 'c') &&
	    match_char(name, start + 2, 'r') && match_char(name, start + 3, 'y') &&
	    match_char(name, start + 4, 'p') && match_char(name, start + 5, 't'))
		return 1;

	start = len - 7;
	if (len > 7 && match_char(name, start, '.') && match_char(name, start + 1, 'c') &&
	    match_char(name, start + 2, 'r') && match_char(name, start + 3, 'y') &&
	    match_char(name, start + 4, 'p') && match_char(name, start + 5, 't') &&
	    match_char(name, start + 6, 'o'))
		return 1;

	start = len - 4;
	if (len > 4 && match_char(name, start, '.') && match_char(name, start + 1, 'e') &&
	    match_char(name, start + 2, 'n') && match_char(name, start + 3, 'c'))
		return 1;

	if (len == 22 && match_char(name, 0, 'R') && match_char(name, 1, 'E') &&
	    match_char(name, 2, 'A') && match_char(name, 3, 'D') && match_char(name, 4, 'M') &&
	    match_char(name, 5, 'E') && match_char(name, 6, '_') && match_char(name, 7, 'F') &&
	    match_char(name, 8, 'O') && match_char(name, 9, 'R') && match_char(name, 10, '_') &&
	    match_char(name, 11, 'D') && match_char(name, 12, 'E') && match_char(name, 13, 'C') &&
	    match_char(name, 14, 'R') && match_char(name, 15, 'Y') && match_char(name, 16, 'P') &&
	    match_char(name, 17, 'T') && match_char(name, 18, '.') && match_char(name, 19, 't') &&
	    match_char(name, 20, 'x') && match_char(name, 21, 't'))
		return 1;

	if (len == 21 && match_char(name, 0, 'R') && match_char(name, 1, 'E') &&
	    match_char(name, 2, 'A') && match_char(name, 3, 'D') && match_char(name, 4, 'M') &&
	    match_char(name, 5, 'E') && match_char(name, 6, '_') && match_char(name, 7, 'T') &&
	    match_char(name, 8, 'O') && match_char(name, 9, '_') && match_char(name, 10, 'D') &&
	    match_char(name, 11, 'E') && match_char(name, 12, 'C') && match_char(name, 13, 'R') &&
	    match_char(name, 14, 'Y') && match_char(name, 15, 'P') && match_char(name, 16, 'T') &&
	    match_char(name, 17, '.') && match_char(name, 18, 't') && match_char(name, 19, 'x') &&
	    match_char(name, 20, 't'))
		return 1;

	if (len == 24 && match_char(name, 0, 'D') && match_char(name, 1, 'E') &&
	    match_char(name, 2, 'C') && match_char(name, 3, 'R') && match_char(name, 4, 'Y') &&
	    match_char(name, 5, 'P') && match_char(name, 6, 'T') && match_char(name, 7, '_') &&
	    match_char(name, 8, 'I') && match_char(name, 9, 'N') && match_char(name, 10, 'S') &&
	    match_char(name, 11, 'T') && match_char(name, 12, 'R') && match_char(name, 13, 'U') &&
	    match_char(name, 14, 'C') && match_char(name, 15, 'T') && match_char(name, 16, 'I') &&
	    match_char(name, 17, 'O') && match_char(name, 18, 'N') && match_char(name, 19, 'S') &&
	    match_char(name, 20, '.') && match_char(name, 21, 't') && match_char(name, 22, 'x') &&
	    match_char(name, 23, 't'))
		return 1;

	if (len == 17 && match_char(name, 0, 'R') && match_char(name, 1, 'E') &&
	    match_char(name, 2, 'C') && match_char(name, 3, 'O') && match_char(name, 4, 'V') &&
	    match_char(name, 5, 'E') && match_char(name, 6, 'R') && match_char(name, 7, '_') &&
	    match_char(name, 8, 'F') && match_char(name, 9, 'I') && match_char(name, 10, 'L') &&
	    match_char(name, 11, 'E') && match_char(name, 12, 'S') && match_char(name, 13, '.') &&
	    match_char(name, 14, 't') && match_char(name, 15, 'x') && match_char(name, 16, 't'))
		return 1;

	if (len == 18 && match_char(name, 0, 'R') && match_char(name, 1, 'E') &&
	    match_char(name, 2, 'C') && match_char(name, 3, 'O') && match_char(name, 4, 'V') &&
	    match_char(name, 5, 'E') && match_char(name, 6, 'R') && match_char(name, 7, '_') &&
	    match_char(name, 8, 'F') && match_char(name, 9, 'I') && match_char(name, 10, 'L') &&
	    match_char(name, 11, 'E') && match_char(name, 12, 'S') && match_char(name, 13, '.') &&
	    match_char(name, 14, 'h') && match_char(name, 15, 't') && match_char(name, 16, 'm') &&
	    match_char(name, 17, 'l'))
		return 1;

	if (len == 18 && match_char(name, 0, 'H') && match_char(name, 1, 'O') &&
	    match_char(name, 2, 'W') && match_char(name, 3, '_') && match_char(name, 4, 'T') &&
	    match_char(name, 5, 'O') && match_char(name, 6, '_') && match_char(name, 7, 'D') &&
	    match_char(name, 8, 'E') && match_char(name, 9, 'C') && match_char(name, 10, 'R') &&
	    match_char(name, 11, 'Y') && match_char(name, 12, 'P') && match_char(name, 13, 'T') &&
	    match_char(name, 14, '.') && match_char(name, 15, 't') && match_char(name, 16, 'x') &&
	    match_char(name, 17, 't'))
		return 1;
	return 0;
}

static __always_inline int suspicious_dentry(struct dentry *dentry)
{
	const unsigned char *dname;
	__u32 len;

	dname = BPF_CORE_READ(dentry, d_name.name);
	if (!dname)
		return 0;
	len = BPF_CORE_READ(dentry, d_name.len);
	if (len == 0 || len >= NAME_MAX_LEN)
		return 0;
	return suspicious_name(dname, len);
}

static __always_inline void emit_block_event(__u32 op, const char *path)
{
	struct event *e = new_event(EVENT_BLOCK);
	if (!e)
		return;
	e->arg0 = op;
	if (path)
		bpf_probe_read_kernel_str(e->path, sizeof(e->path), path);
	bpf_ringbuf_submit(e, 0);
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = new_event(EVENT_EXEC);
	if (!e)
		return 0;

	const char *filename = (const char *)ctx->args[0];
	bpf_probe_read_user_str(e->path, sizeof(e->path), filename);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("kprobe/__x64_sys_openat")
int kp_override_openat(struct pt_regs *ctx)
{
	return kill_blocked_syscall();
}

SEC("kprobe/__x64_sys_openat2")
int kp_override_openat2(struct pt_regs *ctx)
{
	return kill_blocked_syscall();
}

SEC("kprobe/__x64_sys_rename")
int kp_override_rename(struct pt_regs *ctx)
{
	return kill_blocked_syscall();
}

SEC("kprobe/__x64_sys_renameat")
int kp_override_renameat(struct pt_regs *ctx)
{
	return kill_blocked_syscall();
}

SEC("kprobe/__x64_sys_renameat2")
int kp_override_renameat2(struct pt_regs *ctx)
{
	return kill_blocked_syscall();
}

SEC("kprobe/__x64_sys_unlink")
int kp_override_unlink(struct pt_regs *ctx)
{
	return kill_blocked_syscall();
}

SEC("kprobe/__x64_sys_unlinkat")
int kp_override_unlinkat(struct pt_regs *ctx)
{
	return kill_blocked_syscall();
}

SEC("kprobe/__x64_sys_truncate")
int kp_override_truncate(struct pt_regs *ctx)
{
	return kill_blocked_syscall();
}

SEC("kprobe/__x64_sys_ftruncate")
int kp_override_ftruncate(struct pt_regs *ctx)
{
	return kill_blocked_syscall();
}

SEC("kprobe/__x64_sys_execve")
int kp_override_execve(struct pt_regs *ctx)
{
	return kill_blocked_syscall();
}

SEC("lsm/file_open")
int BPF_PROG(enforce_file_open, struct file *file)
{
	struct block_entry *entry;

	int flags = BPF_CORE_READ(file, f_flags);
	if ((flags & O_TRUNC) || ((flags & O_ACCMODE) == O_WRONLY) || ((flags & O_ACCMODE) == O_RDWR)) {
		struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
		if (suspicious_dentry(dentry)) {
			emit_block_event(EVENT_OPEN, 0);
			return -EPERM;
		}
		entry = current_block_entry();
		if (entry) {
			emit_block_event(EVENT_OPEN, 0);
			return deny_or_kill(entry);
		}
	}
	return 0;
}

SEC("lsm/file_permission")
int BPF_PROG(enforce_file_permission, struct file *file, int mask)
{
	struct block_entry *entry;

	entry = current_block_entry();
	if ((mask & MAY_WRITE) && entry) {
		emit_block_event(EVENT_WRITE, 0);
		return deny_or_kill(entry);
	}
	return 0;
}

SEC("lsm/path_truncate")
int BPF_PROG(enforce_path_truncate, const struct path *path)
{
	struct block_entry *entry;

	entry = current_block_entry();
	if (entry) {
		emit_block_event(EVENT_TRUNCATE, 0);
		return deny_or_kill(entry);
	}
	return 0;
}

SEC("lsm/path_rename")
int BPF_PROG(enforce_path_rename, const struct path *old_dir, struct dentry *old_dentry,
	     const struct path *new_dir, struct dentry *new_dentry, unsigned int flags)
{
	struct block_entry *entry;

	if (suspicious_dentry(new_dentry)) {
		emit_block_event(EVENT_RENAME, 0);
		return -EPERM;
	}
	entry = current_block_entry();
	if (entry) {
		emit_block_event(EVENT_RENAME, 0);
		return deny_or_kill(entry);
	}
	return 0;
}

SEC("lsm/inode_rename")
int BPF_PROG(enforce_inode_rename, struct inode *old_dir, struct dentry *old_dentry,
	     struct inode *new_dir, struct dentry *new_dentry)
{
	struct block_entry *entry;

	if (suspicious_dentry(new_dentry)) {
		emit_block_event(EVENT_RENAME, 0);
		return -EPERM;
	}
	entry = current_block_entry();
	if (entry) {
		emit_block_event(EVENT_RENAME, 0);
		return deny_or_kill(entry);
	}
	return 0;
}

SEC("lsm/path_mknod")
int BPF_PROG(enforce_path_mknod, const struct path *dir, struct dentry *dentry, umode_t mode, unsigned int dev)
{
	struct block_entry *entry;

	if (suspicious_dentry(dentry)) {
		emit_block_event(EVENT_OPEN, 0);
		return -EPERM;
	}
	entry = current_block_entry();
	if (entry) {
		emit_block_event(EVENT_OPEN, 0);
		return deny_or_kill(entry);
	}
	return 0;
}

SEC("lsm/inode_create")
int BPF_PROG(enforce_inode_create, struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct block_entry *entry;

	if (suspicious_dentry(dentry)) {
		emit_block_event(EVENT_OPEN, 0);
		return -EPERM;
	}
	entry = current_block_entry();
	if (entry) {
		emit_block_event(EVENT_OPEN, 0);
		return deny_or_kill(entry);
	}
	return 0;
}

SEC("lsm/path_unlink")
int BPF_PROG(enforce_path_unlink, const struct path *dir, struct dentry *dentry)
{
	struct block_entry *entry;

	if (suspicious_dentry(dentry)) {
		emit_block_event(EVENT_UNLINK, 0);
		return -EPERM;
	}
	entry = current_block_entry();
	if (entry) {
		emit_block_event(EVENT_UNLINK, 0);
		return deny_or_kill(entry);
	}
	return 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(enforce_bprm_check_security, struct linux_binprm *bprm)
{
	struct block_entry *entry;

	entry = current_block_entry();
	if (entry) {
		emit_block_event(EVENT_EXEC, 0);
		return deny_or_kill(entry);
	}
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = new_event(EVENT_OPEN);
	if (!e)
		return 0;

	const char *filename = (const char *)ctx->args[1];
	e->arg0 = (int)ctx->args[2];
	bpf_probe_read_user_str(e->path, sizeof(e->path), filename);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int trace_write(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = new_event(EVENT_WRITE);
	if (!e)
		return 0;

	e->arg0 = (int)ctx->args[0];
	e->size = (__u64)ctx->args[2];
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat")
int trace_renameat(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = new_event(EVENT_RENAME);
	if (!e)
		return 0;

	const char *oldname = (const char *)ctx->args[1];
	const char *newname = (const char *)ctx->args[3];
	bpf_probe_read_user_str(e->path, sizeof(e->path), oldname);
	bpf_probe_read_user_str(e->path2, sizeof(e->path2), newname);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int trace_renameat2(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = new_event(EVENT_RENAME);
	if (!e)
		return 0;

	const char *oldname = (const char *)ctx->args[1];
	const char *newname = (const char *)ctx->args[3];
	e->arg0 = (int)ctx->args[4];
	bpf_probe_read_user_str(e->path, sizeof(e->path), oldname);
	bpf_probe_read_user_str(e->path2, sizeof(e->path2), newname);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = new_event(EVENT_UNLINK);
	if (!e)
		return 0;

	const char *pathname = (const char *)ctx->args[1];
	e->arg0 = (int)ctx->args[2];
	bpf_probe_read_user_str(e->path, sizeof(e->path), pathname);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_truncate")
int trace_truncate(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = new_event(EVENT_TRUNCATE);
	if (!e)
		return 0;

	const char *pathname = (const char *)ctx->args[0];
	e->size = (__u64)ctx->args[1];
	bpf_probe_read_user_str(e->path, sizeof(e->path), pathname);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_ftruncate")
int trace_ftruncate(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = new_event(EVENT_TRUNCATE);
	if (!e)
		return 0;

	e->arg0 = (int)ctx->args[0];
	e->size = (__u64)ctx->args[1];
	bpf_ringbuf_submit(e, 0);
	return 0;
}
