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
#define F_DUPFD 0
#define F_DUPFD_CLOEXEC 1030
#define SIGKILL 9
#define NAME_MAX_LEN 128
#define MAX_DENTRY_DEPTH 8
#define FNV_OFFSET 14695981039346656037ULL
#define FNV_PRIME 1099511628211ULL

struct dir_key {
	__u64 dev;
	__u64 ino;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} ringbuf_drops SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, struct block_entry);
} blocked_tgids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u64);
	__type(value, __u8);
} ioc_extensions SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u64);
	__type(value, __u8);
} ioc_ransom_notes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, struct dir_key);
	__type(value, __u8);
} protected_dirs SEC(".maps");

struct pending_open {
	__s32 dirfd;
	__s32 flags;
	char path[PATH_MAX_LEN];
};

struct pending_dup {
	__s32 oldfd;
	__s32 newfd;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct pending_open);
} pending_opens SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct pending_dup);
} pending_dups SEC(".maps");

static __always_inline __u32 current_ppid(void)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct task_struct *parent = BPF_CORE_READ(task, real_parent);
	return BPF_CORE_READ(parent, tgid);
}

static __always_inline void count_ringbuf_drop(void)
{
	__u32 key = 0;
	__u64 *drops = bpf_map_lookup_elem(&ringbuf_drops, &key);

	if (drops)
		__sync_fetch_and_add(drops, 1);
}

static __always_inline struct event *new_event(__u32 type)
{
	struct event *e;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 uid_gid = bpf_get_current_uid_gid();

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_ringbuf_drop();
		return 0;
	}

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

static __always_inline char lower_char(char c)
{
	if (c >= 'A' && c <= 'Z')
		return c + 32;
	return c;
}

static __always_inline int protected_path(const struct path *path)
{
	struct dentry *dentry = BPF_CORE_READ(path, dentry);

	for (__u32 i = 0; i < MAX_DENTRY_DEPTH; i++) {
		struct inode *inode;
		struct super_block *sb;
		struct dentry *parent;
		struct dir_key key = {};

		if (!dentry)
			return 0;
		inode = BPF_CORE_READ(dentry, d_inode);
		if (inode) {
			sb = BPF_CORE_READ(inode, i_sb);
			if (sb)
				key.dev = BPF_CORE_READ(sb, s_dev);
			key.ino = BPF_CORE_READ(inode, i_ino);
			if (bpf_map_lookup_elem(&protected_dirs, &key))
				return 1;
		}
		parent = BPF_CORE_READ(dentry, d_parent);
		if (!parent || parent == dentry)
			return 0;
		dentry = parent;
	}
	return 0;
}

static __always_inline int suspicious_dentry(struct dentry *dentry)
{
	const unsigned char *dname;
	__u32 len;
	__u64 full_hash = FNV_OFFSET;
	__u64 ext_hash = 0;
	__u8 has_ext = 0;

	dname = BPF_CORE_READ(dentry, d_name.name);
	if (!dname)
		return 0;
	len = BPF_CORE_READ(dentry, d_name.len);
	if (len == 0 || len >= NAME_MAX_LEN)
		return 0;

	for (__u32 i = 0; i < NAME_MAX_LEN; i++) {
		char got = 0;
		char lower;

		if (i >= len)
			break;
		if (bpf_probe_read_kernel(&got, sizeof(got), dname + i) != 0)
			return 0;
		lower = lower_char(got);
		full_hash ^= (__u8)lower;
		full_hash *= FNV_PRIME;
		if (got == '.') {
			has_ext = 1;
			ext_hash = FNV_OFFSET;
		}
		if (has_ext) {
			ext_hash ^= (__u8)lower;
			ext_hash *= FNV_PRIME;
		}
	}

	if (bpf_map_lookup_elem(&ioc_ransom_notes, &full_hash))
		return 1;
	if (has_ext && bpf_map_lookup_elem(&ioc_extensions, &ext_hash))
		return 1;
	return 0;
}

static __always_inline int suspicious_path_dentry(const struct path *path, struct dentry *dentry)
{
	return protected_path(path) && suspicious_dentry(dentry);
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

SEC("kprobe/__x64_sys_write")
int kp_override_write(struct pt_regs *ctx)
{
	return kill_blocked_syscall();
}

SEC("kprobe/__x64_sys_pwrite64")
int kp_override_pwrite64(struct pt_regs *ctx)
{
	return kill_blocked_syscall();
}

SEC("kprobe/__x64_sys_writev")
int kp_override_writev(struct pt_regs *ctx)
{
	return kill_blocked_syscall();
}

SEC("kprobe/__x64_sys_copy_file_range")
int kp_override_copy_file_range(struct pt_regs *ctx)
{
	return kill_blocked_syscall();
}

SEC("lsm/file_open")
int BPF_PROG(enforce_file_open, struct file *file)
{
	struct block_entry *entry;

	int flags = BPF_CORE_READ(file, f_flags);
	if ((flags & O_TRUNC) || ((flags & O_ACCMODE) == O_WRONLY) || ((flags & O_ACCMODE) == O_RDWR)) {
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

	if (suspicious_path_dentry(new_dir, new_dentry)) {
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

	if (suspicious_path_dentry(dir, dentry)) {
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

	if (suspicious_path_dentry(dir, dentry)) {
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
	struct pending_open pending = {};
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	const char *filename = (const char *)ctx->args[1];
	pending.dirfd = (int)ctx->args[0];
	pending.flags = (int)ctx->args[2];
	bpf_probe_read_user_str(pending.path, sizeof(pending.path), filename);
	bpf_map_update_elem(&pending_opens, &pid_tgid, &pending, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int trace_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct pending_open *pending = bpf_map_lookup_elem(&pending_opens, &pid_tgid);
	if (!pending)
		return 0;

	int fd = (int)ctx->ret;
	if (fd >= 0) {
		struct event *e = new_event(EVENT_OPEN);
		if (e) {
			e->arg0 = pending->flags;
			e->arg1 = fd;
			e->size = (__u64)(__u32)pending->dirfd;
			__builtin_memcpy(e->path, pending->path, sizeof(e->path));
			bpf_ringbuf_submit(e, 0);
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
	struct open_how *how = (struct open_how *)ctx->args[2];

	const char *filename = (const char *)ctx->args[1];
	pending.dirfd = (int)ctx->args[0];
	bpf_probe_read_user_str(pending.path, sizeof(pending.path), filename);
	bpf_probe_read_user(&pending.flags, sizeof(pending.flags), &how->flags);
	bpf_map_update_elem(&pending_opens, &pid_tgid, &pending, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat2")
int trace_openat2_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct pending_open *pending = bpf_map_lookup_elem(&pending_opens, &pid_tgid);
	if (!pending)
		return 0;

	int fd = (int)ctx->ret;
	if (fd >= 0) {
		struct event *e = new_event(EVENT_OPEN);
		if (e) {
			e->arg0 = pending->flags;
			e->arg1 = fd;
			e->size = (__u64)(__u32)pending->dirfd;
			__builtin_memcpy(e->path, pending->path, sizeof(e->path));
			bpf_ringbuf_submit(e, 0);
		}
	}
	bpf_map_delete_elem(&pending_opens, &pid_tgid);
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

SEC("tracepoint/syscalls/sys_enter_pwrite64")
int trace_pwrite64(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = new_event(EVENT_WRITE);
	if (!e)
		return 0;

	e->arg0 = (int)ctx->args[0];
	e->size = (__u64)ctx->args[2];
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_writev")
int trace_writev(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = new_event(EVENT_WRITE);
	if (!e)
		return 0;

	e->arg0 = (int)ctx->args[0];
	e->size = (__u64)ctx->args[2];
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_copy_file_range")
int trace_copy_file_range(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = new_event(EVENT_WRITE);
	if (!e)
		return 0;

	e->arg0 = (int)ctx->args[2];
	e->size = (__u64)ctx->args[4];
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int trace_close(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = new_event(EVENT_CLOSE);
	if (!e)
		return 0;

	e->arg0 = (int)ctx->args[0];
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_dup")
int trace_dup(struct trace_event_raw_sys_enter *ctx)
{
	struct pending_dup pending = {};
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	pending.oldfd = (int)ctx->args[0];
	pending.newfd = -1;
	bpf_map_update_elem(&pending_dups, &pid_tgid, &pending, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_dup")
int trace_dup_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct pending_dup *pending = bpf_map_lookup_elem(&pending_dups, &pid_tgid);
	if (!pending)
		return 0;

	int newfd = (int)ctx->ret;
	if (newfd >= 0) {
		struct event *e = new_event(EVENT_DUP);
		if (e) {
			e->arg0 = pending->oldfd;
			e->arg1 = newfd;
			bpf_ringbuf_submit(e, 0);
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

	pending.oldfd = (int)ctx->args[0];
	pending.newfd = (int)ctx->args[1];
	bpf_map_update_elem(&pending_dups, &pid_tgid, &pending, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_dup2")
int trace_dup2_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct pending_dup *pending = bpf_map_lookup_elem(&pending_dups, &pid_tgid);
	if (!pending)
		return 0;

	int newfd = (int)ctx->ret;
	if (newfd >= 0) {
		struct event *e = new_event(EVENT_DUP);
		if (e) {
			e->arg0 = pending->oldfd;
			e->arg1 = newfd;
			bpf_ringbuf_submit(e, 0);
		}
	}
	bpf_map_delete_elem(&pending_dups, &pid_tgid);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_dup3")
int trace_dup3(struct trace_event_raw_sys_enter *ctx)
{
	struct pending_dup pending = {};
	__u64 pid_tgid = bpf_get_current_pid_tgid();

	pending.oldfd = (int)ctx->args[0];
	pending.newfd = (int)ctx->args[1];
	bpf_map_update_elem(&pending_dups, &pid_tgid, &pending, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_dup3")
int trace_dup3_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct pending_dup *pending = bpf_map_lookup_elem(&pending_dups, &pid_tgid);
	if (!pending)
		return 0;

	int newfd = (int)ctx->ret;
	if (newfd >= 0) {
		struct event *e = new_event(EVENT_DUP);
		if (e) {
			e->arg0 = pending->oldfd;
			e->arg1 = newfd;
			bpf_ringbuf_submit(e, 0);
		}
	}
	bpf_map_delete_elem(&pending_dups, &pid_tgid);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fcntl")
int trace_fcntl(struct trace_event_raw_sys_enter *ctx)
{
	struct pending_dup pending = {};
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	int cmd = (int)ctx->args[1];

	if (cmd != F_DUPFD && cmd != F_DUPFD_CLOEXEC)
		return 0;

	pending.oldfd = (int)ctx->args[0];
	pending.newfd = -1;
	bpf_map_update_elem(&pending_dups, &pid_tgid, &pending, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_fcntl")
int trace_fcntl_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct pending_dup *pending = bpf_map_lookup_elem(&pending_dups, &pid_tgid);
	if (!pending)
		return 0;

	int newfd = (int)ctx->ret;
	if (newfd >= 0) {
		struct event *e = new_event(EVENT_DUP);
		if (e) {
			e->arg0 = pending->oldfd;
			e->arg1 = newfd;
			bpf_ringbuf_submit(e, 0);
		}
	}
	bpf_map_delete_elem(&pending_dups, &pid_tgid);
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

SEC("tracepoint/syscalls/sys_enter_rename")
int trace_rename(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = new_event(EVENT_RENAME);
	if (!e)
		return 0;

	const char *oldname = (const char *)ctx->args[0];
	const char *newname = (const char *)ctx->args[1];
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

SEC("tracepoint/syscalls/sys_enter_unlink")
int trace_unlink(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = new_event(EVENT_UNLINK);
	if (!e)
		return 0;

	const char *pathname = (const char *)ctx->args[0];
	bpf_probe_read_user_str(e->path, sizeof(e->path), pathname);
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
