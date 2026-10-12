#ifndef EBPF_FLS_EVENTS_H
#define EBPF_FLS_EVENTS_H

#define TASK_COMM_LEN 16
#define PATH_MAX_LEN 256
#define EVENT_VERSION 2

enum event_phase {
	EVENT_PHASE_UNKNOWN = 0,
	EVENT_PHASE_ATTEMPT = 1,
	EVENT_PHASE_SUCCESS = 2,
	EVENT_PHASE_FAILURE = 3,
	EVENT_PHASE_BLOCKED = 4,
	EVENT_PHASE_OBSERVATION = 5,
};

enum event_source {
	EVENT_SOURCE_UNKNOWN = 0,
	EVENT_SOURCE_TRACEPOINT = 1,
	EVENT_SOURCE_KPROBE = 2,
	EVENT_SOURCE_LSM = 3,
	EVENT_SOURCE_SCHED = 4,
};

enum event_flags {
	EVENT_RESULT_VALID = 1,
	EVENT_REQUESTED_BYTES_VALID = 2,
	EVENT_ACTUAL_BYTES_VALID = 4,
	EVENT_SYSCALL_ID_VALID = 8,
	EVENT_VECTOR_COUNT_VALID = 16,
};

enum event_type {
	EVENT_EXEC = 1,
	EVENT_OPEN = 2,
	EVENT_WRITE = 3,
	EVENT_RENAME = 4,
	EVENT_UNLINK = 5,
	EVENT_TRUNCATE = 6,
	EVENT_BLOCK = 7,
	EVENT_CLOSE = 8,
	EVENT_DUP = 9,
	EVENT_SCAN = 10,
	EVENT_MMAP = 11,
	EVENT_IO_URING = 12,
	EVENT_CONNECT = 13,
	EVENT_LINK = 14,
};

enum block_reason {
	BLOCK_REASON_POLICY = 1,
	BLOCK_REASON_EXPIRED = 2,
	BLOCK_REASON_INLINE_IOC = 3,
};

enum block_action {
	BLOCK_ACTION_DENY = 1,
	BLOCK_ACTION_KILL = 2,
};

struct block_entry {
	__u64 expires_ns;
	__u32 reason;
	__u32 action;
};

struct event {
	__u64 ts_ns;
	__u32 pid;
	__u32 tgid;
	__u32 ppid;
	__u32 uid;
	__u32 type;
	__s32 arg0;
	__s32 arg1;
	__u64 size;
	char comm[TASK_COMM_LEN];
	char path[PATH_MAX_LEN];
	char path2[PATH_MAX_LEN];
	__u32 version;
	__u32 phase;
	__u32 source;
	__u32 flags;
	__s64 syscall_id;
	__s64 result;
	__u64 operation_id;
	__u64 requested_bytes;
	__u64 actual_bytes;
	__u32 vector_count;
	__u32 reserved;
};

#endif
