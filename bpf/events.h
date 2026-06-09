#ifndef EBPF_FLS_EVENTS_H
#define EBPF_FLS_EVENTS_H

#define TASK_COMM_LEN 16
#define PATH_MAX_LEN 256

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
};

#endif
