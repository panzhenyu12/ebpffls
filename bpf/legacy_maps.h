#ifndef EBPF_FLS_LEGACY_MAPS_H
#define EBPF_FLS_LEGACY_MAPS_H

/* Stable legacy map ABI; recent libbpf headers no longer define this type. */
struct bpf_map_def {
	__u32 type;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
};

#endif
