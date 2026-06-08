# Anti-ransomware Strategy

This project follows a Tetragon-like model:

1. Observe kernel events with eBPF.
2. Normalize events in a userspace agent.
3. Match events against policy.
4. Apply an action.

## Why behavior instead of signatures?

Ransomware families change names, packers, and hashes quickly. The expensive
behavior is harder to hide: bulk file mutation, rename/unlink loops, ransom note
creation, and backup destruction.

## MVP Signals

- `execve`: establish process identity and command lineage.
- `openat`: detect write/truncate intent and suspicious file names.
- `write`: measure write rate per process.
- `renameat`/`renameat2`: detect encrypted replacement patterns.
- `unlinkat`: detect destructive cleanup.
- `truncate`/`ftruncate`: detect direct file destruction.

## Response Levels

- `log`: emit structured alerts.
- `deny`: after userspace identifies a process, write its TGID into an eBPF map.
  BPF LSM hooks synchronously return `-EPERM` on later file mutation or exec
  attempts.
- `kill`: after userspace identifies a process, write its TGID into an eBPF map.
  kprobe programs on sensitive syscalls call `bpf_send_signal(SIGKILL)` when
  the marked process continues file mutation or exec activity.

Default policy uses `log` to avoid disrupting legitimate workloads.

## Hash Blacklist

Hash matching is intentionally kept in Go userspace. The agent computes SHA-256
with a stat-based cache and compares it to local policy hashes plus downloaded
hash files. eBPF stores only TGIDs that already matched a policy; it does not
read executable files or compute hashes.
