# Anti-ransomware Strategy

## Model

ebpffls follows a Tetragon-like pipeline:

1. **Observe** kernel activity with eBPF (tracepoints + LSM + kprobes).
2. **Normalize** events in the Go agent.
3. **Match** against policy (behavior scores, IOC rules, hash blacklist).
4. **Enforce** via BPF maps, LSM hooks, and syscall kprobes.

## Why behavior plus IOC?

Ransomware families change names, packers, and hashes quickly. Bulk file
mutation, rename loops, ransom notes, and backup destruction are harder to hide
than static signatures. ebpffls therefore uses **four complementary tracks**:

| Track | Mechanism | Best against |
|-------|-----------|--------------|
| 1 — IOC fast path | YAML-synced BPF IOC maps plus scoped BPF LSM hard deny on path-based hooks, when active | Suffix renames, ransom notes |
| 2 — Behavior slow path | Sliding-window score on protected paths | Zero-day bulk encryption |
| 3 — Hash blacklist | SHA-256 of executables in userspace | Known samples |
| 4 — Enforcement | kprobes on marked TGIDs; `bpf_override_return` deny when supported; LSM deny when active | Stopping an already-identified process |

See [ransomware-call-abstraction.md](./ransomware-call-abstraction.md) for how
syscalls map to semantic ransomware operations.

## Call surface (MVP signals)

| Syscall | Semantic op | Observation | Scoring | Enforcement |
|---------|-------------|-------------|---------|-------------|
| `execve` | Spawn | tracepoint | blacklist only | kprobe; optional LSM after mark |
| `openat` / `openat2` | Stage open | tracepoint exit | protected write-open; fd→path cache; relative dirfd resolution | kprobe; optional LSM |
| `write` / `pwrite64` / `writev` | Encrypt in-place | tracepoint | protected/backup fd path when fd was observed | kprobe after mark; optional LSM |
| `mmap` | Memory-mapped write | tracepoint | writable shared mmap on protected/backup fd when fd was observed | kprobe after mark |
| `io_uring_enter` | Async I/O activity | tracepoint | low-confidence score after prior protected file activity | optional kprobe after mark |
| `copy_file_range` | Copy into new file | tracepoint | protected/backup destination fd path when fd was observed | kprobe after mark |
| `rename` / `renameat(2)` | Suffix replace | tracepoint | protected rename; protected suspicious suffix is immediate IOC | kprobe; optional LSM IOC |
| `unlinkat` | Delete | tracepoint | protected/backup | kprobe; optional LSM |
| `truncate` / `ftruncate` | Truncate | tracepoint | protected/backup; ftruncate uses fd→path cache | kprobe; optional LSM |
| `getdents64` | Directory scan | tracepoint | protected/backup directory fd path when fd was observed | kprobe after mark |

Current `io_uring` support is intentionally conservative: the BPF side observes
`io_uring_enter`, but does not parse submission queue entries. The Go agent only
scores it after the same process already touched protected files, which keeps it
as a low-confidence evasion signal instead of a standalone block reason.

## Response levels

| Action | Behavior |
|--------|----------|
| `log` | Emit JSON alert only; do not write `blocked_tgids`. |
| `deny` | Write TGID to map; kprobe `bpf_override_return(-EPERM)` rejects marked syscalls when kernel error injection allows it; BPF LSM also returns `-EPERM` when active. |
| `kill` | Write TGID with kill action; kprobes send `SIGKILL` on sensitive syscalls; userspace also signals the process group leader. |

**Defaults today**

- Policy file `configs/ransomware.yaml`: `action: kill`
- CLI: `--dry-run=true` by default, so first runs only alert unless you pass `--dry-run=false`

Hash blacklist matches always enforce kill (independent of policy action).
Protected-scope high-confidence IOC events, such as ransom-note creation or
rename to a suspicious extension, also enforce immediately without waiting for
the behavior threshold.

At startup, the agent syncs `suspicious_extensions`, `ransom_note_names`, and
existing `protected_dirs` into BPF maps. The BPF LSM IOC path uses lower-case
filename hashes and protected directory inode/dev keys, so path-based create,
rename, and unlink hooks only hard-deny suspicious names under configured
protected directories. `file_open` keeps only marked-TGID enforcement because
full path-scoped IOC matching there exceeds verifier complexity on the reference
kernel; open/write behavior remains covered by tracepoint scoring.

On the current reference server, `CONFIG_BPF_LSM=y` is available but `bpf` is
not listed in `/sys/kernel/security/lsm`, so path-based LSM IOC hard-deny is not
active. The kernel does support `CONFIG_BPF_KPROBE_OVERRIDE` and syscall error
injection, so marked-TGID `deny` uses kprobe `bpf_override_return(-EPERM)`.
Enabling BPF LSM at boot is still required for path-scoped IOC hard-deny
behavior before userspace scoring marks a process.

## Hash blacklist

Hash matching stays in Go userspace. The agent computes SHA-256 with a
stat-based cache and compares against `blacklist_hashes` and
`blacklist_hash_files`. eBPF never reads executables or hashes files.

Triggers:

- `execve` events (async hash queue)
- Periodic `/proc` scan (`blacklist_scan`, default 5s)

## Trust Model

Trusted process exemptions start with `trusted_processes` (`comm`). When
`trusted_exe_paths` or `trusted_uids` are configured, the agent also checks
`/proc/<tgid>/exe` and the event UID before skipping scoring or blacklist scans.
This blocks simple comm spoofing where malware renames itself to a trusted
process name. Backup/snapshot destruction under `backup_dirs` is never skipped
solely because the process is trusted.

`self_protect_paths` defines agent binaries, service units, or deployment
directories that should not be modified at runtime. Write-open, fd writes,
rename, unlink, truncate/ftruncate, and writable mmap against those paths score
with `scores.self_protect` even when the process otherwise matches the trusted
identity model. This is the first self-protection layer; systemd watchdog and
read-only deployment hardening remain deployment tasks.

## Policy model (behavior track)

Within a sliding window (`window`, default 10s), per-TGID score includes:

- write-open on protected or backup paths
- write/pwrite64/writev syscalls on protected or backup file descriptors observed through open/openat/openat2
- writable shared mmap on protected or backup file descriptors
- io_uring_enter activity after prior protected file activity
- copy_file_range to protected or backup file descriptors
- truncate/ftruncate, rename, unlink on protected or backup paths
- getdents64 directory scans on protected or backup file descriptors
- self-protect path tampering, which is not bypassed by trusted process identity
- suspicious extensions and ransom note filenames on create
- backup destruction bonus
- high-rate bonus when open/write event count ≥ 64

When score ≥ `threshold` (default 45), the agent alerts and (unless dry-run)
writes the TGID into `blocked_tgids`.

Blocked lineage exec is re-blocked as a kill action. fd path-aware scoring for
write/pwrite64/writev/ftruncate uses an agent fd→path cache. The cache tracks
close, dup/fcntl duplication, and relative openat/openat2 dirfd resolution.

Long-running state is bounded: `procState`, fd→path entries, and userspace
blocked-lineage memory are pruned after an idle TTL derived from `window` and
`block_ttl`. Ring buffer reserve failures are counted in BPF and logged by the
agent as increasing `ringbuf_drops` totals.

The agent also emits periodic structured metrics logs:

```text
metrics={"schema_version":"v1","kind":"ebpffls_metrics","alerts":1,"blocks":1,"blacklist_matches":0,"ringbuf_drops_total":0}
```

Alerts are emitted as `alert={...}` JSON with `schema_version:"v1"` and
`kind:"ransomware_alert"` for downstream SIEM routing. They include a `features`
object with `distinct_paths`, `open_write_pairs`, `rename_suffix_count`, and
`encryption_state`. `encryption_state` moves to `STAGE` on fanout/staged writes
and `FINALIZE` on suspicious suffix or ransom note finalization.

YAML can define feature-threshold rules:

```yaml
rules:
  - name: fanout-distinct-paths
    feature: distinct_paths
    op: ">="
    value: 50
    action: kill
    reason: distinct path fanout rule
```

Supported features are `distinct_paths`, `open_write_pairs`, and
`rename_suffix_count`. Supported operators are `>`, `>=`, `==`, `<=`, and `<`.

**Not yet implemented:** `exec_after_blocked` as a score-only rule.

## Architecture diagram

```
Syscalls / VFS
     │
     ├─► Tracepoints ──► ringbuf ──► Go agent ──► score / blacklist
     │                                      │
     │                                      ▼
     │                               blocked_tgids map
     │
     ├─► optional LSM (IOC hard deny + marked TGID deny/kill)
     └─► kprobes (marked TGID SIGKILL or override-return deny)
```

## Next steps

See [roadmap.md](./roadmap.md) for phased development plan.
