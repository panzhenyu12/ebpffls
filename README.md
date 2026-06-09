# ebpffls

`ebpffls` is a Go/eBPF anti-ransomware runtime guard inspired by Cilium Tetragon's
event, policy, and action model.

It observes Linux file and process activity with eBPF, correlates behavior in a Go
agent, and can **log**, **deny**, or **kill** offending processes.

## Design

Four complementary defense tracks:

| Track | What it does |
|-------|----------------|
| **IOC fast path** | YAML-synced BPF maps let active BPF LSM deny suspicious extensions and ransom-note filenames under protected directories |
| **Behavior scoring** | Go agent scores bulk mutation on configured protected directories |
| **Hash blacklist** | Userspace SHA-256 match against known ransomware samples |
| **Enforcement** | Marked TGIDs are killed via syscall kprobes; `deny` can use `bpf_override_return(-EPERM)` when supported; BPF LSM adds IOC hard-deny when active |

Components:

- **eBPF sensor** — tracepoints, optional BPF LSM hooks, kprobes on sensitive syscalls
- **Go agent** — ring buffer reader, sliding-window scoring, blacklist scanner, bounded process/fd state caches
- **Policy** — YAML configuration (`configs/ransomware.yaml`)

For syscall-to-semantics mapping see [docs/ransomware-call-abstraction.md](docs/ransomware-call-abstraction.md).

## Build

Requirements on the target Linux host:

- Go 1.22+
- clang/llvm
- kernel BTF at `/sys/kernel/btf/vmlinux`
- BPF LSM compiled for optional IOC hard-deny mode. Check active LSMs with:

```bash
cat /sys/kernel/security/lsm
```

If `bpf` is not listed, tracepoints, userspace scoring, hash blacklist, and
kprobe-based enforcement can still work. `deny` uses `bpf_override_return`
when the kernel enables `CONFIG_BPF_KPROBE_OVERRIDE` and allows syscall error
injection; LSM IOC hard-deny still requires active BPF LSM.

```bash
make build
```

Run Linux/root integration tests:

```bash
sudo make integration-test
```

## Run

Observation only (default — dry-run prevents kernel enforcement):

```bash
sudo ./bin/ebpffls monitor --config configs/ransomware.yaml
```

Enable enforcement after validating policies:

```bash
sudo ./bin/ebpffls monitor --config configs/ransomware.yaml --dry-run=false
```

Multiple policy files can be merged by repeating `--config`; later files append
list fields such as `protected_dirs` and override scalar defaults such as
`threshold` or `action`:

```bash
sudo ./bin/ebpffls monitor --config configs/ransomware.yaml --config team.yaml
```

Debug raw events:

```bash
sudo ./bin/ebpffls monitor --config configs/ransomware.yaml --debug-events
```

## systemd

A hardened unit template is available at `deploy/systemd/ebpffls.service`.
Typical deployment:

```bash
sudo install -m 0755 bin/ebpffls /usr/local/bin/ebpffls
sudo install -d -m 0755 /etc/ebpffls /var/lib/ebpffls
sudo install -m 0644 configs/ransomware.yaml /etc/ebpffls/ransomware.yaml
sudo install -m 0644 deploy/systemd/ebpffls.service /etc/systemd/system/ebpffls.service
sudo systemctl daemon-reload
sudo systemctl enable --now ebpffls
```

## Defaults

| Setting | Value | Notes |
|---------|-------|-------|
| Policy `action` | `kill` | in `configs/ransomware.yaml` |
| CLI `--dry-run` | `true` | enforcement off until explicitly disabled |
| `threshold` | `45` | behavior score in 10s window |
| `block_ttl` | `10m` | marked TGID expiry |

The BPF sensor counts ring buffer reserve failures in a map, and the agent logs
`ringbuf_drops total=<n> delta=<n>` when drops increase.

At startup, the agent syncs `suspicious_extensions`, `ransom_note_names`, and
existing `protected_dirs` into BPF maps for scoped LSM IOC enforcement when BPF
LSM is active.

## Policy model (behavior track)

Within a sliding window, the agent scores:

- write-open on protected paths
- write/pwrite64/writev syscalls on protected or backup file descriptors observed through open/openat/openat2
- writable shared mmap on protected or backup file descriptors
- io_uring_enter activity after prior protected file activity
- copy_file_range to protected or backup file descriptors
- getdents64 directory scans on protected or backup file descriptors
- truncate, ftruncate, rename, and unlink activity
- suspicious extensions and ransom note filenames
- backup/snapshot path destruction
- high-rate bonus when open/write count ≥ 64

When a process crosses the threshold, the agent writes its TGID into a BPF map.
Enforcement then applies via kprobes, and via LSM as well when `bpf` is active.

## Response actions

| Action | Effect |
|--------|--------|
| `log` | JSON alert only |
| `deny` | kprobe `bpf_override_return(-EPERM)` rejects marked syscalls when supported; BPF LSM also returns `-EPERM` when active |
| `kill` | kprobes send `SIGKILL` on sensitive syscalls; userspace also signals the process |

## Hash blacklist

Go computes SHA-256 in userspace (eBPF does not hash files). On match, the
agent kills immediately and marks the TGID in the kernel map.

Configure in `configs/ransomware.yaml`:

```yaml
blacklist_hash_files:
  - configs/blacklist.txt
blacklist_scan: 5s
```

File format (one SHA-256 per line):

```text
# comments allowed
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

## Trust model

Trusted process exemptions can require more than a process name:

```yaml
trusted_processes:
  - rsync
trusted_exe_paths:
  - /usr/bin/rsync
trusted_uids:
  - 0
```

If `trusted_exe_paths` or `trusted_uids` are configured, the comm allowlist must
also match those identity fields. This prevents a process from bypassing scoring
by only spoofing its comm name. Trusted exemptions do not bypass backup/snapshot
destruction scoring under `backup_dirs`.

## Documentation

| Doc | Description |
|-----|-------------|
| [docs/strategy.md](docs/strategy.md) | Architecture and response levels |
| [docs/ransomware-call-abstraction.md](docs/ransomware-call-abstraction.md) | Ransomware syscall / semantic abstraction |
| [docs/roadmap.md](docs/roadmap.md) | Development plan |
| [docs/review-consolidated.md](docs/review-consolidated.md) | Code + doc review notes |

## Limitations (current)

- kprobe attach supports architecture-specific syscall symbols for amd64 and arm64 with `__se_sys_*` fallback, but still depends on kernel symbols being available
- fd-based `write`/`pwrite64`/`writev`/`ftruncate`/`mmap`/`getdents64` scoring depends on fd→path state from observed open/openat/openat2; close/dup and relative dirfd opens are tracked
- BPF IOC maps sync from YAML, but path-scoped IOC hard-deny requires active BPF LSM
- `deny` requires syscall error-injection support for kprobe override, or active BPF LSM for LSM hooks
- io_uring support observes `io_uring_enter` only; it does not parse SQE contents
- No network egress coverage

See [docs/roadmap.md](docs/roadmap.md) for planned improvements.
