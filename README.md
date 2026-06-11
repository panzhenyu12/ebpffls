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

- **eBPF sensor** — CO-RE tracepoints, no-CO-RE legacy probes, optional BPF LSM hooks, and kprobes on sensitive syscalls
- **Go agent** — ringbuf/perf/map-polling event readers, sliding-window scoring, blacklist scanner, bounded process/fd state caches
- **Policy** — YAML configuration (`configs/ransomware.yaml`)

For syscall-to-semantics mapping see [docs/ransomware-call-abstraction.md](docs/ransomware-call-abstraction.md).
For the one-build multi-kernel compatibility plan see [docs/kernel-compatibility.md](docs/kernel-compatibility.md).

## Build

Requirements on the build host:

- Go 1.22+
- clang/llvm

Requirements on the target Linux host:

- root privileges and eBPF support
- kernel BTF at `/sys/kernel/btf/vmlinux`, or `EBPFFLS_BTF` pointing at a matching BTF file, for the modern CO-RE runtime path; kernels without target BTF fall back to embedded no-CO-RE legacy runtime paths
- BPF LSM compiled for optional IOC hard-deny mode. Check active LSMs with:

```bash
cat /sys/kernel/security/lsm
```

If `bpf` is not listed, tracepoints, userspace scoring, hash blacklist, and
kprobe-based enforcement can still work. `deny` uses `bpf_override_return`
when the kernel enables `CONFIG_BPF_KPROBE_OVERRIDE` and allows syscall error
injection; LSM IOC hard-deny still requires active BPF LSM.

The build embeds three BPF runtime objects: modern `core`, `legacy_perf`, and
`ultra_legacy_map`. Runtime mode is selected automatically so the same binary
can run across supported kernel branches without rebuilding on the target host.
Use `EBPFFLS_BPF_MODE=core|legacy_perf|ultra_legacy_map|auto` to force a path
for debugging; the old `legacy` value is accepted as `legacy_perf`.
`core` still needs target-kernel BTF for CO-RE relocation. Without BTF, the
loader uses the already embedded no-CO-RE objects; it does not compile BPF on
the target host.

```bash
make build
```

Run Linux/root integration tests:

```bash
sudo make integration-test
```

The integration suite includes `tests/ransomware_sim.py`, a small reusable
ransomware-like workload simulator used to exercise fanout writes, suspicious
suffix renames, and ransom-note creation paths.

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

Set `cgroup_paths` in a policy to scope scoring and blacklist scanning to
matching `/proc/<tgid>/cgroup` prefixes. Empty `cgroup_paths` means global
coverage. When configured, the agent also syncs matching cgroup v2 IDs into BPF
so scoped-out tracepoint events are filtered before reaching the ring buffer.

Debug raw events:

```bash
sudo ./bin/ebpffls monitor --config configs/ransomware.yaml --debug-events
```

## systemd

A hardened unit template is available at `deploy/systemd/ebpffls.service`.
It uses systemd notify readiness and `WatchdogSec=30s`; the agent sends
`READY=1` after the eBPF sensor is attached and then emits watchdog heartbeats
when `NOTIFY_SOCKET` and `WATCHDOG_USEC` are provided by systemd.
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
- optional IPv4/IPv6 network egress after prior protected file activity
- truncate, ftruncate, rename, and unlink activity
- hardlink and symlink creation or replacement activity
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
| `kill` | userspace signals the process; modern kprobe/LSM paths add kernel-side kill when supported |

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
| [docs/kernel-compatibility.md](docs/kernel-compatibility.md) | One-build kernel compatibility and CO-RE/legacy plan |
| [docs/roadmap.md](docs/roadmap.md) | Development plan |
| [docs/review-consolidated.md](docs/review-consolidated.md) | Code + doc review notes |

## Limitations (current)

- kprobe attach supports architecture-specific syscall symbols for amd64 and arm64 with `__se_sys_*` fallback, but still depends on kernel symbols being available
- fd-based `write`/`pwrite64`/`writev`/`ftruncate`/`mmap`/`getdents64` scoring depends on fd→path state from observed open/openat/openat2; close/dup and relative dirfd opens are tracked
- BPF IOC maps sync from YAML, but path-scoped IOC hard-deny requires active BPF LSM
- `deny` requires syscall error-injection support for kprobe override, or active BPF LSM for LSM hooks
- `ultra_legacy_map` targets the 4.1+ kprobe baseline and uses map polling, so it prioritizes core coverage over event-channel throughput; real coverage still depends on the target kernel's BPF syscall, kprobe/ftrace support, and exported syscall symbols
- io_uring support observes `io_uring_enter` only; it does not parse SQE contents
- Network egress coverage is limited to optional IPv4/IPv6 `connect(2)` scoring after protected file activity; payload inspection and destination reputation are out of scope

See [docs/roadmap.md](docs/roadmap.md) for planned improvements.
