# ebpffls

`ebpffls` is a Go/eBPF anti-ransomware runtime guard inspired by Cilium Tetragon's
event, policy, and action model.

It observes Linux file and process activity with eBPF, correlates behavior in a Go
agent, and can **log**, **deny**, or **kill** offending processes.

## Design

Four complementary defense tracks:

| Track | What it does |
|-------|----------------|
| **IOC fast path** | BPF LSM can instantly deny suspicious extensions and ransom-note filenames when `bpf` LSM is active |
| **Behavior scoring** | Go agent scores bulk mutation on configured protected directories |
| **Hash blacklist** | Userspace SHA-256 match against known ransomware samples |
| **Enforcement** | Marked TGIDs are killed via x86_64 syscall kprobes; BPF LSM adds deny semantics when active |

Components:

- **eBPF sensor** — tracepoints, optional BPF LSM hooks, kprobes on sensitive syscalls
- **Go agent** — ring buffer reader, sliding-window scoring, blacklist scanner
- **Policy** — YAML configuration (`configs/ransomware.yaml`)

For syscall-to-semantics mapping see [docs/ransomware-call-abstraction.md](docs/ransomware-call-abstraction.md).

## Build

Requirements on the target Linux host:

- Go 1.22+
- clang/llvm
- kernel BTF at `/sys/kernel/btf/vmlinux`
- BPF LSM compiled for optional `deny` / IOC hard-deny mode. Check active LSMs with:

```bash
cat /sys/kernel/security/lsm
```

If `bpf` is not listed, tracepoints, userspace scoring, hash blacklist, and
kprobe-based `kill` enforcement can still work; LSM `deny` and IOC hard-deny
will not be active.

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

Debug raw events:

```bash
sudo ./bin/ebpffls monitor --config configs/ransomware.yaml --debug-events
```

## Defaults

| Setting | Value | Notes |
|---------|-------|-------|
| Policy `action` | `kill` | in `configs/ransomware.yaml` |
| CLI `--dry-run` | `true` | enforcement off until explicitly disabled |
| `threshold` | `45` | behavior score in 10s window |
| `block_ttl` | `10m` | marked TGID expiry |

## Policy model (behavior track)

Within a sliding window, the agent scores:

- write-open on protected paths
- truncate, rename, and unlink activity
- suspicious extensions and ransom note filenames
- backup/snapshot path destruction
- high-rate bonus when open/write count ≥ 64

When a process crosses the threshold, the agent writes its TGID into a BPF map.
Enforcement then applies via kprobes, and via LSM as well when `bpf` is active.

> **Note:** `write` syscalls are observed but not yet scored. See the roadmap.

## Response actions

| Action | Effect |
|--------|--------|
| `log` | JSON alert only |
| `deny` | LSM returns `-EPERM` for marked TGID when BPF LSM is active |
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

## Documentation

| Doc | Description |
|-----|-------------|
| [docs/strategy.md](docs/strategy.md) | Architecture and response levels |
| [docs/ransomware-call-abstraction.md](docs/ransomware-call-abstraction.md) | Ransomware syscall / semantic abstraction |
| [docs/roadmap.md](docs/roadmap.md) | Development plan |
| [docs/review-consolidated.md](docs/review-consolidated.md) | Code + doc review notes |

## Limitations (current)

- x86_64 kprobe symbols only
- `write` is in kprobe enforcement for already-marked TGIDs, but is not path-scored in agent
- BPF IOC rules hardcoded; not fully synced with YAML; require active BPF LSM
- `deny` requires active BPF LSM (`bpf` in `/sys/kernel/security/lsm`)
- No mmap / io_uring / network egress coverage

See [docs/roadmap.md](docs/roadmap.md) for planned improvements.
