# ebpffls

`ebpffls` is a Go/eBPF anti-ransomware prototype inspired by Cilium Tetragon's
event, policy, and action model.

It observes Linux runtime behavior with eBPF, correlates file activity in a Go
agent, scores suspicious ransomware-like behavior, and can log, deny, or kill
offending processes.

## Design

- eBPF sensor: low-overhead syscall tracepoints for process and file activity.
- Go agent: ring buffer reader, process/file behavior correlation, sliding-window scoring.
- Policy: YAML configuration similar in spirit to Tetragon tracing policies.
- Actions: `log`, `deny`, or `kill`.

The first version is deliberately conservative: it defaults to `log` mode.

## Build

Requirements on the target Linux host:

- Go 1.22+
- clang/llvm
- kernel BTF at `/sys/kernel/btf/vmlinux`

```bash
make build
```

## Run

```bash
sudo ./bin/ebpffls monitor --config configs/ransomware.yaml
```

Set policy `action: deny` or `action: kill`, then use `--dry-run=false` only
after validating policies in your environment.

```bash
sudo ./bin/ebpffls monitor --config configs/ransomware.yaml --dry-run=false
```

## Policy Model

The default policy scores behavior within a sliding window:

- high-rate writes to protected paths
- truncate, rename, and unlink activity
- suspicious extensions
- ransom note filenames
- backup/snapshot destruction

When a process crosses a policy threshold, the agent writes its TGID into an
eBPF map. The current primary enforcement mode is `kill`: eBPF kprobes call
`bpf_send_signal(SIGKILL)` when the marked process hits sensitive file or exec
syscalls again. `deny` is wired for BPF LSM environments and will be expanded
with `bpf_override_return` after the kill path is stable.

## Hash Blacklist

Go computes SHA-256 hashes in userspace and compares them with local or
downloaded blacklist files. eBPF never computes file hashes. When a hash matches,
the agent writes the TGID into the kernel map and immediately sends SIGKILL;
subsequent sensitive syscalls are also killed from eBPF.

Blacklist file format:

```text
# one SHA-256 per line
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```
