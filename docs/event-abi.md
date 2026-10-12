# Event ABI v2 and Detection Baseline

Status: first AD-00/AD-01 increment implemented and verified, 2026-09-07. This is the data foundation
for the [adaptive detection plan](./adaptive-detection-plan.md), not a completed
adaptive detection engine.

## Wire Format

The existing 576-byte event prefix is unchanged. Version 2 appends 64 bytes:

| Offset | C Type | Field | Meaning |
|--------|--------|-------|---------|
| 576 | u32 | version | 2 |
| 580 | u32 | phase | unknown, attempt, success, failure, blocked, observation |
| 584 | u32 | source | unknown, tracepoint, kprobe, LSM, sched |
| 588 | u32 | flags | Validity bits for the following optional values |
| 592 | s64 | syscall_id | Architecture-specific syscall number, when known |
| 600 | s64 | result | Observed syscall return value, including negative errno |
| 608 | u64 | operation_id | Entry monotonic timestamp for write correlation |
| 616 | u64 | requested_bytes | Scalar write/pwrite requested bytes |
| 624 | u64 | actual_bytes | Positive write return value, or zero on failure |
| 632 | u32 | vector_count | writev iovcnt, not a byte count |
| 636 | u32 | reserved | Zero |

Validity bits are result=1, requested bytes=2, actual bytes=4, syscall ID=8,
vector count=16. A zero field without its validity bit is unknown, not an
observed zero. The old `Size` field retains its type-specific meaning; in
particular, writev `Size` remains iovcnt for compatibility.

The Go decoder accepts native-endian v1 records and recognizes either byte
order for v2 from its version field. Both versions permit up to seven trailing
perf alignment bytes. Unknown versions, invalid enums/flags and invalid sizes
are rejected. Since v1 has no header, a v2 record truncated to a v1-sized record
plus padding cannot be distinguished by bytes alone; use the known transport
record size when validating archived data.

## Event Semantics

| Operation | core / legacy_perf | ultra_legacy_map |
|-----------|--------------------|------------------|
| execve entry | attempt with target path and syscall ID | attempt with target path; syscall ID unknown |
| Successful exec | sched_process_exec confirmation; path/result may be unknown | No confirmation hook; explicitly reported unavailable |
| open | Success/failure return event, result and FD | Success/failure kretprobe event, result and FD |
| write/pwrite/writev | Entry and return records, paired by thread and operation ID | Same pair through entry/return kprobes on the same symbol |
| dup/fcntl duplication | Successful return records | Not added in this increment |
| rename/unlink/truncate/close and other existing entry probes | Attempt only; no invented return value | Attempt only where supported |
| Existing inline LSM IOC | blocked, source LSM | Unavailable |

`operation_id` is not a globally unique identifier. Correlate within a thread
and capture session, and use syscall ID where available. It does not replace
the process-instance identity planned in AD-02. A sched exec confirmation proves
successful execution, not a syscall return value; its result validity bit is
not set.

The legacy scoring path still scores write attempts. Return records enrich
telemetry but do not score a second time. Failed opens cannot populate the FD
cache or increment legacy features. No new behavior model is enabled by these
fields, and successful write bytes do not prove content encryption or damage.

## Executable Identity

Exec attempts invalidate cached executable identity without adopting the
attempted target path. A sched confirmation refreshes the actual executable
from procfs, including interpreter and workload context. Until confirmation,
trust checks that require executable paths continue consulting procfs; a failed
read cannot fall back to an old trusted executable.

This conservative refresh also applies to sensors without exec confirmation.
It costs additional procfs reads after failed/unconfirmed exec and needs future
performance evaluation. Trust in the calling executable cannot suppress the
target executable's blacklist check. Process start-time keys, pidfd-bound
termination and instance-bound asynchronous hash results remain AD-02 work.

## Map Transport Integrity

The new ultra backend uses Linux 4.1-compatible ordinary ARRAY maps, with 256
CPU shards and 128 slots per shard. Each slot contains a leading sequence,
the 640-byte event and a trailing sequence, totaling 656 bytes. Event storage
is approximately 20.5 MiB, plus scratch/cursor and other maps.

Writers invalidate sequence markers, copy the payload and then publish both
markers and the CPU cursor. The reader validates commit markers and rechecks a
candidate slot before accepting it. CPU shards have independent tails; an
overrun is counted and skipped in a bounded step. Batch ordering by monotonic
timestamp is best effort, not a global ordering guarantee.

The reader retains old single-cursor slot compatibility. CPU IDs must fit the
configured shard range; they are never reduced modulo the shard count. The
ultra backend has an x86_64-specific register layout and is restricted to
amd64. Modern core/perf paths retain their existing architecture support.

Ultra syscall arguments are decoded using a per-operation ABI map configured
from the symbol actually attached: `__x64_sys_*` wraps a syscall register frame,
while `__se_sys_*` and `sys_*` use direct arguments. Entry/return pairs must attach
to the same symbol before their ABI is enabled. Unknown ABI or register-read
failure records a capture gap without publishing guessed arguments. Fixed-size
legacy path reads can still fail across an unmapped page; missing paths are not
proof that the syscall had no path.

## Incomplete Data

`ringbuf_drops_total` retains its existing meaning. The additive
`capture_gaps_total` metric reports other observable transport/association
gaps, including pending-write insertion failures and map-reader overruns.
The latter is a diagnostic gap count, not an exact number of missing complete
operations and not a guarantee that all loss mechanisms are detectable.

Pending writes are bounded. Process-exit hooks clean pending state; ultra also
detects an unmatched entry on the next write and expires returns older than
60 seconds. A long legitimate blocking write can therefore have incomplete
telemetry; it must not be interpreted as zero completed bytes.

## Reproduction

`make docker-integration-test` builds the cached test image, reuses global named
Go cache volumes, generates all six BPF objects and runs the existing Linux
test suite. It mounts tracefs/securityfs in an automatically removed privileged
container with `--pid=host`: BPF TGIDs and procfs/process operations must use the
same Linux PID namespace. An isolated container PID namespace is not supported
by the current identity/enforcement path. On Docker Desktop the shared namespace
belongs to the Linux VM, not macOS. The suite only modifies generated test files
and test processes.

The new tests cover legacy deterministic replay, ABI validation, partial and
failed writes, exec identity boundaries, failed opens and concurrent writers.
They do not establish unknown-family recall, a production false-positive rate,
performance overhead or Linux 4.1 verifier compatibility. Compiling the old ISA
and exercising the fallback on a modern kernel is not a substitute for running
on a real old kernel.

## Verified Results (2026-09-07)

Environment: Docker Desktop Linux VM, x86_64, `6.12.76-linuxkit`, with active
LSMs `capability,bpf,landlock`. The privileged test container shared the VM PID
namespace, used unlimited memlock and reused the global Go cache volumes.

| Check | Result |
|-------|--------|
| `make docker-integration-test` | Passed: generation, Go tests, systemd unit checks and the complete integration suite |
| core / legacy_perf / ultra_legacy_map | Each passed 15 controlled write cases, including partial/failed writes and four concurrent writers; 45 cases total |
| Exec identity and failed open | Passed in all three modes, with fixture-TGID-bound assertions for trusted and spoofed failed-exec attempts |
| Active BPF LSM, deny/kill, hash, scope and lineage | Existing integration assertions passed |
| rsync, tar and make benign workloads | Executed and passed, not skipped |
| `go test -race ./...` | Passed on macOS and Linux; final replay-action snapshots also passed the Linux run |
| `go vet ./...`, Bash syntax, `git diff --check` | Passed |

The only explicit integration capability skip in this environment was ultra's
sched exec confirmation, which that backend does not implement. Its exec
attempts, write results and conservative identity handling were tested.
Replay fixtures now record actual candidate action/dry-run fields as well as
state and counts, so a kill-to-deny change cannot silently match a kill baseline.

This increment does not complete P0: AD-02 process instances, instance-bound
asynchronous checks/enforcement and AD-03 evidence arbitration remain pending.
Full result coverage, window-level quality handling, temporal detectors,
workload baselines and models are not enabled. No production accuracy or
performance claim follows from these scenario regressions; arm64 and real
Linux 4.1 runtime validation remain outstanding.
