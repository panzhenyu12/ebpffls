# Agent Replay Baselines

Run with the normal global Go caches:

```sh
go test ./internal/agent -run TestLegacyReplayBaselines -count=3
```

These synthetic, versioned fixtures are AD-00 migration baselines, not a labeled
malware dataset or a correctness specification for the adaptive engine.
`schema_version: agent-replay/v1` versions the test format independently from the
BPF wire ABI and public alert schema. `baseline: legacy-v1` selects the original
scoring/rule behavior. `known-limitation` fixtures deliberately expose behavior
that new opt-in detection must improve; `regression` fixtures protect intentional
semantics. Add separate adaptive fixtures instead of silently rewriting legacy
expectations to make a new engine pass.

Each event uses milliseconds relative to `2026-09-07T00:00:00Z`. The runner builds
a fresh agent and compares every event snapshot against the fixture, then repeats
the complete replay three times. Snapshots include score, feature values,
in-window history types, reasons, logical timestamps, FD count, alert count, and
candidate blocked state. Legacy alert emission timestamps and the wall-clock
lineage cache timestamp are deliberately outside the deterministic snapshot.
This is a deterministic detection-state replay, not an assertion that all public
JSON output already uses an injectable clock.

The runner uses dry-run mode, a nil sensor, synthetic absolute paths, and no
blacklist, trusted identity, cgroup filter, process worker, or live file access.
It never starts collection or executes a signal or BPF map update. A `blocked`
state is only the legacy dry-run candidate; `enforcement_blocks` must stay zero.
These tests do not substitute for privileged Linux load/attach/action tests.

| Fixture | Baseline observation |
|---------|----------------------|
| `legacy-log-first` | A log rule hides a later kill rule and the score threshold. |
| `legacy-kill-first` | Reordering the same rules changes the candidate action. |
| `legacy-zero-score-context` | Read-only open keeps an FD mapping but no scored history; a later attempted write can still score. |
| `legacy-open-only` | Writable open alone increments the legacy `open_write_pairs`. |
| `legacy-open-then-write` | Observing a subsequent write does not increase that feature. |
| `legacy-window-boundary` | Exactly-on-boundary events remain; older contributions expire. |

An open fixture carries a successful returned FD, matching the old open-exit
collector. A legacy write fixture is an observed syscall attempt: it does not
encode a return value, actual byte count, or proof of successful modification.
The read-only-open/write case intentionally demonstrates this blind spot. Future
v2 replay coverage must add successful, failed, zero-byte, and partial writes and
must not infer success from the request size.

Remaining AD-00 work includes failed-exec migration coverage, labeled independent
benign/attack runs, result-aware v2 fixtures, and an evaluation report. This small
suite reports scenario regressions only, not recall or false-positive rates.
