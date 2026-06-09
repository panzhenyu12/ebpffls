package agent

import (
	"testing"
	"time"

	"github.com/panzhenyu/ebpffls/internal/config"
	"github.com/panzhenyu/ebpffls/internal/sensor"
)

func TestPruneIdleRemovesOldProcFDAndBlockedState(t *testing.T) {
	now := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	old := now.Add(-2 * time.Minute)
	fresh := now.Add(-30 * time.Second)
	a := &Agent{
		policy: config.Policy{
			Window:   10 * time.Second,
			BlockTTL: 30 * time.Second,
		},
		procs: map[uint32]*procState{
			100: {TGID: 100, LastSeen: old},
			101: {TGID: 101, LastSeen: fresh},
		},
		fdPaths: map[fdKey]fdState{
			{TGID: 100, FD: 3}: {Path: "/protected/old", LastSeen: old},
			{TGID: 101, FD: 4}: {Path: "/protected/fresh", LastSeen: fresh},
		},
		blocked: map[uint32]time.Time{
			100: old,
			101: fresh,
		},
	}

	a.pruneIdle(now)

	if _, ok := a.procs[100]; ok {
		t.Fatal("stale proc state was not pruned")
	}
	if _, ok := a.procs[101]; !ok {
		t.Fatal("fresh proc state was pruned")
	}
	if _, ok := a.fdPaths[fdKey{TGID: 100, FD: 3}]; ok {
		t.Fatal("stale fd state was not pruned")
	}
	if _, ok := a.fdPaths[fdKey{TGID: 101, FD: 4}]; !ok {
		t.Fatal("fresh fd state was pruned")
	}
	if _, ok := a.blocked[100]; ok {
		t.Fatal("stale blocked lineage state was not pruned")
	}
	if _, ok := a.blocked[101]; !ok {
		t.Fatal("fresh blocked lineage state was pruned")
	}
}

func TestPruneIdleHonorsBlockTTLWhenLongerThanWindow(t *testing.T) {
	now := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	a := &Agent{
		policy: config.Policy{
			Window:   10 * time.Second,
			BlockTTL: 10 * time.Minute,
		},
		procs: map[uint32]*procState{
			100: {TGID: 100, LastSeen: now.Add(-5 * time.Minute)},
			101: {TGID: 101, LastSeen: now.Add(-11 * time.Minute)},
		},
		fdPaths: map[fdKey]fdState{},
		blocked: map[uint32]time.Time{},
	}

	a.pruneIdle(now)

	if _, ok := a.procs[100]; !ok {
		t.Fatal("proc state inside block_ttl was pruned")
	}
	if _, ok := a.procs[101]; ok {
		t.Fatal("proc state older than block_ttl was not pruned")
	}
}

func TestTouchFDRefreshesLastSeenAndReturnsPath(t *testing.T) {
	old := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	seen := old.Add(5 * time.Second)
	a := &Agent{
		fdPaths: map[fdKey]fdState{
			{TGID: 42, FD: 7}: {Path: "/protected/data", LastSeen: old},
		},
	}

	path := a.touchFD(42, 7, seen)

	if path != "/protected/data" {
		t.Fatalf("touchFD path = %q, want /protected/data", path)
	}
	state := a.fdPaths[fdKey{TGID: 42, FD: 7}]
	if !state.LastSeen.Equal(seen) {
		t.Fatalf("LastSeen = %s, want %s", state.LastSeen, seen)
	}
}

func TestRingbufDropDeltaReportsOnlyIncrements(t *testing.T) {
	a := &Agent{}

	if delta := a.ringbufDropDelta(7); delta != 7 {
		t.Fatalf("first delta = %d, want 7", delta)
	}
	if delta := a.ringbufDropDelta(10); delta != 3 {
		t.Fatalf("second delta = %d, want 3", delta)
	}
	if a.metrics.RingbufDropsTotal != 10 {
		t.Fatalf("RingbufDropsTotal = %d, want 10", a.metrics.RingbufDropsTotal)
	}
	if delta := a.ringbufDropDelta(2); delta != 2 {
		t.Fatalf("reset delta = %d, want 2", delta)
	}
}

func TestMetricsIntervalBounds(t *testing.T) {
	a := &Agent{policy: config.Policy{Window: time.Second}}
	if got := a.metricsInterval(); got != 10*time.Second {
		t.Fatalf("metricsInterval small = %s, want 10s", got)
	}
	a.policy.Window = 2 * time.Minute
	if got := a.metricsInterval(); got != time.Minute {
		t.Fatalf("metricsInterval large = %s, want 1m", got)
	}
}

func TestRecordFeaturesTracksDistinctOpenWriteAndRenameSuffix(t *testing.T) {
	a := &Agent{
		policy: config.Policy{
			SuspiciousExtensions: []string{".locked"},
		},
	}
	state := &procState{}

	a.recordFeatures(state, sensor.Event{
		Type: sensor.EventOpen,
		Arg0: 1,
		Path: "/protected/a.txt",
	})
	a.recordFeatures(state, sensor.Event{
		Type:  sensor.EventRename,
		Path:  "/protected/a.txt",
		Path2: "/protected/a.txt.locked",
	})

	if state.Features.DistinctPaths != 2 {
		t.Fatalf("DistinctPaths = %d, want 2", state.Features.DistinctPaths)
	}
	if state.Features.OpenWritePairs != 1 {
		t.Fatalf("OpenWritePairs = %d, want 1", state.Features.OpenWritePairs)
	}
	if state.Features.RenameSuffixCount != 1 {
		t.Fatalf("RenameSuffixCount = %d, want 1", state.Features.RenameSuffixCount)
	}
}

func TestPruneResetsFeatures(t *testing.T) {
	a := &Agent{
		policy: config.Policy{Window: time.Second},
	}
	state := &procState{
		FirstSeen: time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC),
		Features: procFeatures{
			DistinctPaths:     3,
			OpenWritePairs:    2,
			RenameSuffixCount: 1,
			EncryptionState:   "STAGE",
		},
		seenPaths: map[string]struct{}{
			"/protected/a": {},
		},
		openWritePaths: map[string]struct{}{
			"/protected/a": {},
		},
	}

	a.prune(state, state.FirstSeen.Add(2*time.Second))

	if state.Features != (procFeatures{}) {
		t.Fatalf("features = %+v, want zero", state.Features)
	}
	if len(state.seenPaths) != 0 {
		t.Fatalf("seenPaths len = %d, want 0", len(state.seenPaths))
	}
	if len(state.openWritePaths) != 0 {
		t.Fatalf("openWritePaths len = %d, want 0", len(state.openWritePaths))
	}
}

func TestEncryptionStateMachineStageAndFinalize(t *testing.T) {
	a := &Agent{
		policy: config.Policy{
			SuspiciousExtensions: []string{".locked"},
		},
	}
	state := &procState{}

	for _, path := range []string{"/protected/a", "/protected/b", "/protected/c"} {
		a.recordFeatures(state, sensor.Event{Type: sensor.EventOpen, Arg0: 1, Path: path})
	}
	if state.Features.EncryptionState != "STAGE" {
		t.Fatalf("EncryptionState = %q, want STAGE", state.Features.EncryptionState)
	}

	a.recordFeatures(state, sensor.Event{
		Type:  sensor.EventRename,
		Path:  "/protected/c",
		Path2: "/protected/c.locked",
	})
	if state.Features.EncryptionState != "FINALIZE" {
		t.Fatalf("EncryptionState = %q, want FINALIZE", state.Features.EncryptionState)
	}
}

func TestRuleMatchesFeatureThreshold(t *testing.T) {
	rule := config.Rule{Feature: "distinct_paths", Op: ">=", Value: 3, Action: "kill"}
	if !ruleMatches(procFeatures{DistinctPaths: 3}, rule) {
		t.Fatal("rule did not match equal threshold")
	}
	if ruleMatches(procFeatures{DistinctPaths: 2}, rule) {
		t.Fatal("rule matched below threshold")
	}
}

func TestMatchRuleReturnsFirstMatchingRule(t *testing.T) {
	a := &Agent{
		policy: config.Policy{
			Rules: []config.Rule{
				{Feature: "open_write_pairs", Op: ">=", Value: 9, Action: "kill", Reason: "too many opens"},
				{Feature: "distinct_paths", Op: ">=", Value: 2, Action: "deny", Reason: "fanout rule"},
			},
		},
	}
	state := &procState{Features: procFeatures{DistinctPaths: 2, OpenWritePairs: 1}}

	matched, reason, action := a.matchRule(state)
	if !matched {
		t.Fatal("expected rule match")
	}
	if reason != "fanout rule" || action != "deny" {
		t.Fatalf("reason/action = %q/%q, want fanout rule/deny", reason, action)
	}
}
