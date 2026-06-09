package agent

import (
	"testing"
	"time"

	"github.com/panzhenyu/ebpffls/internal/config"
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
	if delta := a.ringbufDropDelta(2); delta != 2 {
		t.Fatalf("reset delta = %d, want 2", delta)
	}
}
