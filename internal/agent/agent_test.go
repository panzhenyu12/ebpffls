package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/panzhenyu/ebpffls/internal/config"
	"github.com/panzhenyu/ebpffls/internal/sensor"
)

func TestAlertSchemaFields(t *testing.T) {
	data, err := json.Marshal(alert{
		SchemaVersion: "v1",
		Kind:          "ransomware_alert",
		Policy:        "test",
		Action:        "kill",
		Reasons:       []string{"behavior threshold"},
		Features:      procFeatures{DistinctPaths: 3},
	})
	if err != nil {
		t.Fatalf("marshal alert: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal alert: %v", err)
	}
	if got["schema_version"] != "v1" {
		t.Fatalf("schema_version = %v, want v1", got["schema_version"])
	}
	if got["kind"] != "ransomware_alert" {
		t.Fatalf("kind = %v, want ransomware_alert", got["kind"])
	}
	if _, ok := got["features"].(map[string]any); !ok {
		t.Fatalf("features missing or wrong type: %#v", got["features"])
	}
}

func TestMetricsSchemaFields(t *testing.T) {
	data, err := json.Marshal(metrics{
		SchemaVersion:     "v1",
		Kind:              "ebpffls_metrics",
		Alerts:            1,
		Blocks:            2,
		BlacklistMatches:  3,
		RingbufDropsTotal: 4,
	})
	if err != nil {
		t.Fatalf("marshal metrics: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal metrics: %v", err)
	}
	if got["schema_version"] != "v1" {
		t.Fatalf("schema_version = %v, want v1", got["schema_version"])
	}
	if got["kind"] != "ebpffls_metrics" {
		t.Fatalf("kind = %v, want ebpffls_metrics", got["kind"])
	}
	if got["alerts"] != float64(1) || got["blocks"] != float64(2) {
		t.Fatalf("metrics counters missing: %#v", got)
	}
}

func TestParseCgroupPath(t *testing.T) {
	got := parseCgroupPath("0::/user.slice/session.scope\n")
	if got != "/user.slice/session.scope" {
		t.Fatalf("cgroup path = %q", got)
	}
}

func TestMatchesCgroupPath(t *testing.T) {
	if !matchesCgroupPath("/user.slice/session.scope", []string{"/user.slice"}) {
		t.Fatal("expected cgroup prefix match")
	}
	if matchesCgroupPath("/system.slice/ssh.service", []string{"/user.slice"}) {
		t.Fatal("unexpected cgroup match")
	}
	if !matchesCgroupPath("/system.slice/ssh.service", []string{"/"}) {
		t.Fatal("root cgroup prefix should match all absolute paths")
	}
}

func TestRootDirectoryPrefixMatchesAbsolutePaths(t *testing.T) {
	if !hasDirPrefix("/var/lib/data", []string{"/"}) {
		t.Fatal("root directory prefix should match absolute paths")
	}
	if !matchesAnyPath("/usr/bin/tool", []string{"/"}) {
		t.Fatal("root path candidate should match absolute paths")
	}
}

func TestProcInPolicyCgroup(t *testing.T) {
	a := &Agent{policy: config.Policy{CgroupPaths: []string{"/allowed"}}}
	if !a.procInPolicyCgroup(procInfo{Cgroup: "/allowed/app.scope"}) {
		t.Fatal("expected proc in policy cgroup")
	}
	if a.procInPolicyCgroup(procInfo{Cgroup: "/other/app.scope"}) {
		t.Fatal("unexpected proc in policy cgroup")
	}
}

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
		procInfos: map[uint32]cachedProcInfo{
			100: {Info: procInfo{TGID: 100, Exe: "/usr/bin/tar"}, LastSeen: old},
			101: {Info: procInfo{TGID: 101, Exe: "/usr/bin/tar"}, LastSeen: fresh},
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
	if _, ok := a.procInfos[100]; ok {
		t.Fatal("stale proc info was not pruned")
	}
	if _, ok := a.procInfos[101]; !ok {
		t.Fatal("fresh proc info was pruned")
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

func TestScoreDirectoryScanUsesFDPath(t *testing.T) {
	a := &Agent{
		policy: config.Policy{
			ProtectedDirs: []string{"/protected"},
			Scores:        config.Scores{Scan: 2},
		},
		fdPaths: map[fdKey]fdState{
			{TGID: 42, FD: 3}: {Path: "/protected"},
		},
	}

	score, reason := a.score(sensor.Event{
		Type: sensor.EventScan,
		TGID: 42,
		Arg0: 3,
	})

	if score != 2 {
		t.Fatalf("score = %d, want 2", score)
	}
	if reason != "directory scan in protected scope" {
		t.Fatalf("reason = %q", reason)
	}
}

func TestScoreWritableMmapUsesFDPath(t *testing.T) {
	a := &Agent{
		policy: config.Policy{
			ProtectedDirs: []string{"/protected"},
			Scores:        config.Scores{Mmap: 4},
		},
		fdPaths: map[fdKey]fdState{
			{TGID: 42, FD: 3}: {Path: "/protected/data.bin"},
		},
	}

	score, reason := a.score(sensor.Event{
		Type: sensor.EventMmap,
		TGID: 42,
		Arg0: 3,
	})

	if score != 4 {
		t.Fatalf("score = %d, want 4", score)
	}
	if reason != "writable mmap in protected scope" {
		t.Fatalf("reason = %q", reason)
	}
}

func TestScoreIOUringRequiresPriorProtectedActivity(t *testing.T) {
	a := &Agent{
		policy: config.Policy{Scores: config.Scores{IOUring: 2}},
		procs: map[uint32]*procState{
			42: {Features: procFeatures{DistinctPaths: 1}},
			43: {},
		},
	}

	score, reason := a.score(sensor.Event{Type: sensor.EventIOUring, TGID: 42})
	if score != 2 {
		t.Fatalf("score = %d, want 2", score)
	}
	if reason != "io_uring activity after protected file activity" {
		t.Fatalf("reason = %q", reason)
	}
	score, _ = a.score(sensor.Event{Type: sensor.EventIOUring, TGID: 43})
	if score != 0 {
		t.Fatalf("score without prior activity = %d, want 0", score)
	}
}

func TestScoreNetworkEgressHonorsAllowlist(t *testing.T) {
	a := &Agent{
		policy: config.Policy{
			NetworkEgress: config.NetworkEgress{
				Enabled:     true,
				Score:       6,
				AllowedCIDR: []string{"127.0.0.0/8"},
				AllowedPort: []int{443},
			},
		},
		procs: map[uint32]*procState{
			42: {Features: procFeatures{DistinctPaths: 1}},
		},
	}

	score, reason := a.score(sensor.Event{Type: sensor.EventConnect, TGID: 42, Arg0: int32(0x08080808), Arg1: 4444})
	if score != 6 {
		t.Fatalf("score = %d, want 6", score)
	}
	if reason != "network egress after suspicious activity" {
		t.Fatalf("reason = %q", reason)
	}
	score, _ = a.score(sensor.Event{Type: sensor.EventConnect, TGID: 42, Arg0: int32(0x0100007f), Arg1: 4444})
	if score != 0 {
		t.Fatalf("loopback score = %d, want 0", score)
	}
	score, _ = a.score(sensor.Event{Type: sensor.EventConnect, TGID: 42, Arg0: int32(0x08080808), Arg1: 443})
	if score != 0 {
		t.Fatalf("allowed port score = %d, want 0", score)
	}
	score, _ = a.score(sensor.Event{Type: sensor.EventConnect, TGID: 42, Size: 99, Arg1: 4444})
	if score != 0 {
		t.Fatalf("unsupported family score = %d, want 0", score)
	}
}

func TestScoreNetworkEgressHonorsIPv6Allowlist(t *testing.T) {
	a := &Agent{
		policy: config.Policy{
			NetworkEgress: config.NetworkEgress{
				Enabled:     true,
				Score:       6,
				AllowedCIDR: []string{"::1/128"},
			},
		},
		procs: map[uint32]*procState{
			42: {Features: procFeatures{DistinctPaths: 1}},
		},
	}

	loopback := string([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	score, _ := a.score(sensor.Event{Type: sensor.EventConnect, TGID: 42, Size: 10, Path: loopback, Arg1: 4444})
	if score != 0 {
		t.Fatalf("loopback IPv6 score = %d, want 0", score)
	}
	public := string([]byte{0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88})
	score, reason := a.score(sensor.Event{Type: sensor.EventConnect, TGID: 42, Size: 10, Path: public, Arg1: 4444})
	if score != 6 {
		t.Fatalf("public IPv6 score = %d, want 6", score)
	}
	if reason != "network egress after suspicious activity" {
		t.Fatalf("reason = %q", reason)
	}
}

func TestScoreSelfProtectWriteOpen(t *testing.T) {
	a := &Agent{
		policy: config.Policy{
			SelfProtectPaths: []string{"/opt/ebpffls/bin/ebpffls"},
			Scores:           config.Scores{SelfProtect: 50},
		},
	}

	score, reason := a.score(sensor.Event{
		Type: sensor.EventOpen,
		Arg0: 1,
		Path: "/opt/ebpffls/bin/ebpffls",
	})

	if score != 50 {
		t.Fatalf("score = %d, want 50", score)
	}
	if reason != "self-protect write-open" {
		t.Fatalf("reason = %q", reason)
	}
}

func TestScoreLinkInProtectedScope(t *testing.T) {
	a := &Agent{
		policy: config.Policy{
			ProtectedDirs: []string{"/protected"},
			Scores:        config.Scores{Rename: 8},
		},
	}

	score, reason := a.score(sensor.Event{
		Type:  sensor.EventLink,
		Path:  "/tmp/source.txt",
		Path2: "/protected/linked.txt",
	})

	if score != 8 {
		t.Fatalf("score = %d, want 8", score)
	}
	if reason != "link in protected scope" {
		t.Fatalf("reason = %q", reason)
	}
}

func TestScoreSymlinkInBackupScope(t *testing.T) {
	a := &Agent{
		policy: config.Policy{
			BackupDirs: []string{"/backup"},
			Scores:     config.Scores{Rename: 8, BackupDestroy: 20},
		},
	}

	score, reason := a.score(sensor.Event{
		Type:  sensor.EventLink,
		Arg0:  1,
		Path:  "/tmp/source.txt",
		Path2: "/backup/linked.txt",
	})

	if score != 28 {
		t.Fatalf("score = %d, want 28", score)
	}
	if reason != "symlink in backup scope" {
		t.Fatalf("reason = %q", reason)
	}
}

func TestScoreSelfProtectLink(t *testing.T) {
	a := &Agent{
		policy: config.Policy{
			SelfProtectPaths: []string{"/opt/ebpffls"},
			Scores:           config.Scores{SelfProtect: 50},
		},
	}

	score, reason := a.score(sensor.Event{
		Type:  sensor.EventLink,
		Path:  "/tmp/source",
		Path2: "/opt/ebpffls/bin/ebpffls.link",
	})

	if score != 50 {
		t.Fatalf("score = %d, want 50", score)
	}
	if reason != "self-protect link" {
		t.Fatalf("reason = %q", reason)
	}
}

func TestScoreExecAfterBlockedLineage(t *testing.T) {
	a := &Agent{
		policy:  config.Policy{Scores: config.Scores{ExecAfterBlocked: 7}},
		blocked: map[uint32]time.Time{100: time.Now()},
	}

	score, reason := a.score(sensor.Event{
		Type: sensor.EventExec,
		TGID: 200,
		PPID: 100,
	})

	if score != 7 {
		t.Fatalf("score = %d, want 7", score)
	}
	if reason != "exec after blocked lineage" {
		t.Fatalf("reason = %q", reason)
	}
}

func TestSelfProtectSensitiveEventBypassesTrustedExemption(t *testing.T) {
	a := &Agent{
		policy: config.Policy{
			SelfProtectPaths: []string{"/opt/ebpffls"},
		},
	}

	if !a.selfProtectSensitiveEvent(sensor.Event{
		Type: sensor.EventUnlink,
		Path: "/opt/ebpffls/bin/ebpffls",
	}) {
		t.Fatal("expected self-protect unlink to be sensitive")
	}
	if !a.selfProtectSensitiveEvent(sensor.Event{
		Type:  sensor.EventLink,
		Path2: "/opt/ebpffls/bin/ebpffls.link",
	}) {
		t.Fatal("expected self-protect link to be sensitive")
	}
}

func TestBackupSensitiveEventIncludesLink(t *testing.T) {
	a := &Agent{
		policy: config.Policy{
			BackupDirs: []string{"/backup"},
		},
	}

	if !a.backupSensitiveEvent(sensor.Event{
		Type:  sensor.EventLink,
		Path2: "/backup/linked",
	}) {
		t.Fatal("expected backup link to be sensitive")
	}
}

func TestTrustedEventUsesCachedProcInfo(t *testing.T) {
	a := &Agent{
		policy: config.Policy{
			TrustedProcesses: []string{"tar"},
			TrustedExePaths:  []string{"/usr/bin/tar"},
			TrustedUIDs:      []uint32{0},
		},
		procInfos: map[uint32]cachedProcInfo{
			42: {
				Info:     procInfo{TGID: 42, Exe: "/usr/bin/tar"},
				LastSeen: time.Now().Add(-time.Second),
			},
		},
	}

	if !a.isTrustedEvent(sensor.Event{Type: sensor.EventOpen, TGID: 42, UID: 0, Comm: "tar", Timestamp: time.Now()}) {
		t.Fatal("expected trusted event to use cached proc exe")
	}
}

func TestExecAttemptNeverCachesTargetAsIdentity(t *testing.T) {
	now := time.Now()
	a := &Agent{
		procInfos: map[uint32]cachedProcInfo{},
	}
	a.cacheExecInfo(sensor.Event{
		Type:      sensor.EventExec,
		PID:       42,
		TGID:      42,
		UID:       0,
		Comm:      "tar",
		Path:      "/usr/bin/tar",
		Timestamp: now,
	})

	cached, ok := a.procInfos[42]
	if !ok {
		t.Fatal("expected cached proc info")
	}
	if cached.Info.Exe != "" || !cached.NeedsRefresh {
		t.Fatalf("attempt cached an executable identity: %+v", cached)
	}
	if !cached.LastSeen.Equal(now) {
		t.Fatalf("cached LastSeen = %s, want %s", cached.LastSeen, now)
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

func TestRecordFeaturesCapsTrackedPaths(t *testing.T) {
	a := &Agent{}
	state := &procState{}
	for i := 0; i < maxTrackedPaths+128; i++ {
		a.recordFeatures(state, sensor.Event{
			Type: sensor.EventOpen,
			Arg0: 1,
			Path: fmt.Sprintf("/protected/file-%d", i),
		})
	}
	if got := len(state.seenPaths); got != maxTrackedPaths {
		t.Fatalf("seenPaths len = %d, want cap %d", got, maxTrackedPaths)
	}
	if got := len(state.openWritePaths); got != maxTrackedPaths {
		t.Fatalf("openWritePaths len = %d, want cap %d", got, maxTrackedPaths)
	}
}

func TestLogActionDoesNotMarkStateBlocked(t *testing.T) {
	a := &Agent{policy: config.Policy{Action: "log"}}
	state := &procState{TGID: 42}
	a.block(state)
	if state.Blocked {
		t.Fatal("log action marked process state blocked")
	}
}

func TestBlockedLineageExpiresByBlockTTL(t *testing.T) {
	a := &Agent{
		policy:  config.Policy{BlockTTL: time.Second},
		blocked: map[uint32]time.Time{42: time.Now().Add(-2 * time.Second)},
	}
	if a.isBlocked(42) {
		t.Fatal("expired blocked lineage still considered active")
	}
	if _, ok := a.blocked[42]; ok {
		t.Fatal("expired blocked lineage was not removed")
	}
}

func TestStateBlockExpiresByBlockTTL(t *testing.T) {
	t0 := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	a := &Agent{policy: config.Policy{BlockTTL: time.Second}}
	state := &procState{Blocked: true, BlockedAt: t0}
	if !a.stateBlocked(state, t0.Add(time.Second)) {
		t.Fatal("state block expired at the inclusive TTL boundary")
	}
	if a.stateBlocked(state, t0.Add(2*time.Second)) {
		t.Fatal("state block remained active after block_ttl")
	}
	if state.Blocked || !state.BlockedAt.IsZero() {
		t.Fatalf("expired state block was not cleared: %+v", state)
	}
}

func TestResolveOpenPathUsesProcCWDAndDirFD(t *testing.T) {
	if _, err := os.Stat("/proc/self/cwd"); err != nil {
		t.Skip("procfs is required")
	}
	dir := t.TempDir()
	a := &Agent{fdPaths: make(map[fdKey]fdState)}
	tgid := uint32(os.Getpid())

	cwd, err := os.Readlink("/proc/self/cwd")
	if err != nil {
		t.Fatalf("read cwd: %v", err)
	}
	dirfd := int32(-100)
	if got := a.resolveOpenPath(sensor.Event{TGID: tgid, Path: "relative.txt", Size: uint64(uint32(dirfd))}); got != filepath.Join(cwd, "relative.txt") {
		t.Fatalf("AT_FDCWD path = %q, want %q", got, filepath.Join(cwd, "relative.txt"))
	}

	f, err := os.Open(dir)
	if err != nil {
		t.Fatalf("open temp dir: %v", err)
	}
	defer f.Close()
	if got := a.resolveOpenPath(sensor.Event{TGID: tgid, Path: "nested.txt", Size: uint64(uint32(f.Fd()))}); got != filepath.Join(dir, "nested.txt") {
		t.Fatalf("dirfd path = %q, want %q", got, filepath.Join(dir, "nested.txt"))
	}
}

func TestPruneUsesSlidingWindowInsteadOfResettingWholeWindow(t *testing.T) {
	t0 := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	a := &Agent{policy: config.Policy{Window: 10 * time.Second}}
	state := &procState{
		FirstSeen: t0,
		Score:     3,
		history: []historyEvent{
			{At: t0, Type: "write", Score: 2, Reason: "old"},
			{At: t0.Add(9 * time.Second), Type: "write", Score: 1, Reason: "recent"},
		},
	}

	a.prune(state, t0.Add(11*time.Second))

	if state.Score != 1 {
		t.Fatalf("score after pruning = %d, want 1", state.Score)
	}
	if state.EventCount != 1 || len(state.RecentEvents) != 1 {
		t.Fatalf("retained events = %d/%d, want 1/1", state.EventCount, len(state.RecentEvents))
	}
	if !state.FirstSeen.Equal(t0.Add(9 * time.Second)) {
		t.Fatalf("FirstSeen = %s, want recent event time", state.FirstSeen)
	}
}

func TestRebuildWindowRestoresHighRateReason(t *testing.T) {
	a := &Agent{policy: config.Policy{Scores: config.Scores{HighRateBonus: 15}}}
	state := &procState{history: make([]historyEvent, 64)}
	for i := range state.history {
		state.history[i] = historyEvent{At: time.Unix(int64(i+1), 0), Type: "write", Score: 1, Reason: "write", WriteCount: 1}
	}
	a.rebuildWindow(state)
	if state.Score != 79 || !state.HighRateScored {
		t.Fatalf("rebuilt high-rate state = score %d, scored %t", state.Score, state.HighRateScored)
	}
	if !slices.Contains(state.Reasons, "high-rate file mutation") {
		t.Fatalf("rebuilt reasons = %#v, missing high-rate reason", state.Reasons)
	}
}

func TestInlineIOCReason(t *testing.T) {
	a := &Agent{policy: config.Policy{
		SuspiciousExtensions: []string{".locked"},
		RansomNoteNames:      []string{"README_FOR_DECRYPT.txt"},
	}}
	tests := []struct {
		name string
		ev   sensor.Event
		want string
	}{
		{name: "ransom note", ev: sensor.Event{Arg0: int32(sensor.EventOpen), Path: "README_FOR_DECRYPT.txt"}, want: "protected ransom note creation"},
		{name: "extension", ev: sensor.Event{Arg0: int32(sensor.EventOpen), Path: "report.locked"}, want: "protected suspicious extension write"},
		{name: "rename", ev: sensor.Event{Arg0: int32(sensor.EventRename), Path: "report.locked"}, want: "protected rename to suspicious extension"},
		{name: "unlink", ev: sensor.Event{Arg0: int32(sensor.EventUnlink), Path: "report.locked"}, want: "protected suspicious IOC unlink"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := a.inlineIOCReason(tt.ev); got != tt.want {
				t.Fatalf("inlineIOCReason = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestImmediateIOCRespectsLogAction(t *testing.T) {
	policy := config.Policy{
		Name:                 "log-only",
		Action:               "log",
		Window:               10 * time.Second,
		Threshold:            45,
		ProtectedDirs:        []string{"/protected"},
		SuspiciousExtensions: []string{".locked"},
	}
	a := New(policy, nil, Options{})
	a.handle(sensor.Event{
		Timestamp: time.Now(),
		PID:       123,
		TGID:      123,
		Type:      sensor.EventRename,
		Path:      "/protected/report.txt",
		Path2:     "/protected/report.txt.locked",
		Comm:      "sample",
	})

	state := a.procs[123]
	if state == nil {
		t.Fatal("immediate IOC did not create process state")
	}
	if state.Blocked {
		t.Fatal("action=log marked immediate IOC state as blocked")
	}
	if state.Score != policy.Threshold {
		t.Fatalf("immediate IOC score = %d, want %d", state.Score, policy.Threshold)
	}
	if a.metrics.Alerts != 1 || a.metrics.Blocks != 0 {
		t.Fatalf("metrics = %+v, want one alert and no blocks", a.metrics)
	}
}
