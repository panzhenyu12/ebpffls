package agent

import (
	"encoding/json"
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

func TestExecEventCachesTargetPathAsProcInfo(t *testing.T) {
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
	if cached.Info.Exe != "/usr/bin/tar" {
		t.Fatalf("cached exe = %q, want /usr/bin/tar", cached.Info.Exe)
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
