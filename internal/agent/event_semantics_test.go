package agent

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/panzhenyu/ebpffls/internal/config"
	"github.com/panzhenyu/ebpffls/internal/sensor"
)

func TestExecAttemptTrustUsesObservedExecutable(t *testing.T) {
	for _, tc := range []struct {
		name, current, target string
		trusted               bool
	}{
		{"failed helper preserves trust", "/usr/bin/trusted", "/missing/helper", true},
		{"failed trusted target cannot grant trust", "/tmp/untrusted", "/usr/bin/trusted", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := New(config.Policy{
				TrustedProcesses: []string{"trusted"},
				TrustedExePaths:  []string{"/usr/bin/trusted"},
				TrustedUIDs:      []uint32{42},
			}, nil, Options{DryRun: true})
			a.procReader = func(tgid uint32) (procInfo, error) {
				return procInfo{TGID: tgid, Exe: tc.current, Cgroup: "/workload"}, nil
			}
			ev := sensor.Event{Type: sensor.EventExec, TGID: 42, UID: 42, Comm: "trusted", Path: tc.target,
				Timestamp: time.Unix(100, 0), ABIVersion: 2, Phase: sensor.PhaseAttempt, Source: sensor.SourceTracepoint}
			a.cacheExecInfo(ev)
			if got := a.isTrustedEvent(ev); got != tc.trusted {
				t.Fatalf("attempt trust=%v, want %v", got, tc.trusted)
			}
			ev.Type, ev.Path = sensor.EventWrite, ""
			if got := a.isTrustedEvent(ev); got != tc.trusted {
				t.Fatalf("post-failure trust=%v, want %v", got, tc.trusted)
			}
			if got := a.procInfos[42].Info; got.Exe != tc.current || got.Cgroup != "/workload" {
				t.Fatalf("identity did not come from procfs: %+v", got)
			}
		})
	}
}

func TestUnconfirmedExecKeepsIdentityFresh(t *testing.T) {
	a := New(config.Policy{}, nil, Options{DryRun: true})
	current := "/usr/bin/before"
	a.procReader = func(tgid uint32) (procInfo, error) {
		return procInfo{TGID: tgid, Exe: current}, nil
	}
	ev := sensor.Event{Type: sensor.EventExec, TGID: 42, Timestamp: time.Unix(100, 0), Path: "/attempted/target"}
	a.cacheExecInfo(ev)
	if info, _ := a.procInfo(42, ev.Timestamp); info.Exe != current {
		t.Fatalf("pre-exec identity=%+v", info)
	}
	current = "/usr/bin/after"
	if info, _ := a.procInfo(42, ev.Timestamp); info.Exe != current {
		t.Fatalf("legacy sensor retained pre-exec identity: %+v", info)
	}
	a.procReader = func(uint32) (procInfo, error) { return procInfo{}, fmt.Errorf("exited") }
	if _, err := a.procInfo(42, ev.Timestamp); err == nil {
		t.Fatal("unconfirmed exec reused stale identity after procfs failed")
	}
}

func TestExecSuccessRefreshesActualIdentityWithoutRescoring(t *testing.T) {
	a := New(config.Policy{Window: time.Second, Threshold: 10}, nil, Options{DryRun: true})
	a.procInfos[42] = cachedProcInfo{Info: procInfo{Exe: "/old"}, NeedsRefresh: true}
	a.procReader = func(tgid uint32) (procInfo, error) {
		return procInfo{TGID: tgid, Exe: "/actual/interpreter", Cgroup: "/workload/new"}, nil
	}
	ev := sensor.Event{Type: sensor.EventExec, TGID: 42, Timestamp: time.Unix(100, 0), Path: "/untrusted/event/path",
		ABIVersion: 2, Phase: sensor.PhaseSuccess, Source: sensor.SourceSched}
	a.handle(ev)
	if got := a.procInfos[42]; got.Info.Exe != "/actual/interpreter" || got.Info.Cgroup != "/workload/new" || got.NeedsRefresh {
		t.Fatalf("success cached incorrect identity: %+v", got)
	}
	if len(a.procs) != 0 || a.metrics.Alerts != 0 {
		t.Fatal("exec completion was scored a second time")
	}
}

func TestWriteCompletionDoesNotDoubleLegacyScore(t *testing.T) {
	a := New(config.Policy{ProtectedDirs: []string{"/protected"}, Window: 10 * time.Second,
		Threshold: 100, Action: "log", Scores: config.Scores{Write: 2}}, nil, Options{DryRun: true})
	at := time.Unix(100, 0)
	a.handle(sensor.Event{Timestamp: at, TGID: 42, Type: sensor.EventOpen, Arg0: 1, Arg1: 3, Path: "/protected/a"})
	attempt := sensor.Event{Timestamp: at, TGID: 42, Type: sensor.EventWrite, Arg0: 3, Size: 100,
		ABIVersion: 2, Phase: sensor.PhaseAttempt, OperationID: 1}
	a.handle(attempt)
	score, count := a.procs[42].Score, a.procs[42].EventCount
	for _, phase := range []sensor.EventPhase{sensor.PhaseSuccess, sensor.PhaseFailure} {
		completion := attempt
		completion.Phase = phase
		a.handle(completion)
		if got := a.procs[42]; got.Score != score || got.EventCount != count {
			t.Fatalf("completion double-counted legacy evidence: score=%d count=%d", got.Score, got.EventCount)
		}
	}
}

func TestFailedOpenCannotPopulateFDOrFeatures(t *testing.T) {
	a := New(config.Policy{ProtectedDirs: []string{"/protected"}, Window: time.Second, Threshold: 1,
		Action: "log", Scores: config.Scores{Write: 2}}, nil, Options{DryRun: true})
	a.handle(sensor.Event{Timestamp: time.Unix(100, 0), TGID: 42, Type: sensor.EventOpen,
		Arg0: 1, Arg1: 3, Path: "/protected/failed", ABIVersion: 2, Phase: sensor.PhaseFailure, Result: -13})
	if len(a.fdPaths) != 0 || len(a.procs) != 0 || a.metrics.Alerts != 0 {
		t.Fatal("failed open changed FD state or detection features")
	}
}

func TestTrustedCallerCannotSuppressExecTargetHashCheck(t *testing.T) {
	a := New(config.Policy{
		TrustedProcesses: []string{"trusted"},
		TrustedExePaths:  []string{"/usr/bin/trusted"},
		BlacklistHashes:  []string{strings.Repeat("a", 64)},
	}, nil, Options{DryRun: true})
	a.procReader = func(tgid uint32) (procInfo, error) {
		return procInfo{TGID: tgid, Exe: "/usr/bin/trusted"}, nil
	}
	a.handle(sensor.Event{Type: sensor.EventExec, TGID: 42, Comm: "trusted",
		Timestamp: time.Unix(100, 0), Path: "/nonexistent/exec-target",
		ABIVersion: 2, Phase: sensor.PhaseAttempt})
	if len(a.hashQueue) != 1 {
		t.Fatal("trust in the caller bypassed the exec target's hash check")
	}
}

func TestCaptureGapCounterDoesNotChangeRingbufMetrics(t *testing.T) {
	a := New(config.Policy{}, nil, Options{DryRun: true})
	a.ringbufDropDelta(7)
	for _, tc := range []struct{ total, delta uint64 }{{3, 3}, {3, 0}, {10, 7}, {2, 2}} {
		if got := a.captureGapDelta(tc.total); got != tc.delta {
			t.Fatalf("captureGapDelta(%d)=%d, want %d", tc.total, got, tc.delta)
		}
		if a.metrics.CaptureGapsTotal != tc.total || a.metrics.RingbufDropsTotal != 7 {
			t.Fatalf("gap counters are not independent: %+v", a.metrics)
		}
	}
}

func TestDebugEventsDoNotAmplifyAgentWrites(t *testing.T) {
	var output bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&output)
	t.Cleanup(func() { log.SetOutput(previous) })
	a := New(config.Policy{}, nil, Options{DryRun: true, DebugEvents: true})
	ev := sensor.Event{Type: sensor.EventWrite, TGID: uint32(os.Getpid()),
		Timestamp: time.Unix(100, 0), ABIVersion: 2, Phase: sensor.PhaseSuccess}
	a.handle(ev)
	if output.Len() != 0 {
		t.Fatalf("own telemetry generated another log write: %s", output.String())
	}
	ev.TGID++
	a.handle(ev)
	if !strings.Contains(output.String(), "abi=2 phase=success") {
		t.Fatalf("other process telemetry was suppressed: %s", output.String())
	}
}
