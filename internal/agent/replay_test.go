package agent

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/panzhenyu/ebpffls/internal/config"
	"github.com/panzhenyu/ebpffls/internal/sensor"
)

const replaySchemaVersion = "agent-replay/v1"

type replayFixture struct {
	SchemaVersion  string       `json:"schema_version"`
	Baseline       string       `json:"baseline"`
	ID             string       `json:"id"`
	Classification string       `json:"classification"`
	Description    string       `json:"description"`
	FollowUp       string       `json:"follow_up"`
	Policy         replayPolicy `json:"policy"`
	Events         []replayStep `json:"events"`
}

type replayPolicy struct {
	WindowMS   int64         `json:"window_ms"`
	Threshold  int           `json:"threshold"`
	Action     string        `json:"action"`
	WriteScore int           `json:"write_score"`
	Rules      []config.Rule `json:"rules"`
}

type replayStep struct {
	AtMS  int64          `json:"at_ms"`
	Type  string         `json:"type"`
	Arg0  int32          `json:"arg0"`
	Arg1  int32          `json:"arg1"`
	Size  uint64         `json:"size"`
	Path  string         `json:"path"`
	Path2 string         `json:"path2"`
	Want  replaySnapshot `json:"want"`
}

type replaySnapshot struct {
	State             *replayProcSnapshot     `json:"state"`
	TrackedFDs        int                     `json:"tracked_fds"`
	Alerts            uint64                  `json:"alerts"`
	EnforcementBlocks uint64                  `json:"enforcement_blocks"`
	CandidateActions  []replayCandidateAction `json:"candidate_actions"`
}

type replayCandidateAction struct {
	Action string `json:"action"`
	DryRun bool   `json:"dry_run"`
}

type replayProcSnapshot struct {
	Score        int          `json:"score"`
	EventCount   int          `json:"event_count"`
	WriteCount   int          `json:"write_count"`
	Blocked      bool         `json:"blocked"`
	FirstSeenMS  int64        `json:"first_seen_ms"`
	LastSeenMS   int64        `json:"last_seen_ms"`
	Features     procFeatures `json:"features"`
	Reasons      []string     `json:"reasons"`
	HistoryTypes []string     `json:"history_types"`
}

// These fixtures describe the opt-out legacy engine, including its limitations.
// New-engine correctness belongs in separate fixtures, not revised legacy goldens.
func TestLegacyReplayBaselines(t *testing.T) {
	paths, err := filepath.Glob("testdata/replay/*.json")
	if err != nil || len(paths) == 0 {
		t.Fatalf("find replay fixtures: paths=%v err=%v", paths, err)
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			fixture := loadReplayFixture(t, path)
			var first []replaySnapshot
			for run := 0; run < 3; run++ {
				got := runLegacyReplay(t, fixture)
				if run == 0 {
					first = got
				} else if !reflect.DeepEqual(got, first) {
					t.Fatalf("run %d is not deterministic:\nfirst=%s\nactual=%s", run+1, replayJSON(t, first), replayJSON(t, got))
				}
				for i, step := range fixture.Events {
					if !reflect.DeepEqual(got[i], step.Want) {
						t.Fatalf("run %d event %d (%s at %dms), %s:\nwant=%s\ngot=%s", run+1, i+1, step.Type, step.AtMS, fixture.Description, replayJSON(t, step.Want), replayJSON(t, got[i]))
					}
				}
			}
		})
	}
}

func TestLegacyReplayCapturesDenyCandidate(t *testing.T) {
	fixture := loadReplayFixture(t, "testdata/replay/legacy-kill-first.json")
	fixture.Policy.Rules[0].Action = "deny"
	got := runLegacyReplay(t, fixture)
	want := []replayCandidateAction{{Action: "deny", DryRun: true}}
	if !reflect.DeepEqual(got[0].CandidateActions, want) {
		t.Fatalf("candidate actions = %s, want %s", replayJSON(t, got[0].CandidateActions), replayJSON(t, want))
	}
	if reflect.DeepEqual(got[0], fixture.Events[0].Want) {
		t.Fatal("deny candidate unexpectedly matched the kill baseline")
	}
}

func loadReplayFixture(t *testing.T, path string) replayFixture {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fixture replayFixture
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&fixture); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		t.Fatalf("trailing data in %s: %v", path, err)
	}
	if fixture.SchemaVersion != replaySchemaVersion || fixture.Baseline != "legacy-v1" {
		t.Fatalf("unsupported replay contract: schema=%q baseline=%q", fixture.SchemaVersion, fixture.Baseline)
	}
	if fixture.ID+".json" != filepath.Base(path) || fixture.Description == "" || fixture.FollowUp == "" {
		t.Fatal("fixture needs matching id, description, and follow_up")
	}
	if fixture.Classification != "known-limitation" && fixture.Classification != "regression" {
		t.Fatalf("unsupported fixture classification %q", fixture.Classification)
	}
	if fixture.Policy.WindowMS <= 0 || fixture.Policy.Threshold <= 0 || fixture.Policy.WriteScore <= 0 || len(fixture.Events) == 0 {
		t.Fatal("fixture needs positive window, threshold, write score, and events")
	}
	switch fixture.Policy.Action {
	case "log", "deny", "kill":
	default:
		t.Fatalf("invalid replay action %q", fixture.Policy.Action)
	}
	for i, step := range fixture.Events {
		if step.AtMS < 0 || (i > 0 && step.AtMS < fixture.Events[i-1].AtMS) {
			t.Fatalf("event %d has invalid logical timestamp %d", i+1, step.AtMS)
		}
		if step.Type == "open" && (!filepath.IsAbs(step.Path) || step.Arg1 < 0) {
			t.Fatalf("event %d must use a synthetic absolute path and successful open fd", i+1)
		}
	}
	return fixture
}

func runLegacyReplay(t *testing.T, fixture replayFixture) []replaySnapshot {
	t.Helper()
	// Log capture is process-global, so replay tests must not use t.Parallel.
	var output bytes.Buffer
	previousOutput := log.Writer()
	log.SetOutput(&output)
	defer log.SetOutput(previousOutput)
	const tgid = uint32(424242)
	epoch := time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)
	a := New(config.Policy{
		Name:          fixture.ID,
		Window:        time.Duration(fixture.Policy.WindowMS) * time.Millisecond,
		Threshold:     fixture.Policy.Threshold,
		Action:        fixture.Policy.Action,
		ProtectedDirs: []string{"/replay/protected"},
		Scores:        config.Scores{Write: fixture.Policy.WriteScore},
		Rules:         fixture.Policy.Rules,
	}, nil, Options{DryRun: true})
	result := make([]replaySnapshot, 0, len(fixture.Events))
	for i, step := range fixture.Events {
		var eventType uint32
		switch step.Type {
		case "open":
			eventType = sensor.EventOpen
		case "write":
			eventType = sensor.EventWrite
		default:
			t.Fatalf("event %d has unsupported replay type %q", i+1, step.Type)
		}
		output.Reset()
		previousAlerts := a.metrics.Alerts
		a.handle(sensor.Event{
			Timestamp: epoch.Add(time.Duration(step.AtMS) * time.Millisecond),
			Type:      eventType, PID: tgid, TGID: tgid, UID: 65534, Comm: "replay",
			Arg0: step.Arg0, Arg1: step.Arg1, Size: step.Size,
			Path: step.Path, Path2: step.Path2,
		})
		snapshot := replaySnapshot{
			TrackedFDs: len(a.fdPaths), Alerts: a.metrics.Alerts, EnforcementBlocks: a.metrics.Blocks,
			CandidateActions: replayAlertActions(t, output.Bytes(), fixture.ID, tgid),
		}
		if uint64(len(snapshot.CandidateActions)) != snapshot.Alerts-previousAlerts {
			t.Fatalf("event %d alert output/counter mismatch: actions=%s alerts_delta=%d", i+1,
				replayJSON(t, snapshot.CandidateActions), snapshot.Alerts-previousAlerts)
		}
		if state := a.procs[tgid]; state != nil {
			observed := &replayProcSnapshot{
				Score: state.Score, EventCount: state.EventCount, WriteCount: state.WriteCount,
				Blocked: state.Blocked, Features: state.Features,
				FirstSeenMS: state.FirstSeen.Sub(epoch).Milliseconds(), LastSeenMS: state.LastSeen.Sub(epoch).Milliseconds(),
				Reasons: append([]string(nil), state.Reasons...),
			}
			for _, event := range state.history {
				observed.HistoryTypes = append(observed.HistoryTypes, event.Type)
			}
			snapshot.State = observed
		}
		if snapshot.EnforcementBlocks != 0 {
			t.Fatalf("event %d unexpectedly requested real enforcement", i+1)
		}
		result = append(result, snapshot)
	}
	return result
}

func replayAlertActions(t *testing.T, output []byte, policy string, tgid uint32) []replayCandidateAction {
	t.Helper()
	var actions []replayCandidateAction
	for _, line := range bytes.Split(output, []byte("\n")) {
		const marker = "alert="
		start := bytes.Index(line, []byte(marker))
		if start < 0 {
			continue
		}
		var observed alert
		if err := json.Unmarshal(line[start+len(marker):], &observed); err != nil {
			t.Fatalf("decode replay alert: %v", err)
		}
		if observed.SchemaVersion != "v1" || observed.Kind != "ransomware_alert" || observed.Policy != policy || observed.TGID != tgid {
			t.Fatalf("unexpected replay alert identity/schema: %+v", observed)
		}
		if !observed.DryRun {
			t.Fatalf("replay emitted a non-dry-run alert: %+v", observed)
		}
		actions = append(actions, replayCandidateAction{Action: observed.Action, DryRun: observed.DryRun})
	}
	return actions
}

func replayJSON(t *testing.T, value any) string {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
