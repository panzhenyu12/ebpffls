package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadValidatesAndNormalizesRules(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(`
name: rules-test
protected_dirs:
  - /tmp
suspicious_extensions: []
ransom_note_names: []
rules:
  - name: fanout
    feature: DISTINCT_PATHS
    op: ">="
    value: 5
    action: KILL
`), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	policy, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(policy.Rules) != 1 {
		t.Fatalf("rules len = %d, want 1", len(policy.Rules))
	}
	rule := policy.Rules[0]
	if rule.Feature != "distinct_paths" || rule.Action != "kill" || rule.Reason != "fanout" {
		t.Fatalf("rule = %+v", rule)
	}
}

func TestLoadNormalizesRuleBlockActionToDeny(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(`
name: block-rule-test
rules:
  - name: fanout
    feature: distinct_paths
    op: ">"
    value: 5
    action: block
`), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	policy, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := policy.Rules[0].Action; got != "deny" {
		t.Fatalf("rule action = %q, want deny", got)
	}
}

func TestLoadManyMergesPolicies(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.yaml")
	overlay := filepath.Join(dir, "overlay.yaml")
	if err := os.WriteFile(base, []byte(`
name: base
threshold: 100
action: log
protected_dirs:
  - /base
cgroup_paths:
  - /base.slice
suspicious_extensions:
  - .locked
scores:
  write: 1
network_egress:
  enabled: true
  score: 3
  allowed_cidrs:
    - 127.0.0.0/8
rules:
  - name: base-rule
    feature: distinct_paths
    op: ">="
    value: 10
    action: log
`), 0600); err != nil {
		t.Fatalf("write base config: %v", err)
	}
	if err := os.WriteFile(overlay, []byte(`
name: overlay
threshold: 7
action: kill
protected_dirs:
  - /overlay
cgroup_paths:
  - /overlay.slice
ransom_note_names:
  - README.txt
scores:
  write: 4
network_egress:
  score: 9
  allowed_ports:
    - 443
rules:
  - name: overlay-rule
    feature: distinct_paths
    op: ">"
    value: 2
    action: block
`), 0600); err != nil {
		t.Fatalf("write overlay config: %v", err)
	}

	policy, err := LoadMany([]string{base, overlay})
	if err != nil {
		t.Fatalf("LoadMany: %v", err)
	}
	if policy.Name != "base+overlay" {
		t.Fatalf("name = %q, want base+overlay", policy.Name)
	}
	if policy.Threshold != 7 || policy.Action != "kill" {
		t.Fatalf("threshold/action = %d/%q, want 7/kill", policy.Threshold, policy.Action)
	}
	if len(policy.ProtectedDirs) != 2 || policy.ProtectedDirs[0] != "/base" || policy.ProtectedDirs[1] != "/overlay" {
		t.Fatalf("protected_dirs = %#v", policy.ProtectedDirs)
	}
	if len(policy.CgroupPaths) != 2 || policy.CgroupPaths[0] != "/base.slice" || policy.CgroupPaths[1] != "/overlay.slice" {
		t.Fatalf("cgroup_paths = %#v", policy.CgroupPaths)
	}
	if policy.Scores.Write != 4 {
		t.Fatalf("write score = %d, want 4", policy.Scores.Write)
	}
	if !policy.NetworkEgress.Enabled || policy.NetworkEgress.Score != 9 {
		t.Fatalf("network egress = %+v, want enabled score 9", policy.NetworkEgress)
	}
	if len(policy.NetworkEgress.AllowedCIDR) != 1 || len(policy.NetworkEgress.AllowedPort) != 1 {
		t.Fatalf("network allowlists = %+v", policy.NetworkEgress)
	}
	if len(policy.Rules) != 2 || policy.Rules[1].Action != "deny" {
		t.Fatalf("rules = %#v, want overlay block normalized to deny", policy.Rules)
	}
}

func TestLoadRejectsInvalidRuleFeature(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(`
name: bad-rule-test
rules:
  - feature: entropy
    op: ">="
    value: 5
    action: kill
`), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if _, err := Load(path); err == nil {
		t.Fatal("Load succeeded, want invalid rule error")
	}
}

func TestLoadRejectsInvalidPolicyRuntimeValues(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{name: "action", yaml: "action: quarantine\n", want: "unsupported action"},
		{name: "window", yaml: "window: 0s\n", want: "window must be greater than zero"},
		{name: "block ttl", yaml: "block_ttl: -1s\n", want: "block_ttl must not be negative"},
		{name: "score", yaml: "scores:\n  write: -1\n", want: "score write must not be negative"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "policy.yaml")
			if err := os.WriteFile(path, []byte("name: invalid\n"+tt.yaml), 0600); err != nil {
				t.Fatalf("write config: %v", err)
			}
			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Load error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestLoadNormalizesIOCNames(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(`
name: ioc-normalize
suspicious_extensions:
  - LOCKED
  - " .enc "
ransom_note_names:
  - " README.txt "
`), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	policy, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := policy.SuspiciousExtensions; len(got) != 2 || got[0] != ".locked" || got[1] != ".enc" {
		t.Fatalf("suspicious_extensions = %#v", got)
	}
	if got := policy.RansomNoteNames; len(got) != 1 || got[0] != "README.txt" {
		t.Fatalf("ransom_note_names = %#v", got)
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte("name: strict\nthreshhold: 10\n"), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "field threshhold not found") {
		t.Fatalf("Load error = %v, want unknown-field error", err)
	}
}

func TestLoadValidatesNetworkAllowlists(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{name: "CIDR", yaml: "allowed_cidrs:\n    - not-a-cidr", want: "invalid network_egress allowed CIDR"},
		{name: "low port", yaml: "allowed_ports:\n    - 0", want: "must be between 1 and 65535"},
		{name: "high port", yaml: "allowed_ports:\n    - 65536", want: "must be between 1 and 65535"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "policy.yaml")
			data := "name: network\nnetwork_egress:\n  enabled: true\n  " + tt.yaml + "\n"
			if err := os.WriteFile(path, []byte(data), 0600); err != nil {
				t.Fatalf("write config: %v", err)
			}
			if _, err := Load(path); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Load error = %v, want substring %q", err, tt.want)
			}
		})
	}
}
