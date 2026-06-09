package config

import (
	"os"
	"path/filepath"
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
