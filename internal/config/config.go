package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Scores struct {
	Write               int `yaml:"write"`
	Truncate            int `yaml:"truncate"`
	Rename              int `yaml:"rename"`
	Unlink              int `yaml:"unlink"`
	SuspiciousExtension int `yaml:"suspicious_extension"`
	RansomNote          int `yaml:"ransom_note"`
	BackupDestroy       int `yaml:"backup_destroy"`
	HighRateBonus       int `yaml:"high_rate_bonus"`
	ExecAfterBlocked    int `yaml:"exec_after_blocked"`
	Scan                int `yaml:"scan"`
	Mmap                int `yaml:"mmap"`
}

type Rule struct {
	Name    string `yaml:"name"`
	Feature string `yaml:"feature"`
	Op      string `yaml:"op"`
	Value   int    `yaml:"value"`
	Action  string `yaml:"action"`
	Reason  string `yaml:"reason"`
}

type Policy struct {
	Name                 string        `yaml:"name"`
	Description          string        `yaml:"description"`
	Window               time.Duration `yaml:"-"`
	WindowRaw            string        `yaml:"window"`
	Threshold            int           `yaml:"threshold"`
	Action               string        `yaml:"action"`
	BlockTTL             time.Duration `yaml:"-"`
	BlockTTLRaw          string        `yaml:"block_ttl"`
	ProtectedDirs        []string      `yaml:"protected_dirs"`
	BackupDirs           []string      `yaml:"backup_dirs"`
	TrustedProcesses     []string      `yaml:"trusted_processes"`
	TrustedExePaths      []string      `yaml:"trusted_exe_paths"`
	TrustedUIDs          []uint32      `yaml:"trusted_uids"`
	BlacklistHashes      []string      `yaml:"blacklist_hashes"`
	BlacklistHashFiles   []string      `yaml:"blacklist_hash_files"`
	BlacklistScan        time.Duration `yaml:"-"`
	BlacklistScanRaw     string        `yaml:"blacklist_scan"`
	SuspiciousExtensions []string      `yaml:"suspicious_extensions"`
	RansomNoteNames      []string      `yaml:"ransom_note_names"`
	Scores               Scores        `yaml:"scores"`
	Rules                []Rule        `yaml:"rules"`
}

func Load(path string) (Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, fmt.Errorf("read config: %w", err)
	}
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return Policy{}, fmt.Errorf("parse config: %w", err)
	}
	if p.WindowRaw == "" {
		p.WindowRaw = "10s"
	}
	p.Window, err = time.ParseDuration(p.WindowRaw)
	if err != nil {
		return Policy{}, fmt.Errorf("parse window: %w", err)
	}
	if p.BlockTTLRaw == "" {
		p.BlockTTLRaw = "10m"
	}
	p.BlockTTL, err = time.ParseDuration(p.BlockTTLRaw)
	if err != nil {
		return Policy{}, fmt.Errorf("parse block_ttl: %w", err)
	}
	if p.Threshold == 0 {
		p.Threshold = 45
	}
	if p.Action == "" {
		p.Action = "log"
	}
	p.Action = strings.ToLower(p.Action)
	if p.BlacklistScanRaw == "" {
		p.BlacklistScanRaw = "5s"
	}
	p.BlacklistScan, err = time.ParseDuration(p.BlacklistScanRaw)
	if err != nil {
		return Policy{}, fmt.Errorf("parse blacklist_scan: %w", err)
	}
	if p.Scores.Write == 0 {
		p.Scores.Write = 1
	}
	if p.Scores.Truncate == 0 {
		p.Scores.Truncate = 6
	}
	if p.Scores.Rename == 0 {
		p.Scores.Rename = 8
	}
	if p.Scores.Unlink == 0 {
		p.Scores.Unlink = 8
	}
	if p.Scores.SuspiciousExtension == 0 {
		p.Scores.SuspiciousExtension = 10
	}
	if p.Scores.RansomNote == 0 {
		p.Scores.RansomNote = 20
	}
	if p.Scores.BackupDestroy == 0 {
		p.Scores.BackupDestroy = 20
	}
	if p.Scores.HighRateBonus == 0 {
		p.Scores.HighRateBonus = 15
	}
	if p.Scores.ExecAfterBlocked == 0 {
		p.Scores.ExecAfterBlocked = 10
	}
	if p.Scores.Scan == 0 {
		p.Scores.Scan = 1
	}
	if p.Scores.Mmap == 0 {
		p.Scores.Mmap = 3
	}
	for i := range p.Rules {
		r := &p.Rules[i]
		r.Feature = strings.ToLower(strings.TrimSpace(r.Feature))
		r.Op = strings.TrimSpace(r.Op)
		r.Action = strings.ToLower(strings.TrimSpace(r.Action))
		if r.Action == "" {
			r.Action = p.Action
		}
		if r.Reason == "" {
			r.Reason = r.Name
		}
		if err := validateRule(*r); err != nil {
			return Policy{}, fmt.Errorf("validate rule %d: %w", i, err)
		}
	}
	return p, nil
}

func validateRule(rule Rule) error {
	switch rule.Feature {
	case "distinct_paths", "open_write_pairs", "rename_suffix_count":
	default:
		return fmt.Errorf("unsupported feature %q", rule.Feature)
	}
	switch rule.Op {
	case ">", ">=", "==", "<=", "<":
	default:
		return fmt.Errorf("unsupported op %q", rule.Op)
	}
	if rule.Value < 0 {
		return fmt.Errorf("value must be >= 0")
	}
	switch rule.Action {
	case "log", "deny", "kill":
	default:
		return fmt.Errorf("unsupported action %q", rule.Action)
	}
	return nil
}
