package config

import (
	"bytes"
	"fmt"
	"net"
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
	SelfProtect         int `yaml:"self_protect"`
	SuspiciousExtension int `yaml:"suspicious_extension"`
	RansomNote          int `yaml:"ransom_note"`
	BackupDestroy       int `yaml:"backup_destroy"`
	HighRateBonus       int `yaml:"high_rate_bonus"`
	ExecAfterBlocked    int `yaml:"exec_after_blocked"`
	Scan                int `yaml:"scan"`
	Mmap                int `yaml:"mmap"`
	IOUring             int `yaml:"io_uring"`
	NetworkEgress       int `yaml:"network_egress"`
}

type Rule struct {
	Name    string `yaml:"name"`
	Feature string `yaml:"feature"`
	Op      string `yaml:"op"`
	Value   int    `yaml:"value"`
	Action  string `yaml:"action"`
	Reason  string `yaml:"reason"`
}

type NetworkEgress struct {
	Enabled     bool     `yaml:"enabled"`
	Score       int      `yaml:"score"`
	AllowedCIDR []string `yaml:"allowed_cidrs"`
	AllowedPort []int    `yaml:"allowed_ports"`
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
	SelfProtectPaths     []string      `yaml:"self_protect_paths"`
	CgroupPaths          []string      `yaml:"cgroup_paths"`
	TrustedProcesses     []string      `yaml:"trusted_processes"`
	TrustedExePaths      []string      `yaml:"trusted_exe_paths"`
	TrustedUIDs          []uint32      `yaml:"trusted_uids"`
	BlacklistHashes      []string      `yaml:"blacklist_hashes"`
	BlacklistHashFiles   []string      `yaml:"blacklist_hash_files"`
	BlacklistScan        time.Duration `yaml:"-"`
	BlacklistScanRaw     string        `yaml:"blacklist_scan"`
	SuspiciousExtensions []string      `yaml:"suspicious_extensions"`
	RansomNoteNames      []string      `yaml:"ransom_note_names"`
	NetworkEgress        NetworkEgress `yaml:"network_egress"`
	Scores               Scores        `yaml:"scores"`
	Rules                []Rule        `yaml:"rules"`
}

func Load(path string) (Policy, error) {
	policy, err := loadOne(path)
	if err != nil {
		return Policy{}, err
	}
	return normalize(policy)
}

func LoadMany(paths []string) (Policy, error) {
	if len(paths) == 0 {
		paths = []string{"configs/ransomware.yaml"}
	}
	policies := make([]Policy, 0, len(paths))
	for _, path := range paths {
		policy, err := loadOne(path)
		if err != nil {
			return Policy{}, err
		}
		policies = append(policies, policy)
	}
	return normalize(mergePolicies(policies))
}

func loadOne(path string) (Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, fmt.Errorf("read config: %w", err)
	}
	var p Policy
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&p); err != nil {
		return Policy{}, fmt.Errorf("parse config: %w", err)
	}
	return p, nil
}

func normalize(p Policy) (Policy, error) {
	var err error
	if p.WindowRaw == "" {
		p.WindowRaw = "10s"
	}
	p.Window, err = time.ParseDuration(p.WindowRaw)
	if err != nil {
		return Policy{}, fmt.Errorf("parse window: %w", err)
	}
	if p.Window <= 0 {
		return Policy{}, fmt.Errorf("window must be greater than zero")
	}
	if p.BlockTTLRaw == "" {
		p.BlockTTLRaw = "10m"
	}
	p.BlockTTL, err = time.ParseDuration(p.BlockTTLRaw)
	if err != nil {
		return Policy{}, fmt.Errorf("parse block_ttl: %w", err)
	}
	if p.BlockTTL < 0 {
		return Policy{}, fmt.Errorf("block_ttl must not be negative")
	}
	if p.Threshold == 0 {
		p.Threshold = 45
	}
	if p.Threshold < 0 {
		return Policy{}, fmt.Errorf("threshold must not be negative")
	}
	if p.Action == "" {
		p.Action = "log"
	}
	p.Action = strings.ToLower(strings.TrimSpace(p.Action))
	switch p.Action {
	case "log", "deny", "kill":
	default:
		return Policy{}, fmt.Errorf("unsupported action %q; use log, deny, or kill", p.Action)
	}
	if p.BlacklistScanRaw == "" {
		p.BlacklistScanRaw = "5s"
	}
	p.BlacklistScan, err = time.ParseDuration(p.BlacklistScanRaw)
	if err != nil {
		return Policy{}, fmt.Errorf("parse blacklist_scan: %w", err)
	}
	if p.BlacklistScan < 0 {
		return Policy{}, fmt.Errorf("blacklist_scan must not be negative")
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
	if p.Scores.SelfProtect == 0 {
		p.Scores.SelfProtect = 50
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
	if p.Scores.IOUring == 0 {
		p.Scores.IOUring = 1
	}
	if p.Scores.NetworkEgress == 0 {
		p.Scores.NetworkEgress = 5
	}
	if p.NetworkEgress.Score == 0 {
		p.NetworkEgress.Score = p.Scores.NetworkEgress
	}
	for i, cidr := range p.NetworkEgress.AllowedCIDR {
		cidr = strings.TrimSpace(cidr)
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return Policy{}, fmt.Errorf("invalid network_egress allowed CIDR %q: %w", cidr, err)
		}
		p.NetworkEgress.AllowedCIDR[i] = cidr
	}
	for _, port := range p.NetworkEgress.AllowedPort {
		if port < 1 || port > 65535 {
			return Policy{}, fmt.Errorf("network_egress allowed port %d must be between 1 and 65535", port)
		}
	}
	if err := validateScores(p.Scores, p.NetworkEgress.Score); err != nil {
		return Policy{}, err
	}
	for i, extension := range p.SuspiciousExtensions {
		extension = strings.TrimSpace(strings.ToLower(extension))
		if extension != "" && !strings.HasPrefix(extension, ".") {
			extension = "." + extension
		}
		p.SuspiciousExtensions[i] = extension
	}
	for i, name := range p.RansomNoteNames {
		p.RansomNoteNames[i] = strings.TrimSpace(name)
	}
	for i := range p.Rules {
		r := &p.Rules[i]
		r.Feature = strings.ToLower(strings.TrimSpace(r.Feature))
		r.Op = strings.TrimSpace(r.Op)
		r.Action = strings.ToLower(strings.TrimSpace(r.Action))
		if r.Action == "" {
			r.Action = p.Action
		}
		if r.Action == "block" {
			r.Action = "deny"
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

func validateScores(scores Scores, networkScore int) error {
	values := map[string]int{
		"write":                scores.Write,
		"truncate":             scores.Truncate,
		"rename":               scores.Rename,
		"unlink":               scores.Unlink,
		"self_protect":         scores.SelfProtect,
		"suspicious_extension": scores.SuspiciousExtension,
		"ransom_note":          scores.RansomNote,
		"backup_destroy":       scores.BackupDestroy,
		"high_rate_bonus":      scores.HighRateBonus,
		"exec_after_blocked":   scores.ExecAfterBlocked,
		"scan":                 scores.Scan,
		"mmap":                 scores.Mmap,
		"io_uring":             scores.IOUring,
		"network_egress":       networkScore,
	}
	for name, value := range values {
		if value < 0 {
			return fmt.Errorf("score %s must not be negative", name)
		}
	}
	return nil
}

func mergePolicies(policies []Policy) Policy {
	var merged Policy
	for _, p := range policies {
		if p.Name != "" {
			if merged.Name == "" {
				merged.Name = p.Name
			} else {
				merged.Name += "+" + p.Name
			}
		}
		if p.Description != "" {
			merged.Description = p.Description
		}
		if p.WindowRaw != "" {
			merged.WindowRaw = p.WindowRaw
		}
		if p.Threshold != 0 {
			merged.Threshold = p.Threshold
		}
		if p.Action != "" {
			merged.Action = p.Action
		}
		if p.BlockTTLRaw != "" {
			merged.BlockTTLRaw = p.BlockTTLRaw
		}
		if p.BlacklistScanRaw != "" {
			merged.BlacklistScanRaw = p.BlacklistScanRaw
		}
		merged.ProtectedDirs = append(merged.ProtectedDirs, p.ProtectedDirs...)
		merged.BackupDirs = append(merged.BackupDirs, p.BackupDirs...)
		merged.SelfProtectPaths = append(merged.SelfProtectPaths, p.SelfProtectPaths...)
		merged.CgroupPaths = append(merged.CgroupPaths, p.CgroupPaths...)
		merged.TrustedProcesses = append(merged.TrustedProcesses, p.TrustedProcesses...)
		merged.TrustedExePaths = append(merged.TrustedExePaths, p.TrustedExePaths...)
		merged.TrustedUIDs = append(merged.TrustedUIDs, p.TrustedUIDs...)
		merged.BlacklistHashes = append(merged.BlacklistHashes, p.BlacklistHashes...)
		merged.BlacklistHashFiles = append(merged.BlacklistHashFiles, p.BlacklistHashFiles...)
		merged.SuspiciousExtensions = append(merged.SuspiciousExtensions, p.SuspiciousExtensions...)
		merged.RansomNoteNames = append(merged.RansomNoteNames, p.RansomNoteNames...)
		merged.Rules = append(merged.Rules, p.Rules...)
		merged.Scores = mergeScores(merged.Scores, p.Scores)
		merged.NetworkEgress = mergeNetworkEgress(merged.NetworkEgress, p.NetworkEgress)
	}
	return merged
}

func mergeNetworkEgress(base, override NetworkEgress) NetworkEgress {
	base.Enabled = base.Enabled || override.Enabled
	if override.Score != 0 {
		base.Score = override.Score
	}
	base.AllowedCIDR = append(base.AllowedCIDR, override.AllowedCIDR...)
	base.AllowedPort = append(base.AllowedPort, override.AllowedPort...)
	return base
}

func mergeScores(base, override Scores) Scores {
	if override.Write != 0 {
		base.Write = override.Write
	}
	if override.Truncate != 0 {
		base.Truncate = override.Truncate
	}
	if override.Rename != 0 {
		base.Rename = override.Rename
	}
	if override.Unlink != 0 {
		base.Unlink = override.Unlink
	}
	if override.SelfProtect != 0 {
		base.SelfProtect = override.SelfProtect
	}
	if override.SuspiciousExtension != 0 {
		base.SuspiciousExtension = override.SuspiciousExtension
	}
	if override.RansomNote != 0 {
		base.RansomNote = override.RansomNote
	}
	if override.BackupDestroy != 0 {
		base.BackupDestroy = override.BackupDestroy
	}
	if override.HighRateBonus != 0 {
		base.HighRateBonus = override.HighRateBonus
	}
	if override.ExecAfterBlocked != 0 {
		base.ExecAfterBlocked = override.ExecAfterBlocked
	}
	if override.Scan != 0 {
		base.Scan = override.Scan
	}
	if override.Mmap != 0 {
		base.Mmap = override.Mmap
	}
	if override.IOUring != 0 {
		base.IOUring = override.IOUring
	}
	if override.NetworkEgress != 0 {
		base.NetworkEgress = override.NetworkEgress
	}
	return base
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
	case "log", "deny", "kill", "block":
	default:
		return fmt.Errorf("unsupported action %q", rule.Action)
	}
	return nil
}
