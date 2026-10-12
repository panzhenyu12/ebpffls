package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/panzhenyu/ebpffls/internal/config"
	"github.com/panzhenyu/ebpffls/internal/sensor"
)

type Options struct {
	DryRun      bool
	DebugEvents bool
}

type Agent struct {
	policy          config.Policy
	sensor          *sensor.Sensor
	options         Options
	procs           map[uint32]*procState
	fdMu            sync.RWMutex
	fdPaths         map[fdKey]fdState
	procMu          sync.RWMutex
	procInfos       map[uint32]cachedProcInfo
	procReader      func(uint32) (procInfo, error)
	blockedMu       sync.RWMutex
	blocked         map[uint32]time.Time
	blacklist       *blacklist
	hashes          *hashCache
	hashQueue       chan hashJob
	metricsMu       sync.Mutex
	lastDrops       uint64
	lastCaptureGaps uint64
	metrics         metrics
}

const (
	// Keep alert payloads and per-process cardinality bounded even when a
	// process continuously mutates files faster than the window can expire.
	maxRecentEvents  = 256
	maxTrackedPaths  = 4096
	maxHistoryEvents = 4096
)

type hashJob struct {
	TGID   uint32
	PID    uint32
	PPID   uint32
	UID    uint32
	Comm   string
	Path   string
	Reason string
}

type fdKey struct {
	TGID uint32
	FD   int32
}

type fdState struct {
	Path     string
	LastSeen time.Time
}

type cachedProcInfo struct {
	Info         procInfo
	LastSeen     time.Time
	NeedsRefresh bool
}

type procState struct {
	TGID           uint32
	PID            uint32
	PPID           uint32
	UID            uint32
	Comm           string
	Score          int
	FirstSeen      time.Time
	LastSeen       time.Time
	EventCount     int
	WriteCount     int
	Blocked        bool
	BlockedAt      time.Time
	Reasons        []string
	RecentEvents   []scoredEvent
	HighRateScored bool
	Features       procFeatures
	seenPaths      map[string]struct{}
	openWritePaths map[string]struct{}
	history        []historyEvent
}

type historyEvent struct {
	At             time.Time
	Type           string
	Path           string
	Path2          string
	Score          int
	Reason         string
	WriteCount     int
	FeaturePaths   []string
	OpenWritePath  string
	RenameSuffix   bool
	FinalizeSignal bool
}

type procFeatures struct {
	DistinctPaths     int    `json:"distinct_paths"`
	OpenWritePairs    int    `json:"open_write_pairs"`
	RenameSuffixCount int    `json:"rename_suffix_count"`
	EncryptionState   string `json:"encryption_state,omitempty"`
}

type metrics struct {
	SchemaVersion     string `json:"schema_version"`
	Kind              string `json:"kind"`
	Alerts            uint64 `json:"alerts"`
	Blocks            uint64 `json:"blocks"`
	BlacklistMatches  uint64 `json:"blacklist_matches"`
	RingbufDropsTotal uint64 `json:"ringbuf_drops_total"`
	CaptureGapsTotal  uint64 `json:"capture_gaps_total"`
}

type scoredEvent struct {
	At     time.Time `json:"at"`
	Type   string    `json:"type"`
	Path   string    `json:"path,omitempty"`
	Path2  string    `json:"path2,omitempty"`
	Score  int       `json:"score"`
	Reason string    `json:"reason"`
}

type alert struct {
	SchemaVersion string        `json:"schema_version"`
	Kind          string        `json:"kind"`
	At            time.Time     `json:"at"`
	Policy        string        `json:"policy"`
	Action        string        `json:"action"`
	DryRun        bool          `json:"dry_run"`
	TGID          uint32        `json:"tgid"`
	PID           uint32        `json:"pid"`
	PPID          uint32        `json:"ppid"`
	UID           uint32        `json:"uid"`
	Comm          string        `json:"comm"`
	Score         int           `json:"score"`
	Threshold     int           `json:"threshold"`
	Reasons       []string      `json:"reasons"`
	Features      procFeatures  `json:"features"`
	Events        []scoredEvent `json:"events"`
}

func New(policy config.Policy, s *sensor.Sensor, options Options) *Agent {
	bl, err := newBlacklist(policy)
	if err != nil {
		log.Printf("failed to load blacklist: %v", err)
	}
	return &Agent{
		policy:    policy,
		sensor:    s,
		options:   options,
		procs:     make(map[uint32]*procState),
		fdPaths:   make(map[fdKey]fdState),
		procInfos: make(map[uint32]cachedProcInfo),
		blocked:   make(map[uint32]time.Time),
		blacklist: bl,
		hashes:    newHashCache(),
		hashQueue: make(chan hashJob, 1024),
		metrics: metrics{
			SchemaVersion: "v1",
			Kind:          "ebpffls_metrics",
		},
	}
}

func (a *Agent) Run(ctx context.Context) error {
	if a == nil || a.sensor == nil {
		return fmt.Errorf("agent sensor is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	events, errs := a.sensor.Events(ctx)
	pruneTicker := time.NewTicker(a.pruneInterval())
	dropTicker := time.NewTicker(a.ringbufDropInterval())
	metricsTicker := time.NewTicker(a.metricsInterval())
	defer pruneTicker.Stop()
	defer dropTicker.Stop()
	defer metricsTicker.Stop()
	if a.blacklist != nil {
		go a.hashWorker(ctx)
		go a.scanBlacklist(ctx)
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case err, ok := <-errs:
			if !ok {
				errs = nil
				continue
			}
			if err != nil {
				return err
			}
		case ev, ok := <-events:
			if !ok {
				return nil
			}
			a.handle(ev)
		case <-pruneTicker.C:
			a.pruneIdle(time.Now())
		case <-dropTicker.C:
			a.logRingbufDrops()
		case <-metricsTicker.C:
			a.logMetrics()
		}
	}
}

func (a *Agent) handle(ev sensor.Event) {
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now()
	}
	// Logging our own writes would generate more events, especially now that
	// each write can emit both an attempt and a completion.
	if a.options.DebugEvents && ev.TGID != uint32(os.Getpid()) {
		log.Printf("event type=%s pid=%d tgid=%d ppid=%d uid=%d comm=%q arg0=%d size=%d path=%q path2=%q abi=%d phase=%s source=%s flags=%d syscall_id=%d result=%d operation_id=%d requested_bytes=%d actual_bytes=%d vector_count=%d",
			ev.TypeName(), ev.PID, ev.TGID, ev.PPID, ev.UID, ev.Comm, ev.Arg0, ev.Size, ev.Path, ev.Path2,
			ev.ABIVersion, ev.PhaseName(), ev.SourceName(), ev.Flags, ev.SyscallID, ev.Result, ev.OperationID, ev.RequestedBytes, ev.ActualBytes, ev.VectorCount)
	}

	if ev.Type == sensor.EventBlock {
		if ev.Size == uint64(sensor.BlockReasonInlineIOC) {
			a.handleInlineIOCBlock(ev)
			return
		}
		log.Printf("blocked op=%s pid=%d tgid=%d comm=%s", eventName(uint32(ev.Arg0)), ev.PID, ev.TGID, ev.Comm)
		return
	}

	// Completion records enrich telemetry; the legacy detector already scores
	// write attempts. Failed operations must never update its FD or path state.
	if ev.Phase == sensor.PhaseFailure ||
		(ev.Type == sensor.EventWrite && ev.Phase == sensor.PhaseSuccess) {
		return
	}

	if a.updateFD(&ev) {
		return
	}

	if !a.inPolicyCgroup(ev.TGID) {
		return
	}

	if ev.Type == sensor.EventExec {
		a.cacheExecInfo(ev)
		if ev.Phase == sensor.PhaseSuccess {
			return
		}
	}

	if ev.Type == sensor.EventExec && a.blockedLineage(ev) && !a.options.DryRun {
		a.enforceTGID(ev.TGID, sensor.BlockActionKill, "exec by blocked lineage")
		return
	}

	if ok, hash := a.blacklistedEvent(ev); ok {
		a.enforceBlacklist(ev.TGID, ev.PID, ev.PPID, ev.UID, ev.Comm, ev.Path, hash, "blacklisted exec")
		return
	}

	if a.isTrustedEvent(ev) && !a.backupSensitiveEvent(ev) && !a.selfProtectSensitiveEvent(ev) {
		return
	}

	if reason := a.immediateIOC(ev); reason != "" {
		state := a.state(ev)
		a.prune(state, ev.Timestamp)
		a.recordFeatures(state, ev)
		action := normalizeAction(strings.ToLower(strings.TrimSpace(a.policy.Action)))
		state.Score = max(state.Score, a.policy.Threshold)
		state.EventCount++
		if action != "log" {
			state.Blocked = true
			state.BlockedAt = ev.Timestamp
		}
		state.Reasons = appendReason(state.Reasons, reason)
		state.RecentEvents = append(state.RecentEvents, scoredEvent{
			At:     ev.Timestamp,
			Type:   ev.TypeName(),
			Path:   ev.Path,
			Path2:  ev.Path2,
			Score:  a.policy.Threshold,
			Reason: reason,
		})
		if len(state.RecentEvents) > maxRecentEvents {
			state.RecentEvents = state.RecentEvents[len(state.RecentEvents)-maxRecentEvents:]
		}
		a.alertAndEnforce(state, reason, action)
		return
	}

	score, reason := a.score(ev)
	if score == 0 {
		return
	}

	state := a.state(ev)
	a.prune(state, ev.Timestamp)
	a.recordFeatures(state, ev)
	state.Score += score
	state.EventCount++
	if ev.Type == sensor.EventWrite || ev.Type == sensor.EventOpen {
		state.WriteCount++
	}
	state.RecentEvents = append(state.RecentEvents, scoredEvent{
		At:     ev.Timestamp,
		Type:   ev.TypeName(),
		Path:   ev.Path,
		Path2:  ev.Path2,
		Score:  score,
		Reason: reason,
	})
	if len(state.RecentEvents) > maxRecentEvents {
		state.RecentEvents = state.RecentEvents[len(state.RecentEvents)-maxRecentEvents:]
	}
	state.Reasons = appendReason(state.Reasons, reason)

	if !state.HighRateScored && state.WriteCount >= 64 {
		state.Score += a.policy.Scores.HighRateBonus
		state.HighRateScored = true
		state.Reasons = appendReason(state.Reasons, "high-rate file mutation")
	}

	history := historyEvent{
		At:           ev.Timestamp,
		Type:         ev.TypeName(),
		Path:         ev.Path,
		Path2:        ev.Path2,
		Score:        score,
		Reason:       reason,
		FeaturePaths: append([]string(nil), a.featurePaths(ev)...),
	}
	if ev.Type == sensor.EventWrite || ev.Type == sensor.EventOpen {
		history.WriteCount = 1
	}
	if ev.Type == sensor.EventOpen && isWriteOpen(ev.Arg0) && ev.Path != "" {
		history.OpenWritePath = ev.Path
	}
	history.RenameSuffix = ev.Type == sensor.EventRename && a.hasSuspiciousExtension(ev.Path2)
	history.FinalizeSignal = (ev.Type == sensor.EventRename && a.hasSuspiciousExtension(ev.Path2)) ||
		(ev.Type == sensor.EventOpen && (a.isRansomNote(ev.Path) || a.hasSuspiciousExtension(ev.Path)))
	state.history = append(state.history, history)
	if len(state.history) > maxHistoryEvents {
		state.history = state.history[len(state.history)-maxHistoryEvents:]
		a.rebuildWindow(state)
	}

	blocked := a.stateBlocked(state, ev.Timestamp)
	if matched, reason, action := a.matchRule(state); matched && !blocked {
		if action != "log" {
			state.Blocked = true
			state.BlockedAt = ev.Timestamp
		}
		state.Reasons = appendReason(state.Reasons, reason)
		a.alertAndEnforce(state, reason, action)
		return
	}

	if state.Score >= a.policy.Threshold && !a.stateBlocked(state, ev.Timestamp) {
		a.block(state)
	}
}

func (a *Agent) updateFD(ev *sensor.Event) bool {
	switch ev.Type {
	case sensor.EventOpen:
		if ev.Path == "" || ev.Arg1 < 0 {
			return false
		}
		path := a.resolveOpenPath(*ev)
		a.fdMu.Lock()
		a.fdPaths[fdKey{TGID: ev.TGID, FD: ev.Arg1}] = fdState{Path: path, LastSeen: ev.Timestamp}
		a.fdMu.Unlock()
		ev.Path = path
		return false
	case sensor.EventClose:
		a.fdMu.Lock()
		delete(a.fdPaths, fdKey{TGID: ev.TGID, FD: ev.Arg0})
		a.fdMu.Unlock()
		return true
	case sensor.EventDup:
		if ev.Arg0 < 0 || ev.Arg1 < 0 {
			return true
		}
		a.fdMu.Lock()
		if state := a.fdPaths[fdKey{TGID: ev.TGID, FD: ev.Arg0}]; state.Path != "" {
			state.LastSeen = ev.Timestamp
			a.fdPaths[fdKey{TGID: ev.TGID, FD: ev.Arg1}] = state
		} else {
			delete(a.fdPaths, fdKey{TGID: ev.TGID, FD: ev.Arg1})
		}
		a.fdMu.Unlock()
		return true
	}
	return false
}

func (a *Agent) resolveOpenPath(ev sensor.Event) string {
	path := ev.Path
	if filepath.IsAbs(path) {
		return path
	}
	dirfd := int32(ev.Size)
	base := ""
	if dirfd == -100 {
		base = procSymlink(ev.TGID, "cwd")
	} else {
		base = a.fdPath(ev.TGID, dirfd)
		if base == "" {
			base = procSymlink(ev.TGID, fmt.Sprintf("fd/%d", dirfd))
		}
	}
	if base == "" {
		return path
	}
	return filepath.Clean(filepath.Join(base, path))
}

func procSymlink(tgid uint32, name string) string {
	if tgid == 0 || name == "" {
		return ""
	}
	path, err := os.Readlink(fmt.Sprintf("/proc/%d/%s", tgid, name))
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(path, " (deleted)")
}

func (a *Agent) fdPath(tgid uint32, fd int32) string {
	a.fdMu.RLock()
	path := a.fdPaths[fdKey{TGID: tgid, FD: fd}].Path
	a.fdMu.RUnlock()
	return path
}

func (a *Agent) touchFD(tgid uint32, fd int32, seen time.Time) string {
	a.fdMu.Lock()
	key := fdKey{TGID: tgid, FD: fd}
	state := a.fdPaths[key]
	if state.Path != "" {
		state.LastSeen = seen
		a.fdPaths[key] = state
	}
	a.fdMu.Unlock()
	return state.Path
}

func (a *Agent) immediateIOC(ev sensor.Event) string {
	switch ev.Type {
	case sensor.EventOpen:
		if !isWriteOpen(ev.Arg0) || !a.inProtectedScope(ev.Path) {
			return ""
		}
		if a.isRansomNote(ev.Path) {
			return "protected ransom note creation"
		}
		if a.hasSuspiciousExtension(ev.Path) {
			return "protected suspicious extension write"
		}
	case sensor.EventRename:
		if !a.inProtectedScope(ev.Path2) || !a.hasSuspiciousExtension(ev.Path2) {
			return ""
		}
		return "protected rename to suspicious extension"
	}
	return ""
}

func (a *Agent) handleInlineIOCBlock(ev sensor.Event) {
	action := actionName(uint32(ev.Arg1))
	if action != "deny" && action != "kill" {
		log.Printf("blocked inline_ioc op=%s pid=%d tgid=%d comm=%s invalid_action=%d", eventName(uint32(ev.Arg0)), ev.PID, ev.TGID, ev.Comm, ev.Arg1)
		return
	}

	state := a.state(ev)
	a.prune(state, ev.Timestamp)
	if a.stateBlocked(state, ev.Timestamp) {
		log.Printf("blocked inline_ioc op=%s pid=%d tgid=%d comm=%s action=%s path=%q", eventName(uint32(ev.Arg0)), ev.PID, ev.TGID, ev.Comm, action, ev.Path)
		return
	}

	reason := a.inlineIOCReason(ev)
	state.Score = max(state.Score, a.policy.Threshold)
	state.EventCount++
	state.Blocked = true
	state.BlockedAt = ev.Timestamp
	state.Reasons = appendReason(state.Reasons, reason)
	state.RecentEvents = append(state.RecentEvents, scoredEvent{
		At:     ev.Timestamp,
		Type:   eventName(uint32(ev.Arg0)),
		Path:   ev.Path,
		Score:  a.policy.Threshold,
		Reason: reason,
	})
	if len(state.RecentEvents) > maxRecentEvents {
		state.RecentEvents = state.RecentEvents[len(state.RecentEvents)-maxRecentEvents:]
	}
	a.emitAlert(state, action, false)
	a.metricsMu.Lock()
	a.metrics.Blocks++
	a.metricsMu.Unlock()
	log.Printf("blocked inline_ioc op=%s pid=%d tgid=%d comm=%s action=%s path=%q", eventName(uint32(ev.Arg0)), ev.PID, ev.TGID, ev.Comm, action, ev.Path)
}

func (a *Agent) inlineIOCReason(ev sensor.Event) string {
	switch uint32(ev.Arg0) {
	case sensor.EventOpen:
		if a.isRansomNote(ev.Path) {
			return "protected ransom note creation"
		}
		return "protected suspicious extension write"
	case sensor.EventRename:
		return "protected rename to suspicious extension"
	case sensor.EventUnlink:
		return "protected suspicious IOC unlink"
	default:
		return "protected inline IOC"
	}
}

func (a *Agent) blacklistedEvent(ev sensor.Event) (bool, string) {
	if a.blacklist == nil || a.blacklist.empty() || ev.Type != sensor.EventExec || ev.Path == "" {
		return false, ""
	}
	if hash, ok := a.hashes.get(ev.Path); ok {
		return a.blacklist.matchHash(hash), hash
	}
	a.enqueueHash(hashJob{
		TGID:   ev.TGID,
		PID:    ev.PID,
		PPID:   ev.PPID,
		UID:    ev.UID,
		Comm:   ev.Comm,
		Path:   ev.Path,
		Reason: "blacklisted exec",
	})
	return false, ""
}

func (a *Agent) isBlocked(tgid uint32) bool {
	if tgid == 0 {
		return false
	}
	a.blockedMu.RLock()
	seen, ok := a.blocked[tgid]
	a.blockedMu.RUnlock()
	if !ok {
		return false
	}
	if a.policy.BlockTTL > 0 && !seen.IsZero() && time.Since(seen) > a.policy.BlockTTL {
		a.blockedMu.Lock()
		if current, exists := a.blocked[tgid]; exists && current.Equal(seen) {
			delete(a.blocked, tgid)
		}
		a.blockedMu.Unlock()
		return false
	}
	return true
}

func (a *Agent) blockedLineage(ev sensor.Event) bool {
	return a.isBlocked(ev.TGID) || a.isBlocked(ev.PPID)
}

func (a *Agent) rememberBlocked(tgid uint32) {
	a.blockedMu.Lock()
	a.blocked[tgid] = time.Now()
	a.blockedMu.Unlock()
}

func (a *Agent) enforceTGID(tgid uint32, action uint32, reason string) {
	if a.options.DryRun {
		return
	}
	if a.sensor == nil {
		log.Printf("cannot enforce tgid=%d reason=%q: sensor is nil", tgid, reason)
		return
	}
	if err := a.sensor.BlockTGID(tgid, action, a.policy.BlockTTL); err != nil {
		log.Printf("failed to block tgid=%d reason=%q: %v", tgid, reason, err)
		return
	}
	a.rememberBlocked(tgid)
	if action == sensor.BlockActionKill {
		if proc, err := os.FindProcess(int(tgid)); err == nil {
			_ = proc.Signal(syscall.SIGKILL)
		}
	}
	log.Printf("enforced action=%s tgid=%d reason=%q ttl=%s", actionName(action), tgid, reason, a.policy.BlockTTL)
}

func (a *Agent) enqueueHash(job hashJob) {
	if a == nil || a.hashQueue == nil {
		return
	}
	select {
	case a.hashQueue <- job:
	default:
		log.Printf("hash queue full; dropping path=%q pid=%d", job.Path, job.PID)
	}
}

func (a *Agent) hashWorker(ctx context.Context) {
	if a == nil || a.hashes == nil || a.blacklist == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		select {
		case <-ctx.Done():
			return
		case job, ok := <-a.hashQueue:
			if !ok {
				return
			}
			hash, err := a.hashes.compute(job.Path)
			if err != nil {
				if a.options.DebugEvents {
					log.Printf("hash compute failed path=%q: %v", job.Path, err)
				}
				continue
			}
			if a.blacklist.matchHash(hash) {
				a.enforceBlacklist(job.TGID, job.PID, job.PPID, job.UID, job.Comm, job.Path, hash, job.Reason)
			}
		}
	}
}

func (a *Agent) procHash(path string) (string, bool) {
	if a == nil || a.hashes == nil || path == "" {
		return "", false
	}
	hash, err := a.hashes.compute(path)
	if err != nil {
		if a.options.DebugEvents {
			log.Printf("hash proc exe failed path=%q: %v", path, err)
		}
		return "", false
	}
	return hash, true
}

func (a *Agent) scanBlacklist(ctx context.Context) {
	if a == nil || a.blacklist == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	interval := a.policy.BlacklistScan
	if interval <= 0 {
		interval = 5 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	a.scanBlacklistOnce()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.scanBlacklistOnce()
		}
	}
}

func (a *Agent) scanBlacklistOnce() {
	if a == nil || a.blacklist == nil {
		return
	}
	if err := a.blacklist.reloadFiles(); err != nil {
		log.Printf("failed to reload blacklist hash files: %v", err)
	}
	procs, err := listProcs()
	if err != nil {
		log.Printf("failed to scan /proc for blacklist: %v", err)
		return
	}
	for _, proc := range procs {
		if !a.procInPolicyCgroup(proc) {
			continue
		}
		if a.isTrustedProc(proc) {
			continue
		}
		hash, ok := a.procHash(proc.Exe)
		if ok && a.blacklist.matchHash(hash) {
			a.enforceBlacklist(proc.TGID, proc.PID, 0, 0, proc.Comm, proc.Exe, hash, "blacklisted running process")
		}
	}
}

func (a *Agent) enforceBlacklist(tgid, pid, ppid, uid uint32, comm, path, hash, reason string) {
	al := alert{
		SchemaVersion: "v1",
		Kind:          "ransomware_alert",
		At:            time.Now(),
		Policy:        a.policy.Name,
		Action:        "kill",
		DryRun:        a.options.DryRun,
		TGID:          tgid,
		PID:           pid,
		PPID:          ppid,
		UID:           uid,
		Comm:          comm,
		Score:         a.policy.Threshold,
		Threshold:     a.policy.Threshold,
		Reasons:       []string{reason},
		Events: []scoredEvent{{
			At:     time.Now(),
			Type:   "blacklist",
			Path:   path,
			Path2:  hash,
			Score:  a.policy.Threshold,
			Reason: reason,
		}},
	}
	data, _ := json.Marshal(al)
	log.Printf("alert=%s", data)
	a.metricsMu.Lock()
	a.metrics.Alerts++
	a.metrics.BlacklistMatches++
	a.metricsMu.Unlock()
	if a.options.DryRun {
		return
	}
	a.metricsMu.Lock()
	a.metrics.Blocks++
	a.metricsMu.Unlock()
	a.enforceTGID(tgid, sensor.BlockActionKill, reason)
	log.Printf("enforced blacklist tgid=%d reason=%q path=%q sha256=%s", tgid, reason, path, hash)
}

func (a *Agent) state(ev sensor.Event) *procState {
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now()
	}
	state := a.procs[ev.TGID]
	if state == nil {
		state = &procState{
			TGID:      ev.TGID,
			FirstSeen: ev.Timestamp,
		}
		state.initFeatureMaps()
		a.procs[ev.TGID] = state
	}
	state.PID = ev.PID
	state.PPID = ev.PPID
	state.UID = ev.UID
	state.Comm = ev.Comm
	state.LastSeen = ev.Timestamp
	return state
}

func (a *Agent) prune(state *procState, now time.Time) {
	if state == nil || a.policy.Window <= 0 {
		return
	}
	if len(state.history) == 0 {
		if state.FirstSeen.IsZero() || now.Sub(state.FirstSeen) <= a.policy.Window {
			return
		}
		state.Score = 0
		state.EventCount = 0
		state.WriteCount = 0
		state.Reasons = nil
		state.RecentEvents = nil
		state.HighRateScored = false
		state.Features = procFeatures{}
		state.seenPaths = nil
		state.openWritePaths = nil
		state.initFeatureMaps()
		state.FirstSeen = now
		return
	}
	retained := state.history[:0]
	for _, event := range state.history {
		if event.At.IsZero() || now.Sub(event.At) <= a.policy.Window {
			retained = append(retained, event)
		}
	}
	if len(retained) == len(state.history) {
		return
	}
	state.history = retained
	a.rebuildWindow(state)
}

func (a *Agent) rebuildWindow(state *procState) {
	if state == nil {
		return
	}
	state.Score = 0
	state.EventCount = 0
	state.WriteCount = 0
	state.Reasons = nil
	state.RecentEvents = nil
	state.HighRateScored = false
	state.Features = procFeatures{}
	state.seenPaths = nil
	state.openWritePaths = nil
	state.initFeatureMaps()
	state.FirstSeen = time.Time{}
	for _, event := range state.history {
		if event.At.IsZero() {
			continue
		}
		if state.FirstSeen.IsZero() || event.At.Before(state.FirstSeen) {
			state.FirstSeen = event.At
		}
		state.Score += event.Score
		state.EventCount++
		state.WriteCount += event.WriteCount
		state.RecentEvents = append(state.RecentEvents, scoredEvent{
			At:     event.At,
			Type:   event.Type,
			Path:   event.Path,
			Path2:  event.Path2,
			Score:  event.Score,
			Reason: event.Reason,
		})
		state.Reasons = appendReason(state.Reasons, event.Reason)
		for _, path := range event.FeaturePaths {
			if path == "" {
				continue
			}
			if _, exists := state.seenPaths[path]; !exists && len(state.seenPaths) < maxTrackedPaths {
				state.seenPaths[path] = struct{}{}
			}
		}
		if event.OpenWritePath != "" {
			if _, exists := state.openWritePaths[event.OpenWritePath]; !exists && len(state.openWritePaths) < maxTrackedPaths {
				state.openWritePaths[event.OpenWritePath] = struct{}{}
			}
		}
		if event.RenameSuffix {
			state.Features.RenameSuffixCount++
		}
	}
	state.Features.DistinctPaths = len(state.seenPaths)
	state.Features.OpenWritePairs = len(state.openWritePaths)
	for _, event := range state.history {
		if event.FinalizeSignal {
			state.Features.EncryptionState = "FINALIZE"
			break
		}
	}
	if state.Features.EncryptionState == "" && (state.Features.OpenWritePairs >= 3 || state.Features.DistinctPaths >= 3) {
		state.Features.EncryptionState = "STAGE"
	}
	if state.WriteCount >= 64 {
		state.Score += a.policy.Scores.HighRateBonus
		state.HighRateScored = true
		state.Reasons = appendReason(state.Reasons, "high-rate file mutation")
	}
	if len(state.RecentEvents) > maxRecentEvents {
		state.RecentEvents = state.RecentEvents[len(state.RecentEvents)-maxRecentEvents:]
	}
}

func (state *procState) initFeatureMaps() {
	if state.seenPaths == nil {
		state.seenPaths = make(map[string]struct{})
	}
	if state.openWritePaths == nil {
		state.openWritePaths = make(map[string]struct{})
	}
}

func (a *Agent) recordFeatures(state *procState, ev sensor.Event) {
	state.initFeatureMaps()
	for _, path := range a.featurePaths(ev) {
		if path == "" {
			continue
		}
		if _, exists := state.seenPaths[path]; !exists && len(state.seenPaths) < maxTrackedPaths {
			state.seenPaths[path] = struct{}{}
		}
	}
	if ev.Type == sensor.EventOpen && isWriteOpen(ev.Arg0) && ev.Path != "" {
		if _, exists := state.openWritePaths[ev.Path]; !exists && len(state.openWritePaths) < maxTrackedPaths {
			state.openWritePaths[ev.Path] = struct{}{}
		}
	}
	if ev.Type == sensor.EventRename && a.hasSuspiciousExtension(ev.Path2) {
		state.Features.RenameSuffixCount++
	}
	state.Features.DistinctPaths = len(state.seenPaths)
	state.Features.OpenWritePairs = len(state.openWritePaths)
	a.updateEncryptionState(state, ev)
}

func (a *Agent) featurePaths(ev sensor.Event) []string {
	switch ev.Type {
	case sensor.EventWrite:
		if path := a.fdPath(ev.TGID, ev.Arg0); path != "" {
			return []string{path}
		}
	case sensor.EventScan:
		if path := a.fdPath(ev.TGID, ev.Arg0); path != "" {
			return []string{path}
		}
	case sensor.EventMmap:
		if path := a.fdPath(ev.TGID, ev.Arg0); path != "" {
			return []string{path}
		}
	case sensor.EventTruncate:
		if ev.Path != "" {
			return []string{ev.Path}
		}
		if path := a.fdPath(ev.TGID, ev.Arg0); path != "" {
			return []string{path}
		}
	case sensor.EventRename:
		return []string{ev.Path, ev.Path2}
	case sensor.EventLink:
		return []string{ev.Path, ev.Path2}
	}
	if path := pickPath(ev); path != "" {
		return []string{path}
	}
	return nil
}

func (a *Agent) updateEncryptionState(state *procState, ev sensor.Event) {
	if state.Features.EncryptionState == "FINALIZE" {
		return
	}
	if ev.Type == sensor.EventRename && a.hasSuspiciousExtension(ev.Path2) {
		state.Features.EncryptionState = "FINALIZE"
		return
	}
	if ev.Type == sensor.EventOpen && (a.isRansomNote(ev.Path) || a.hasSuspiciousExtension(ev.Path)) {
		state.Features.EncryptionState = "FINALIZE"
		return
	}
	if state.Features.OpenWritePairs >= 3 || state.Features.DistinctPaths >= 3 {
		state.Features.EncryptionState = "STAGE"
	}
}

func (a *Agent) pruneInterval() time.Duration {
	ttl := a.idleTTL()
	interval := ttl / 2
	if interval < time.Second {
		return time.Second
	}
	if interval > time.Minute {
		return time.Minute
	}
	return interval
}

func (a *Agent) idleTTL() time.Duration {
	ttl := a.policy.Window * 3
	if ttl < time.Minute {
		ttl = time.Minute
	}
	if a.policy.BlockTTL > ttl {
		ttl = a.policy.BlockTTL
	}
	return ttl
}

func (a *Agent) ringbufDropInterval() time.Duration {
	interval := a.policy.Window
	if interval <= 0 {
		return 30 * time.Second
	}
	if interval < 5*time.Second {
		return 5 * time.Second
	}
	if interval > time.Minute {
		return time.Minute
	}
	return interval
}

func (a *Agent) metricsInterval() time.Duration {
	interval := a.policy.Window
	if interval <= 0 {
		return 30 * time.Second
	}
	if interval < 10*time.Second {
		return 10 * time.Second
	}
	if interval > time.Minute {
		return time.Minute
	}
	return interval
}

func (a *Agent) pruneIdle(now time.Time) {
	ttl := a.idleTTL()
	for tgid, state := range a.procs {
		if state.LastSeen.IsZero() || now.Sub(state.LastSeen) <= ttl {
			continue
		}
		delete(a.procs, tgid)
	}

	a.fdMu.Lock()
	for key, state := range a.fdPaths {
		if state.LastSeen.IsZero() || now.Sub(state.LastSeen) <= ttl {
			continue
		}
		delete(a.fdPaths, key)
	}
	a.fdMu.Unlock()

	a.procMu.Lock()
	for tgid, cached := range a.procInfos {
		if cached.LastSeen.IsZero() || now.Sub(cached.LastSeen) <= ttl {
			continue
		}
		delete(a.procInfos, tgid)
	}
	a.procMu.Unlock()

	a.blockedMu.Lock()
	for tgid, seen := range a.blocked {
		if seen.IsZero() {
			if state := a.procs[tgid]; state != nil {
				seen = state.LastSeen
			}
		}
		if seen.IsZero() || now.Sub(seen) <= ttl {
			continue
		}
		delete(a.blocked, tgid)
	}
	a.blockedMu.Unlock()
}

func (a *Agent) logRingbufDrops() {
	if a.sensor == nil {
		return
	}
	drops, err := a.sensor.RingbufDrops()
	if err != nil {
		if a.options.DebugEvents {
			log.Printf("failed to read ringbuf drop counter: %v", err)
		}
		return
	}
	delta := a.ringbufDropDelta(drops)
	if delta > 0 {
		log.Printf("ringbuf_drops total=%d delta=%d", drops, delta)
	}
	gaps, err := a.sensor.CaptureGaps()
	if err != nil {
		if a.options.DebugEvents {
			log.Printf("failed to read capture gap counter: %v", err)
		}
		return
	}
	if delta := a.captureGapDelta(gaps); delta > 0 {
		log.Printf("capture_gaps total=%d delta=%d", gaps, delta)
	}
}

func (a *Agent) captureGapDelta(current uint64) uint64 {
	a.metricsMu.Lock()
	defer a.metricsMu.Unlock()
	previous := a.lastCaptureGaps
	a.lastCaptureGaps = current
	a.metrics.CaptureGapsTotal = current
	if current < previous {
		return current
	}
	return current - previous
}

func (a *Agent) ringbufDropDelta(current uint64) uint64 {
	a.metricsMu.Lock()
	defer a.metricsMu.Unlock()
	previous := a.lastDrops
	a.lastDrops = current
	a.metrics.RingbufDropsTotal = current
	if current < previous {
		return current
	}
	return current - previous
}

func (a *Agent) logMetrics() {
	a.metricsMu.Lock()
	a.metrics.SchemaVersion = "v1"
	a.metrics.Kind = "ebpffls_metrics"
	data, _ := json.Marshal(a.metrics)
	a.metricsMu.Unlock()
	log.Printf("metrics=%s", data)
}

func (a *Agent) matchRule(state *procState) (bool, string, string) {
	for _, rule := range a.policy.Rules {
		if !ruleMatches(state.Features, rule) {
			continue
		}
		reason := rule.Reason
		if reason == "" {
			reason = "feature rule"
		}
		return true, reason, rule.Action
	}
	return false, "", ""
}

func ruleMatches(features procFeatures, rule config.Rule) bool {
	var got int
	switch rule.Feature {
	case "distinct_paths":
		got = features.DistinctPaths
	case "open_write_pairs":
		got = features.OpenWritePairs
	case "rename_suffix_count":
		got = features.RenameSuffixCount
	default:
		return false
	}
	switch rule.Op {
	case ">":
		return got > rule.Value
	case ">=":
		return got >= rule.Value
	case "==":
		return got == rule.Value
	case "<=":
		return got <= rule.Value
	case "<":
		return got < rule.Value
	default:
		return false
	}
}

func (a *Agent) score(ev sensor.Event) (int, string) {
	path := pickPath(ev)
	protected := a.inProtectedScope(path)
	backup := a.inBackupScope(path)
	selfProtect := a.inSelfProtectScope(path)

	switch ev.Type {
	case sensor.EventExec:
		if a.blockedLineage(ev) {
			return a.policy.Scores.ExecAfterBlocked, "exec after blocked lineage"
		}
		return 0, ""
	case sensor.EventIOUring:
		state := a.procs[ev.TGID]
		if state == nil || state.Features.DistinctPaths == 0 {
			return 0, ""
		}
		return a.policy.Scores.IOUring, "io_uring activity after protected file activity"
	case sensor.EventConnect:
		if !a.policy.NetworkEgress.Enabled || a.networkAllowed(ev) {
			return 0, ""
		}
		state := a.procs[ev.TGID]
		if state == nil || state.Features.DistinctPaths == 0 {
			return 0, ""
		}
		return a.policy.NetworkEgress.Score, "network egress after suspicious activity"
	case sensor.EventScan:
		path = a.touchFD(ev.TGID, ev.Arg0, ev.Timestamp)
		if path == "" {
			return 0, ""
		}
		if a.inBackupScope(path) {
			return a.policy.Scores.Scan + a.policy.Scores.BackupDestroy, "directory scan on backup fd"
		}
		if a.inProtectedScope(path) {
			return a.policy.Scores.Scan, "directory scan in protected scope"
		}
	case sensor.EventMmap:
		path = a.touchFD(ev.TGID, ev.Arg0, ev.Timestamp)
		if path == "" {
			return 0, ""
		}
		if a.inSelfProtectScope(path) {
			return a.policy.Scores.SelfProtect, "self-protect writable mmap"
		}
		if a.inBackupScope(path) {
			return a.policy.Scores.Mmap + a.policy.Scores.BackupDestroy, "writable mmap on backup fd"
		}
		if a.inProtectedScope(path) {
			return a.policy.Scores.Mmap, "writable mmap in protected scope"
		}
	case sensor.EventOpen:
		if selfProtect && isWriteOpen(ev.Arg0) {
			return a.policy.Scores.SelfProtect, "self-protect write-open"
		}
		if !protected && !backup {
			return 0, ""
		}
		if isWriteOpen(ev.Arg0) {
			if a.isRansomNote(path) {
				return a.policy.Scores.RansomNote, "ransom note creation"
			}
			if a.hasSuspiciousExtension(path) {
				return a.policy.Scores.SuspiciousExtension, "suspicious extension write"
			}
			return a.policy.Scores.Write, "write-open in protected scope"
		}
	case sensor.EventWrite:
		path = a.touchFD(ev.TGID, ev.Arg0, ev.Timestamp)
		if path == "" {
			return 0, ""
		}
		if a.inSelfProtectScope(path) {
			return a.policy.Scores.SelfProtect, "self-protect fd write"
		}
		if a.inBackupScope(path) {
			return a.policy.Scores.Write + a.policy.Scores.BackupDestroy, "write syscall on backup fd"
		}
		if a.inProtectedScope(path) {
			return a.policy.Scores.Write, "write syscall on protected fd"
		}
	case sensor.EventRename:
		if a.inSelfProtectScope(ev.Path) || a.inSelfProtectScope(ev.Path2) {
			return a.policy.Scores.SelfProtect, "self-protect rename"
		}
		if a.inProtectedScope(ev.Path) || a.inProtectedScope(ev.Path2) || a.inBackupScope(ev.Path) || a.inBackupScope(ev.Path2) {
			if a.hasSuspiciousExtension(ev.Path2) {
				return a.policy.Scores.Rename + a.policy.Scores.SuspiciousExtension, "rename to suspicious extension"
			}
			return a.policy.Scores.Rename, "rename in protected scope"
		}
	case sensor.EventLink:
		op := "link"
		if ev.Arg0 == 1 {
			op = "symlink"
		}
		if a.inSelfProtectScope(ev.Path) || a.inSelfProtectScope(ev.Path2) {
			return a.policy.Scores.SelfProtect, "self-protect " + op
		}
		if a.inBackupScope(ev.Path) || a.inBackupScope(ev.Path2) {
			return a.policy.Scores.Rename + a.policy.Scores.BackupDestroy, op + " in backup scope"
		}
		if a.inProtectedScope(ev.Path) || a.inProtectedScope(ev.Path2) {
			return a.policy.Scores.Rename, op + " in protected scope"
		}
	case sensor.EventUnlink:
		if selfProtect {
			return a.policy.Scores.SelfProtect, "self-protect deletion"
		}
		if backup {
			return a.policy.Scores.Unlink + a.policy.Scores.BackupDestroy, "backup deletion"
		}
		if protected {
			return a.policy.Scores.Unlink, "unlink in protected scope"
		}
	case sensor.EventTruncate:
		if path == "" {
			path = a.touchFD(ev.TGID, ev.Arg0, ev.Timestamp)
			backup = a.inBackupScope(path)
			protected = a.inProtectedScope(path)
			selfProtect = a.inSelfProtectScope(path)
		}
		if selfProtect {
			if ev.Path == "" {
				return a.policy.Scores.SelfProtect, "self-protect fd truncation"
			}
			return a.policy.Scores.SelfProtect, "self-protect truncation"
		}
		if backup {
			if ev.Path == "" {
				return a.policy.Scores.Truncate + a.policy.Scores.BackupDestroy, "backup fd truncation"
			}
			return a.policy.Scores.Truncate + a.policy.Scores.BackupDestroy, "backup truncation"
		}
		if protected {
			if ev.Path == "" {
				return a.policy.Scores.Truncate, "ftruncate on protected fd"
			}
			return a.policy.Scores.Truncate, "truncate in protected scope"
		}
	}
	return 0, ""
}

func (a *Agent) backupSensitiveEvent(ev sensor.Event) bool {
	path := pickPath(ev)
	switch ev.Type {
	case sensor.EventOpen:
		return isWriteOpen(ev.Arg0) && a.inBackupScope(path)
	case sensor.EventWrite, sensor.EventTruncate:
		if path == "" {
			path = a.touchFD(ev.TGID, ev.Arg0, ev.Timestamp)
		}
		return a.inBackupScope(path)
	case sensor.EventRename:
		return a.inBackupScope(ev.Path) || a.inBackupScope(ev.Path2)
	case sensor.EventLink:
		return a.inBackupScope(ev.Path) || a.inBackupScope(ev.Path2)
	case sensor.EventUnlink:
		return a.inBackupScope(path)
	default:
		return false
	}
}

func (a *Agent) selfProtectSensitiveEvent(ev sensor.Event) bool {
	path := pickPath(ev)
	switch ev.Type {
	case sensor.EventOpen:
		return isWriteOpen(ev.Arg0) && a.inSelfProtectScope(path)
	case sensor.EventWrite, sensor.EventMmap, sensor.EventTruncate:
		if path == "" {
			path = a.touchFD(ev.TGID, ev.Arg0, ev.Timestamp)
		}
		return a.inSelfProtectScope(path)
	case sensor.EventRename:
		return a.inSelfProtectScope(ev.Path) || a.inSelfProtectScope(ev.Path2)
	case sensor.EventLink:
		return a.inSelfProtectScope(ev.Path) || a.inSelfProtectScope(ev.Path2)
	case sensor.EventUnlink:
		return a.inSelfProtectScope(path)
	default:
		return false
	}
}

func (a *Agent) block(state *procState) {
	action := normalizeAction(strings.ToLower(strings.TrimSpace(a.policy.Action)))
	if action != "log" {
		state.Blocked = true
		state.BlockedAt = state.LastSeen
		if state.BlockedAt.IsZero() {
			state.BlockedAt = time.Now()
		}
	}
	a.alertAndEnforce(state, "behavior threshold", action)
}

func (a *Agent) stateBlocked(state *procState, now time.Time) bool {
	if state == nil || !state.Blocked {
		return false
	}
	if a.policy.BlockTTL <= 0 || state.BlockedAt.IsZero() {
		return true
	}
	if now.IsZero() {
		now = time.Now()
	}
	if now.Sub(state.BlockedAt) <= a.policy.BlockTTL {
		return true
	}
	state.Blocked = false
	state.BlockedAt = time.Time{}
	return false
}

func (a *Agent) alertAndEnforce(state *procState, reason string, action string) {
	if state == nil {
		return
	}
	action = normalizeAction(strings.ToLower(strings.TrimSpace(action)))
	a.emitAlert(state, action, a.options.DryRun)

	if a.options.DryRun || action == "log" {
		if a.options.DryRun && action != "log" {
			a.rememberBlocked(state.TGID)
		}
		return
	}
	a.metricsMu.Lock()
	a.metrics.Blocks++
	a.metricsMu.Unlock()
	a.enforceTGID(state.TGID, blockAction(action), reason)
}

func (a *Agent) emitAlert(state *procState, action string, dryRun bool) {
	al := alert{
		SchemaVersion: "v1",
		Kind:          "ransomware_alert",
		At:            time.Now(),
		Policy:        a.policy.Name,
		Action:        action,
		DryRun:        dryRun,
		TGID:          state.TGID,
		PID:           state.PID,
		PPID:          state.PPID,
		UID:           state.UID,
		Comm:          state.Comm,
		Score:         state.Score,
		Threshold:     a.policy.Threshold,
		Reasons:       state.Reasons,
		Features:      state.Features,
		Events:        state.RecentEvents,
	}
	data, _ := json.Marshal(al)
	log.Printf("alert=%s", data)
	a.metricsMu.Lock()
	a.metrics.Alerts++
	a.metricsMu.Unlock()
}

func (a *Agent) inProtectedScope(path string) bool {
	return hasDirPrefix(path, a.policy.ProtectedDirs)
}

func (a *Agent) inBackupScope(path string) bool {
	return hasDirPrefix(path, a.policy.BackupDirs)
}

func (a *Agent) inSelfProtectScope(path string) bool {
	return hasDirPrefix(path, a.policy.SelfProtectPaths)
}

func (a *Agent) networkAllowed(ev sensor.Event) bool {
	ip := eventIP(ev)
	if !ip.IsValid() {
		return true
	}
	port := int(ev.Arg1)
	for _, allowed := range a.policy.NetworkEgress.AllowedPort {
		if port == allowed {
			return true
		}
	}
	for _, cidr := range a.policy.NetworkEgress.AllowedCIDR {
		prefix, err := netip.ParsePrefix(cidr)
		if err == nil && prefix.Contains(ip) {
			return true
		}
		addr, err := netip.ParseAddr(cidr)
		if err == nil && addr == ip {
			return true
		}
	}
	return false
}

func (a *Agent) inPolicyCgroup(tgid uint32) bool {
	if !hasConfiguredPaths(a.policy.CgroupPaths) {
		return true
	}
	info, err := readProc(tgid)
	if err != nil {
		return false
	}
	return a.procInPolicyCgroup(info)
}

func (a *Agent) procInPolicyCgroup(proc procInfo) bool {
	if !hasConfiguredPaths(a.policy.CgroupPaths) {
		return true
	}
	return matchesCgroupPath(proc.Cgroup, a.policy.CgroupPaths)
}

func hasConfiguredPaths(paths []string) bool {
	for _, path := range paths {
		if strings.TrimSpace(path) != "" {
			return true
		}
	}
	return false
}

func (a *Agent) isTrustedEvent(ev sensor.Event) bool {
	if !a.trustedComm(ev.Comm) {
		return false
	}
	exe := ""
	if len(a.policy.TrustedExePaths) > 0 {
		if info, err := a.procInfo(ev.TGID, ev.Timestamp); err == nil {
			exe = info.Exe
		}
	}
	return a.isTrustedIdentityMatched(exe, ev.UID)
}

func (a *Agent) isTrustedProc(proc procInfo) bool {
	if !a.trustedComm(proc.Comm) {
		return false
	}
	return a.isTrustedIdentityMatched(proc.Exe, proc.UID)
}

func (a *Agent) isTrustedIdentityMatched(exe string, uid uint32) bool {
	if len(a.policy.TrustedUIDs) > 0 && !containsUID(a.policy.TrustedUIDs, uid) {
		return false
	}
	if len(a.policy.TrustedExePaths) > 0 && !matchesAnyPath(exe, a.policy.TrustedExePaths) {
		return false
	}
	return true
}

func (a *Agent) trustedComm(comm string) bool {
	for _, trusted := range a.policy.TrustedProcesses {
		if comm == trusted {
			return true
		}
	}
	return false
}

func containsUID(uids []uint32, uid uint32) bool {
	for _, candidate := range uids {
		if uid == candidate {
			return true
		}
	}
	return false
}

func (a *Agent) procInfo(tgid uint32, seen time.Time) (procInfo, error) {
	if seen.IsZero() {
		seen = time.Now()
	}
	a.procMu.RLock()
	cached, ok := a.procInfos[tgid]
	a.procMu.RUnlock()
	if ok && cached.Info.Exe != "" && !cached.NeedsRefresh {
		a.procMu.Lock()
		cached.LastSeen = seen
		a.procInfos[tgid] = cached
		a.procMu.Unlock()
		return cached.Info, nil
	}

	info, err := a.readProcessInfo(tgid)
	if err != nil {
		if ok && !cached.NeedsRefresh {
			a.procMu.Lock()
			cached.LastSeen = seen
			a.procInfos[tgid] = cached
			a.procMu.Unlock()
			return cached.Info, nil
		}
		return procInfo{}, err
	}
	a.procMu.Lock()
	a.procInfos[tgid] = cachedProcInfo{Info: info, LastSeen: seen, NeedsRefresh: cached.NeedsRefresh}
	a.procMu.Unlock()
	return info, nil
}

func (a *Agent) readProcessInfo(tgid uint32) (procInfo, error) {
	if a.procReader != nil {
		return a.procReader(tgid)
	}
	return readProc(tgid)
}

func (a *Agent) cacheExecInfo(ev sensor.Event) {
	seen := ev.Timestamp
	if seen.IsZero() {
		seen = time.Now()
	}
	a.procMu.Lock()
	cached := a.procInfos[ev.TGID]
	cached.LastSeen = seen
	cached.NeedsRefresh = true
	a.procInfos[ev.TGID] = cached
	a.procMu.Unlock()

	// An attempted target is not the executable identity. Without a confirmed
	// exec (including old sensors), keep reading procfs instead of trusting a
	// pre-exec cache that can outlive a successful process replacement.
	if ev.Phase != sensor.PhaseSuccess || ev.Source != sensor.SourceSched {
		return
	}
	info, err := a.readProcessInfo(ev.TGID)
	if err != nil || info.Exe == "" {
		return
	}
	a.procMu.Lock()
	a.procInfos[ev.TGID] = cachedProcInfo{Info: info, LastSeen: seen}
	a.procMu.Unlock()
}

func (a *Agent) hasSuspiciousExtension(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	for _, candidate := range a.policy.SuspiciousExtensions {
		candidate = strings.ToLower(strings.TrimSpace(candidate))
		if candidate != "" && !strings.HasPrefix(candidate, ".") {
			candidate = "." + candidate
		}
		if ext == candidate {
			return true
		}
	}
	return false
}

func (a *Agent) isRansomNote(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	for _, candidate := range a.policy.RansomNoteNames {
		if base == strings.ToLower(strings.TrimSpace(candidate)) {
			return true
		}
	}
	return false
}

func hasDirPrefix(path string, dirs []string) bool {
	if path == "" {
		return false
	}
	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		cleanDir := filepath.Clean(dir)
		cleanPath := filepath.Clean(path)
		if cleanDir == "/" {
			if strings.HasPrefix(cleanPath, "/") {
				return true
			}
			continue
		}
		if cleanPath == cleanDir || strings.HasPrefix(cleanPath, cleanDir+"/") {
			return true
		}
	}
	return false
}

func matchesAnyPath(path string, candidates []string) bool {
	if path == "" {
		return false
	}
	cleanPath := filepath.Clean(path)
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		cleanCandidate := filepath.Clean(candidate)
		if cleanCandidate == "/" {
			if strings.HasPrefix(cleanPath, "/") {
				return true
			}
			continue
		}
		if cleanPath == cleanCandidate || strings.HasPrefix(cleanPath, cleanCandidate+"/") {
			return true
		}
	}
	return false
}

func matchesCgroupPath(path string, candidates []string) bool {
	if path == "" {
		return false
	}
	cleanPath := filepath.Clean(path)
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		cleanCandidate := filepath.Clean(candidate)
		if cleanCandidate == "." {
			cleanCandidate = "/"
		}
		if cleanCandidate == "/" {
			if strings.HasPrefix(cleanPath, "/") {
				return true
			}
			continue
		}
		if cleanPath == cleanCandidate || strings.HasPrefix(cleanPath, cleanCandidate+"/") {
			return true
		}
	}
	return false
}

func eventIP(ev sensor.Event) netip.Addr {
	const (
		afInet  = 2
		afInet6 = 10
	)
	if ev.Size == afInet6 {
		raw := []byte(ev.Path)
		if len(raw) < 16 {
			return netip.Addr{}
		}
		var addr [16]byte
		copy(addr[:], raw[:16])
		return netip.AddrFrom16(addr)
	}
	if ev.Size != 0 && ev.Size != afInet {
		return netip.Addr{}
	}
	raw := uint32(ev.Arg0)
	return netip.AddrFrom4([4]byte{
		byte(raw),
		byte(raw >> 8),
		byte(raw >> 16),
		byte(raw >> 24),
	})
}

func pickPath(ev sensor.Event) string {
	if ev.Path2 != "" {
		return ev.Path2
	}
	return ev.Path
}

func isWriteOpen(flags int32) bool {
	const (
		oAccMode = 00000003
		oWronly  = 00000001
		oRdwr    = 00000002
		oTrunc   = 00001000
	)
	return flags&oTrunc != 0 || flags&oAccMode == oWronly || flags&oAccMode == oRdwr
}

func appendReason(reasons []string, reason string) []string {
	for _, existing := range reasons {
		if existing == reason {
			return reasons
		}
	}
	return append(reasons, reason)
}

func actionName(action uint32) string {
	switch action {
	case sensor.BlockActionDeny:
		return "deny"
	case sensor.BlockActionKill:
		return "kill"
	default:
		return fmt.Sprintf("unknown(%d)", action)
	}
}

func normalizeAction(action string) string {
	switch action {
	case "deny", "kill", "log":
		return action
	default:
		return fmt.Sprintf("unknown(%s)", action)
	}
}

func blockAction(action string) uint32 {
	if action == "kill" {
		return sensor.BlockActionKill
	}
	return sensor.BlockActionDeny
}

func eventName(t uint32) string {
	switch t {
	case sensor.EventExec:
		return "exec"
	case sensor.EventOpen:
		return "open"
	case sensor.EventWrite:
		return "write"
	case sensor.EventRename:
		return "rename"
	case sensor.EventUnlink:
		return "unlink"
	case sensor.EventTruncate:
		return "truncate"
	case sensor.EventBlock:
		return "block"
	case sensor.EventClose:
		return "close"
	case sensor.EventDup:
		return "dup"
	case sensor.EventScan:
		return "scan"
	case sensor.EventMmap:
		return "mmap"
	case sensor.EventIOUring:
		return "io_uring"
	case sensor.EventConnect:
		return "connect"
	case sensor.EventLink:
		return "link"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}
