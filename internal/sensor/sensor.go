package sensor

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/panzhenyu/ebpffls/internal/config"
)

const (
	BlockReasonPolicy    uint32 = 1
	BlockReasonInlineIOC uint32 = 3

	BlockActionDeny uint32 = 1
	BlockActionKill uint32 = 2

	ultraLegacyEventSlots = 1024
	ultraLegacyMaxCPUs    = 256
	mapPollingBatchSize   = 128
)

type BlockEntry struct {
	ExpiresNs uint64
	Reason    uint32
	Action    uint32
}

type dirKey struct {
	Dev uint64
	Ino uint64
}

type Sensor struct {
	closer       interface{ Close() error }
	maps         sensorMaps
	programs     sensorPrograms
	links        []link.Link
	reader       eventReader
	mode         runtimeMode
	closeOnce    sync.Once
	closeErr     error
	capabilities EnforcementCapabilities
}

type EnforcementCapabilities struct {
	Mode          string
	DenyAvailable bool
	DenyOpenat    bool
	UserspaceKill bool
	LSMHooks      []string
	OverrideHooks []string
}

var ErrDenyUnavailable = errors.New("deny enforcement unavailable")

type configurationError struct{ err error }

func (e *configurationError) Error() string { return e.err.Error() }
func (e *configurationError) Unwrap() error { return e.err }

type Options struct {
	DryRun bool
}

type runtimeMode string

const (
	runtimeModeCore           runtimeMode = "core"
	runtimeModeLegacyPerf     runtimeMode = "legacy_perf"
	runtimeModeUltraLegacyMap runtimeMode = "ultra_legacy_map"
)

type sensorMaps struct {
	Events             *ebpf.Map
	EventCursor        *ebpf.Map
	RingbufDrops       *ebpf.Map
	CaptureGaps        *ebpf.Map
	SyscallABI         *ebpf.Map
	BlockedTgids       *ebpf.Map
	IocExtensions      *ebpf.Map
	IocRansomNotes     *ebpf.Map
	ProtectedDirs      *ebpf.Map
	InlineIOCAction    *ebpf.Map
	AllowedCgroups     *ebpf.Map
	CgroupScopeEnabled *ebpf.Map
}

type sensorPrograms struct {
	TraceExecve        *ebpf.Program
	TraceExecSuccess   *ebpf.Program
	TraceProcessExit   *ebpf.Program
	TraceOpenat        *ebpf.Program
	TraceOpenatExit    *ebpf.Program
	TraceOpenat2       *ebpf.Program
	TraceOpenat2Exit   *ebpf.Program
	TraceWrite         *ebpf.Program
	TraceWriteExit     *ebpf.Program
	TracePwrite64      *ebpf.Program
	TracePwrite64Exit  *ebpf.Program
	TraceWritev        *ebpf.Program
	TraceWritevExit    *ebpf.Program
	TraceCopyFileRange *ebpf.Program
	TraceGetdents64    *ebpf.Program
	TraceMmap          *ebpf.Program
	TraceIoUringEnter  *ebpf.Program
	TraceConnect       *ebpf.Program
	TraceClose         *ebpf.Program
	TraceDup           *ebpf.Program
	TraceDupExit       *ebpf.Program
	TraceDup2          *ebpf.Program
	TraceDup2Exit      *ebpf.Program
	TraceDup3          *ebpf.Program
	TraceDup3Exit      *ebpf.Program
	TraceFcntl         *ebpf.Program
	TraceFcntlExit     *ebpf.Program
	TraceRename        *ebpf.Program
	TraceRenameat      *ebpf.Program
	TraceRenameat2     *ebpf.Program
	TraceLink          *ebpf.Program
	TraceLinkat        *ebpf.Program
	TraceSymlink       *ebpf.Program
	TraceSymlinkat     *ebpf.Program
	TraceUnlink        *ebpf.Program
	TraceUnlinkat      *ebpf.Program
	TraceTruncate      *ebpf.Program
	TraceFtruncate     *ebpf.Program

	EnforceFileOpen          *ebpf.Program
	EnforceFilePermission    *ebpf.Program
	EnforcePathTruncate      *ebpf.Program
	EnforcePathRename        *ebpf.Program
	EnforceInodeRename       *ebpf.Program
	EnforcePathMknod         *ebpf.Program
	EnforceInodeCreate       *ebpf.Program
	EnforcePathUnlink        *ebpf.Program
	EnforceBprmCheckSecurity *ebpf.Program

	KpOverrideOpenat        *ebpf.Program
	KpOverrideOpen          *ebpf.Program
	KpRetOpenat             *ebpf.Program
	KpRetOpen               *ebpf.Program
	KpOverrideOpenat2       *ebpf.Program
	KpOverrideRename        *ebpf.Program
	KpOverrideRenameat      *ebpf.Program
	KpOverrideRenameat2     *ebpf.Program
	KpOverrideLink          *ebpf.Program
	KpOverrideLinkat        *ebpf.Program
	KpOverrideSymlink       *ebpf.Program
	KpOverrideSymlinkat     *ebpf.Program
	KpOverrideUnlink        *ebpf.Program
	KpOverrideUnlinkat      *ebpf.Program
	KpOverrideTruncate      *ebpf.Program
	KpOverrideFtruncate     *ebpf.Program
	KpOverrideExecve        *ebpf.Program
	KpOverrideWrite         *ebpf.Program
	KpRetWrite              *ebpf.Program
	KpOverridePwrite64      *ebpf.Program
	KpRetPwrite64           *ebpf.Program
	KpOverrideWritev        *ebpf.Program
	KpRetWritev             *ebpf.Program
	KpProcessExit           *ebpf.Program
	KpOverrideCopyFileRange *ebpf.Program
	KpOverrideGetdents64    *ebpf.Program
	KpOverrideMmap          *ebpf.Program
	KpOverrideIoUringEnter  *ebpf.Program
}

type lsmAttachFunc func(*ebpf.Program) (link.Link, error)

type lsmAttachSummary struct {
	Attached int
	Skipped  int
}

type loadedSensorObjects struct {
	closer   interface{ Close() error }
	maps     sensorMaps
	programs sensorPrograms
	mode     runtimeMode
}

type eventRecord struct {
	RawSample []byte
}

type eventReader interface {
	Read() (eventRecord, error)
	Close() error
}

type objectLoaders struct {
	core           func() (loadedSensorObjects, error)
	legacyPerf     func() (loadedSensorObjects, error)
	ultraLegacyMap func() (loadedSensorObjects, error)
}

func New(policy config.Policy) (*Sensor, error) {
	return NewWithOptions(policy, Options{DryRun: true})
}

func NewWithOptions(policy config.Policy, options Options) (*Sensor, error) {
	return newSensorWith(strings.TrimSpace(os.Getenv("EBPFFLS_BPF_MODE")), objectLoaders{
		core: loadCoreSensorObjects, legacyPerf: loadLegacyPerfSensorObjects, ultraLegacyMap: loadUltraLegacyMapSensorObjects,
	}, func(s *Sensor) error { return s.initialize(policy, options) })
}

func newSensorWith(modeValue string, loaders objectLoaders, initialize func(*Sensor) error) (*Sensor, error) {
	modes, err := sensorModeCandidates(modeValue)
	if err != nil {
		return nil, err
	}
	var failures []error
	for _, mode := range modes {
		loaded, err := loadSensorObjectsWith(string(mode), loaders)
		if err == nil {
			s := &Sensor{closer: loaded.closer, maps: loaded.maps, programs: loaded.programs, mode: mode}
			s.capabilities = EnforcementCapabilities{Mode: string(mode), UserspaceKill: true}
			err = initialize(s)
			if err == nil {
				log.Printf("bpf_runtime mode=%s", mode)
				log.Printf("bpf_ready mode=%s", mode)
				return s, nil
			}
			if closeErr := s.Close(); closeErr != nil {
				return nil, errors.Join(err, fmt.Errorf("cleanup failed BPF runtime %s: %w", mode, closeErr))
			}
		} else if loaded.closer != nil {
			if closeErr := loaded.closer.Close(); closeErr != nil {
				return nil, errors.Join(err, closeErr)
			}
		}
		var configErr *configurationError
		if errors.As(err, &configErr) {
			return nil, err
		}
		failures = append(failures, fmt.Errorf("%s: %w", mode, err))
		log.Printf("bpf_runtime_unavailable mode=%s error=%v", mode, err)
	}
	return nil, fmt.Errorf("initialize BPF runtime: %w", errors.Join(failures...))
}

func sensorModeCandidates(modeValue string) ([]runtimeMode, error) {
	switch mode := runtimeMode(strings.ToLower(strings.TrimSpace(modeValue))); mode {
	case "", "auto":
		return []runtimeMode{runtimeModeCore, runtimeModeLegacyPerf, runtimeModeUltraLegacyMap}, nil
	case runtimeModeCore, runtimeModeLegacyPerf, runtimeModeUltraLegacyMap:
		return []runtimeMode{mode}, nil
	case "legacy":
		return []runtimeMode{runtimeModeLegacyPerf}, nil
	default:
		return nil, fmt.Errorf("unsupported EBPFFLS_BPF_MODE=%q", mode)
	}
}

func (s *Sensor) initialize(policy config.Policy, options Options) error {
	if err := s.ConfigurePolicy(policy); err != nil {
		return &configurationError{err}
	}
	// Keep inline actions disabled until collection and capability checks succeed.
	if err := s.ConfigureEnforcement(policy.Action, true); err != nil {
		return &configurationError{err}
	}

	if err := s.attachTracepoints(); err != nil {
		return err
	}
	if err := s.attachLSMPrograms(); err != nil {
		return err
	}
	if err := s.attachKprobePrograms(); err != nil {
		return err
	}
	s.logCapabilities()
	if err := s.validatePolicyCapabilities(policy, options.DryRun); err != nil {
		return err
	}

	rd, err := newEventReader(s.mode, s.maps.Events, s.maps.EventCursor)
	if err != nil {
		return fmt.Errorf("open event reader: %w", err)
	}
	s.reader = rd
	if err := s.ConfigureEnforcement(policy.Action, options.DryRun); err != nil {
		return &configurationError{err}
	}
	return nil
}

func (s *Sensor) attachTracepoints() error {
	if s.mode == runtimeModeUltraLegacyMap {
		log.Printf("tracepoints skipped in bpf runtime mode=%s; using kprobe event collection", s.mode)
		return nil
	}
	tracepoints := []struct {
		category string
		name     string
		prog     *ebpf.Program
		optional bool
	}{
		{"syscalls", "sys_enter_execve", s.programs.TraceExecve, false},
		{"sched", "sched_process_exec", s.programs.TraceExecSuccess, false},
		{"sched", "sched_process_exit", s.programs.TraceProcessExit, false},
		{"syscalls", "sys_enter_openat", s.programs.TraceOpenat, false},
		{"syscalls", "sys_exit_openat", s.programs.TraceOpenatExit, false},
		{"syscalls", "sys_enter_write", s.programs.TraceWrite, false},
		{"syscalls", "sys_exit_write", s.programs.TraceWriteExit, false},
		{"syscalls", "sys_enter_pwrite64", s.programs.TracePwrite64, false},
		{"syscalls", "sys_exit_pwrite64", s.programs.TracePwrite64Exit, false},
		{"syscalls", "sys_enter_writev", s.programs.TraceWritev, false},
		{"syscalls", "sys_exit_writev", s.programs.TraceWritevExit, false},
		{"syscalls", "sys_enter_copy_file_range", s.programs.TraceCopyFileRange, true},
		{"syscalls", "sys_enter_getdents64", s.programs.TraceGetdents64, false},
		{"syscalls", "sys_enter_mmap", s.programs.TraceMmap, false},
		{"syscalls", "sys_enter_io_uring_enter", s.programs.TraceIoUringEnter, true},
		{"syscalls", "sys_enter_connect", s.programs.TraceConnect, true},
		{"syscalls", "sys_enter_close", s.programs.TraceClose, false},
		{"syscalls", "sys_enter_dup", s.programs.TraceDup, false},
		{"syscalls", "sys_exit_dup", s.programs.TraceDupExit, false},
		{"syscalls", "sys_enter_dup2", s.programs.TraceDup2, false},
		{"syscalls", "sys_exit_dup2", s.programs.TraceDup2Exit, false},
		{"syscalls", "sys_enter_dup3", s.programs.TraceDup3, false},
		{"syscalls", "sys_exit_dup3", s.programs.TraceDup3Exit, false},
		{"syscalls", "sys_enter_fcntl", s.programs.TraceFcntl, false},
		{"syscalls", "sys_exit_fcntl", s.programs.TraceFcntlExit, false},
		{"syscalls", "sys_enter_rename", s.programs.TraceRename, false},
		{"syscalls", "sys_enter_renameat", s.programs.TraceRenameat, false},
		{"syscalls", "sys_enter_renameat2", s.programs.TraceRenameat2, true},
		{"syscalls", "sys_enter_link", s.programs.TraceLink, true},
		{"syscalls", "sys_enter_linkat", s.programs.TraceLinkat, true},
		{"syscalls", "sys_enter_symlink", s.programs.TraceSymlink, true},
		{"syscalls", "sys_enter_symlinkat", s.programs.TraceSymlinkat, true},
		{"syscalls", "sys_enter_unlink", s.programs.TraceUnlink, false},
		{"syscalls", "sys_enter_unlinkat", s.programs.TraceUnlinkat, false},
		{"syscalls", "sys_enter_truncate", s.programs.TraceTruncate, false},
		{"syscalls", "sys_enter_ftruncate", s.programs.TraceFtruncate, false},
	}
	for _, tp := range tracepoints {
		tp.optional = tp.optional || optionalSyscallTracepoint(tp.category, tp.name, runtime.GOARCH)
		if tp.prog == nil {
			if tp.optional {
				log.Printf("optional tracepoint %s/%s unavailable in bpf object", tp.category, tp.name)
				continue
			}
			return fmt.Errorf("missing required tracepoint program %s/%s", tp.category, tp.name)
		}
		l, err := link.Tracepoint(tp.category, tp.name, tp.prog, nil)
		if err != nil {
			if tp.optional {
				log.Printf("optional tracepoint %s/%s unavailable: %v", tp.category, tp.name, err)
				continue
			}
			return fmt.Errorf("attach tracepoint %s/%s: %w", tp.category, tp.name, err)
		}
		s.links = append(s.links, l)
	}
	entry, exit := s.programs.TraceOpenat2, s.programs.TraceOpenat2Exit
	if entry == nil || exit == nil {
		log.Printf("optional tracepoint pair openat2 unavailable in bpf object")
		return nil
	}
	entryLink, err := link.Tracepoint("syscalls", "sys_enter_openat2", entry, nil)
	if err != nil {
		log.Printf("optional tracepoint pair openat2 unavailable: %v", err)
		return nil
	}
	exitLink, err := link.Tracepoint("syscalls", "sys_exit_openat2", exit, nil)
	if err != nil {
		entryLink.Close()
		log.Printf("optional tracepoint pair openat2 unavailable: %v", err)
		return nil
	}
	s.links = append(s.links, entryLink, exitLink)
	return nil
}

func (s *Sensor) attachLSMPrograms() error {
	names := map[*ebpf.Program]string{
		s.programs.EnforceFileOpen: "file_open", s.programs.EnforceFilePermission: "file_permission",
		s.programs.EnforcePathTruncate: "path_truncate", s.programs.EnforcePathRename: "path_rename",
		s.programs.EnforceInodeRename: "inode_rename", s.programs.EnforcePathMknod: "path_mknod",
		s.programs.EnforceInodeCreate: "inode_create", s.programs.EnforcePathUnlink: "path_unlink",
		s.programs.EnforceBprmCheckSecurity: "bprm_check_security",
	}
	lsms := []*ebpf.Program{
		s.programs.EnforceFileOpen,
		s.programs.EnforceFilePermission,
		s.programs.EnforcePathTruncate,
		s.programs.EnforcePathRename,
		s.programs.EnforceInodeRename,
		s.programs.EnforcePathMknod,
		s.programs.EnforceInodeCreate,
		s.programs.EnforcePathUnlink,
		s.programs.EnforceBprmCheckSecurity,
	}
	lsms = nonNilPrograms(lsms)
	lsmSummary := lsmAttachResult{lsmAttachSummary: lsmAttachSummary{Skipped: len(lsms)}}
	if len(lsms) == 0 {
		log.Printf("optional BPF LSM unavailable in bpf runtime mode=%s; skipping LSM attach", s.mode)
	} else if bpfLSMActive() {
		lsmSummary = attachLSMPrograms(lsms, func(prog *ebpf.Program) (link.Link, error) {
			attached, err := link.AttachLSM(link.LSMOptions{Program: prog})
			if err == nil {
				s.recordDenyHook("lsm", names[prog])
			}
			return attached, err
		})
	} else {
		log.Printf("optional BPF LSM inactive in /sys/kernel/security/lsm; skipping LSM attach")
	}
	s.links = append(s.links, lsmSummary.links...)
	log.Printf("bpf_lsm attached=%d skipped=%d mode=optional", lsmSummary.Attached, lsmSummary.Skipped)
	return nil
}

func (s *Sensor) attachKprobePrograms() error {
	paired := map[string]bool{}
	if s.mode == runtimeModeUltraLegacyMap {
		if s.programs.KpProcessExit == nil {
			return fmt.Errorf("missing required process-exit kprobe")
		}
		exitLink, err := link.Kprobe("do_exit", s.programs.KpProcessExit, nil)
		if err != nil {
			return fmt.Errorf("attach process-exit kprobe do_exit: %w", err)
		}
		s.links = append(s.links, exitLink)
		pairs := []struct {
			op       string
			entry    *ebpf.Program
			exit     *ebpf.Program
			optional bool
		}{
			{"open", s.programs.KpOverrideOpen, s.programs.KpRetOpen, true},
			{"openat", s.programs.KpOverrideOpenat, s.programs.KpRetOpenat, false},
			{"write", s.programs.KpOverrideWrite, s.programs.KpRetWrite, false},
			{"pwrite64", s.programs.KpOverridePwrite64, s.programs.KpRetPwrite64, false},
			{"writev", s.programs.KpOverrideWritev, s.programs.KpRetWritev, false},
		}
		for _, pair := range pairs {
			paired[pair.op] = true
			links, symbol, err := attachKprobePairWith(pair.op, pair.entry, pair.exit, attachEntryKprobe, attachReturnKprobe, func(symbol string) error {
				return s.configureKprobeABI(pair.op, symbol)
			})
			if err != nil {
				if pair.optional {
					log.Printf("optional kprobe pair op=%s unavailable: %v", pair.op, err)
					continue
				}
				return fmt.Errorf("attach required kprobe pair %s: %w", pair.op, err)
			}
			log.Printf("attached kprobe pair op=%s symbol=%s", pair.op, symbol)
			s.links = append(s.links, links...)
		}
		log.Printf("exec_success unavailable in bpf runtime mode=%s; exec events remain attempts", s.mode)
	}
	kprobes := []struct {
		op       string
		prog     *ebpf.Program
		optional bool
	}{
		{"openat", s.programs.KpOverrideOpenat, false},
		{"open", s.programs.KpOverrideOpen, true},
		{"openat2", s.programs.KpOverrideOpenat2, true},
		{"rename", s.programs.KpOverrideRename, false},
		{"renameat", s.programs.KpOverrideRenameat, false},
		{"renameat2", s.programs.KpOverrideRenameat2, true},
		{"link", s.programs.KpOverrideLink, true},
		{"linkat", s.programs.KpOverrideLinkat, true},
		{"symlink", s.programs.KpOverrideSymlink, true},
		{"symlinkat", s.programs.KpOverrideSymlinkat, true},
		{"unlink", s.programs.KpOverrideUnlink, false},
		{"unlinkat", s.programs.KpOverrideUnlinkat, false},
		{"truncate", s.programs.KpOverrideTruncate, false},
		{"ftruncate", s.programs.KpOverrideFtruncate, false},
		{"execve", s.programs.KpOverrideExecve, false},
		{"write", s.programs.KpOverrideWrite, false},
		{"pwrite64", s.programs.KpOverridePwrite64, false},
		{"writev", s.programs.KpOverrideWritev, false},
		{"copy_file_range", s.programs.KpOverrideCopyFileRange, true},
		{"getdents64", s.programs.KpOverrideGetdents64, false},
		{"mmap", s.programs.KpOverrideMmap, false},
		{"io_uring_enter", s.programs.KpOverrideIoUringEnter, true},
	}
	for _, kp := range kprobes {
		if paired[kp.op] {
			continue
		}
		optional := kp.optional || s.mode != runtimeModeUltraLegacyMap || kp.prog == nil
		if kp.prog == nil {
			if optional {
				log.Printf("optional override kprobe op=%s unavailable in bpf object", kp.op)
				continue
			}
			return fmt.Errorf("missing required override kprobe program %s", kp.op)
		}
		l, symbol, err := attachKprobeWith(kp.op, kp.prog, attachEntryKprobe, func(symbol string) error {
			return s.configureKprobeABI(kp.op, symbol)
		})
		if err != nil {
			if optional {
				log.Printf("optional override kprobe op=%s unavailable: %v", kp.op, err)
				continue
			}
			return fmt.Errorf("attach override kprobe %s: %w", kp.op, err)
		}
		log.Printf("attached override kprobe op=%s symbol=%s", kp.op, symbol)
		if s.mode != runtimeModeUltraLegacyMap {
			s.recordDenyHook("override", kp.op)
		}
		s.links = append(s.links, l)
	}

	kretprobes := []struct {
		op   string
		prog *ebpf.Program
	}{
		{"open", s.programs.KpRetOpen},
		{"openat", s.programs.KpRetOpenat},
	}
	for _, kp := range kretprobes {
		if paired[kp.op] {
			continue
		}
		if kp.prog == nil {
			continue
		}
		l, symbol, err := attachKretprobe(kp.op, kp.prog)
		if err != nil {
			log.Printf("optional kretprobe op=%s unavailable: %v", kp.op, err)
			continue
		}
		log.Printf("attached kretprobe op=%s symbol=%s", kp.op, symbol)
		s.links = append(s.links, l)
	}
	return nil
}

func optionalSyscallTracepoint(category, name, arch string) bool {
	if category != "syscalls" || arch != "arm64" {
		return false
	}
	op := strings.TrimPrefix(strings.TrimPrefix(name, "sys_enter_"), "sys_exit_")
	switch op {
	case "dup2", "rename", "unlink", "link", "symlink", "open":
		return true
	default:
		return false
	}
}

func (s *Sensor) recordDenyHook(kind, name string) {
	s.capabilities.DenyAvailable = true
	if kind == "lsm" {
		s.capabilities.LSMHooks = append(s.capabilities.LSMHooks, name)
		if name == "file_open" {
			s.capabilities.DenyOpenat = true
		}
	} else {
		s.capabilities.OverrideHooks = append(s.capabilities.OverrideHooks, name)
		if name == "openat" {
			s.capabilities.DenyOpenat = true
		}
	}
}

func (s *Sensor) Capabilities() EnforcementCapabilities {
	caps := s.capabilities
	caps.LSMHooks = append([]string(nil), caps.LSMHooks...)
	caps.OverrideHooks = append([]string(nil), caps.OverrideHooks...)
	return caps
}

func (s *Sensor) logCapabilities() {
	log.Printf("bpf_capabilities mode=%s deny_available=%t deny_openat=%t userspace_kill=%t lsm_hooks=%q override_hooks=%q", s.mode,
		s.capabilities.DenyAvailable, s.capabilities.DenyOpenat, s.capabilities.UserspaceKill,
		strings.Join(s.capabilities.LSMHooks, ","), strings.Join(s.capabilities.OverrideHooks, ","))
}

func (s *Sensor) validatePolicyCapabilities(policy config.Policy, dryRun bool) error {
	if dryRun || s.capabilities.DenyAvailable {
		return nil
	}
	if strings.EqualFold(strings.TrimSpace(policy.Action), "deny") {
		return fmt.Errorf("%w: mode=%s", ErrDenyUnavailable, s.mode)
	}
	for _, rule := range policy.Rules {
		action := strings.ToLower(strings.TrimSpace(rule.Action))
		if action == "deny" || action == "block" {
			return fmt.Errorf("%w: rule=%q mode=%s", ErrDenyUnavailable, rule.Name, s.mode)
		}
	}
	return nil
}

func loadSensorObjects() (loadedSensorObjects, error) {
	return loadSensorObjectsWith(strings.TrimSpace(os.Getenv("EBPFFLS_BPF_MODE")), objectLoaders{
		core:           loadCoreSensorObjects,
		legacyPerf:     loadLegacyPerfSensorObjects,
		ultraLegacyMap: loadUltraLegacyMapSensorObjects,
	})
}

func loadSensorObjectsWith(modeValue string, loaders objectLoaders) (loadedSensorObjects, error) {
	mode := runtimeMode(strings.ToLower(strings.TrimSpace(modeValue)))
	switch mode {
	case "", "auto":
		return loadSensorObjectsAuto(loaders)
	case runtimeModeCore:
		return loaders.core()
	case runtimeModeLegacyPerf, "legacy":
		return loaders.legacyPerf()
	case runtimeModeUltraLegacyMap:
		return loaders.ultraLegacyMap()
	default:
		return loadedSensorObjects{}, fmt.Errorf("unsupported EBPFFLS_BPF_MODE=%q", mode)
	}
}

func loadSensorObjectsAuto(loaders objectLoaders) (loadedSensorObjects, error) {
	core, err := loaders.core()
	if err == nil {
		return core, nil
	}
	log.Printf("core BPF runtime unavailable; falling back to legacy_perf mode: %v", err)
	legacyPerf, legacyPerfErr := loaders.legacyPerf()
	if legacyPerfErr == nil {
		return legacyPerf, nil
	}
	log.Printf("legacy_perf BPF runtime unavailable; falling back to ultra_legacy_map mode: %v", legacyPerfErr)
	ultraLegacyMap, ultraLegacyMapErr := loaders.ultraLegacyMap()
	if ultraLegacyMapErr == nil {
		return ultraLegacyMap, nil
	}
	return loadedSensorObjects{}, fmt.Errorf("load bpf objects: core: %v; legacy_perf: %v; ultra_legacy_map: %w", err, legacyPerfErr, ultraLegacyMapErr)
}

func loadCoreSensorObjects() (loadedSensorObjects, error) {
	var objs ransomwareObjects
	opts, err := coreCollectionOptions()
	if err != nil {
		return loadedSensorObjects{}, err
	}
	spec, err := loadRansomware()
	if err != nil {
		return loadedSensorObjects{}, err
	}
	var options ebpf.CollectionOptions
	if opts != nil {
		options = *opts
	}
	selectPathRenameVariant(spec, options.Programs.KernelTypes)
	bundle, err := loadGroupedCollections(runtimeModeCore, spec, options, ebpf.NewCollectionWithOptions)
	if err != nil {
		return loadedSensorObjects{}, fmt.Errorf("load core bpf objects: %w", err)
	}
	bindAvailableObjects(&objs.ransomwareMaps, bundle.maps, bundle.programs)
	bindAvailableObjects(&objs.ransomwarePrograms, bundle.maps, bundle.programs)
	if selected := bundle.programs["enforce_path_rename_legacy"]; selected != nil {
		objs.EnforcePathRename = selected
	}
	return loadedSensorObjects{
		closer:   bundle,
		maps:     coreMaps(objs),
		programs: corePrograms(objs),
		mode:     runtimeModeCore,
	}, nil
}

func coreCollectionOptions() (*ebpf.CollectionOptions, error) {
	btfPath := strings.TrimSpace(os.Getenv("EBPFFLS_BTF"))
	if btfPath == "" {
		return nil, nil
	}
	spec, err := btf.LoadSpec(btfPath)
	if err != nil {
		return nil, &configurationError{fmt.Errorf("load EBPFFLS_BTF=%q: %w", btfPath, err)}
	}
	log.Printf("btf source=%q", btfPath)
	return &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{KernelTypes: spec},
	}, nil
}

func loadLegacyPerfSensorObjects() (loadedSensorObjects, error) {
	var objs ransomwareLegacyObjects
	spec, err := loadRansomwareLegacy()
	if err != nil {
		return loadedSensorObjects{}, err
	}
	bundle, err := loadGroupedCollections(runtimeModeLegacyPerf, spec, ebpf.CollectionOptions{}, ebpf.NewCollectionWithOptions)
	if err != nil {
		return loadedSensorObjects{}, fmt.Errorf("load legacy_perf bpf objects: %w", err)
	}
	bindAvailableObjects(&objs.ransomwareLegacyMaps, bundle.maps, bundle.programs)
	bindAvailableObjects(&objs.ransomwareLegacyPrograms, bundle.maps, bundle.programs)
	return loadedSensorObjects{
		closer:   bundle,
		maps:     legacyPerfMaps(objs),
		programs: legacyPerfPrograms(objs),
		mode:     runtimeModeLegacyPerf,
	}, nil
}

type collectionBundle struct {
	collections []*ebpf.Collection
	maps        map[string]*ebpf.Map
	programs    map[string]*ebpf.Program
}

func (b *collectionBundle) Close() error {
	var closeErr error
	for i := len(b.collections) - 1; i >= 0; i-- {
		for _, program := range b.collections[i].Programs {
			closeErr = errors.Join(closeErr, program.Close())
		}
		for _, m := range b.collections[i].Maps {
			closeErr = errors.Join(closeErr, m.Close())
		}
	}
	b.collections = nil
	return closeErr
}

type collectionLoadFunc func(*ebpf.CollectionSpec, ebpf.CollectionOptions) (*ebpf.Collection, error)

func loadGroupedCollections(mode runtimeMode, spec *ebpf.CollectionSpec, options ebpf.CollectionOptions, load collectionLoadFunc) (*collectionBundle, error) {
	base := spec.Copy()
	var optional []string
	for name, program := range base.Programs {
		if program.Type == ebpf.LSM || strings.HasPrefix(name, "kp_override_") {
			optional = append(optional, name)
			delete(base.Programs, name)
		}
	}
	core, err := load(base, options)
	if err != nil {
		return nil, err
	}
	bundle := &collectionBundle{collections: []*ebpf.Collection{core}, maps: core.Maps, programs: make(map[string]*ebpf.Program)}
	for name, program := range core.Programs {
		bundle.programs[name] = program
	}
	sort.Strings(optional)
	for _, name := range optional {
		group := spec.Copy()
		group.Programs = map[string]*ebpf.ProgramSpec{name: group.Programs[name]}
		shared := options
		shared.MapReplacements = core.Maps
		loaded, err := load(group, shared)
		if err != nil {
			log.Printf("optional_bpf_program_unavailable mode=%s program=%s error=%v", mode, name, err)
			continue
		}
		bundle.collections = append(bundle.collections, loaded)
		bundle.programs[name] = loaded.Programs[name]
	}
	return bundle, nil
}

// Generated ebpf tags remain the binding authority, while absent optional
// programs deliberately stay nil instead of failing Collection.Assign.
func bindAvailableObjects(target interface{}, maps map[string]*ebpf.Map, programs map[string]*ebpf.Program) {
	value := reflect.ValueOf(target).Elem()
	for i := 0; i < value.NumField(); i++ {
		field := value.Field(i)
		name := value.Type().Field(i).Tag.Get("ebpf")
		switch field.Type() {
		case reflect.TypeOf((*ebpf.Map)(nil)):
			field.Set(reflect.ValueOf(maps[name]))
		case reflect.TypeOf((*ebpf.Program)(nil)):
			field.Set(reflect.ValueOf(programs[name]))
		}
	}
}

func selectPathRenameVariant(spec *ebpf.CollectionSpec, types *btf.Spec) {
	if _, exists := spec.Programs["enforce_path_rename_legacy"]; !exists {
		return
	}
	if types == nil {
		types, _ = btf.LoadKernelSpec()
	}
	var target *btf.Func
	selected := ""
	if types != nil && types.TypeByName("bpf_lsm_path_rename", &target) == nil {
		if prototype, ok := target.Type.(*btf.FuncProto); ok {
			selected = pathRenameVariant(len(prototype.Params))
		}
	}
	for _, name := range []string{"enforce_path_rename", "enforce_path_rename_legacy"} {
		if name != selected {
			delete(spec.Programs, name)
		}
	}
	if selected == "" {
		log.Printf("optional_bpf_program_unavailable hook=path_rename reason=unsupported_target_prototype")
	}
}

func pathRenameVariant(parameterCount int) string {
	switch parameterCount {
	case 4:
		return "enforce_path_rename_legacy"
	case 5:
		return "enforce_path_rename"
	default:
		return ""
	}
}

func loadUltraLegacyMapSensorObjects() (loadedSensorObjects, error) {
	if err := validateUltraLegacyArchitecture(runtime.GOARCH); err != nil {
		return loadedSensorObjects{}, err
	}
	var objs ransomwareUltraLegacyObjects
	if err := loadRansomwareUltraLegacyObjects(&objs, nil); err != nil {
		return loadedSensorObjects{}, fmt.Errorf("load ultra_legacy_map bpf objects: %w", err)
	}
	return loadedSensorObjects{
		closer:   &objs,
		maps:     ultraLegacyMapMaps(objs),
		programs: ultraLegacyMapPrograms(objs),
		mode:     runtimeModeUltraLegacyMap,
	}, nil
}

func validateUltraLegacyArchitecture(arch string) error {
	if arch != "amd64" {
		return fmt.Errorf("ultra_legacy_map requires amd64: its legacy pt_regs layout and event publication protocol do not support %s", arch)
	}
	return nil
}

func coreMaps(objs ransomwareObjects) sensorMaps {
	return sensorMaps{
		Events:             objs.Events,
		RingbufDrops:       objs.RingbufDrops,
		CaptureGaps:        objs.CaptureGaps,
		BlockedTgids:       objs.BlockedTgids,
		IocExtensions:      objs.IocExtensions,
		IocRansomNotes:     objs.IocRansomNotes,
		ProtectedDirs:      objs.ProtectedDirs,
		InlineIOCAction:    objs.InlineIocAction,
		AllowedCgroups:     objs.AllowedCgroups,
		CgroupScopeEnabled: objs.CgroupScopeEnabled,
	}
}

func legacyPerfMaps(objs ransomwareLegacyObjects) sensorMaps {
	return sensorMaps{
		Events:             objs.Events,
		RingbufDrops:       objs.RingbufDrops,
		CaptureGaps:        objs.CaptureGaps,
		BlockedTgids:       objs.BlockedTgids,
		IocExtensions:      objs.IocExtensions,
		IocRansomNotes:     objs.IocRansomNotes,
		ProtectedDirs:      objs.ProtectedDirs,
		AllowedCgroups:     objs.AllowedCgroups,
		CgroupScopeEnabled: objs.CgroupScopeEnabled,
	}
}

func ultraLegacyMapMaps(objs ransomwareUltraLegacyObjects) sensorMaps {
	return sensorMaps{
		Events:             objs.Events,
		EventCursor:        objs.EventCursor,
		RingbufDrops:       objs.RingbufDrops,
		CaptureGaps:        objs.CaptureGaps,
		SyscallABI:         objs.SyscallAbi,
		BlockedTgids:       objs.BlockedTgids,
		IocExtensions:      objs.IocExtensions,
		IocRansomNotes:     objs.IocRansomNotes,
		ProtectedDirs:      objs.ProtectedDirs,
		AllowedCgroups:     objs.AllowedCgroups,
		CgroupScopeEnabled: objs.CgroupScopeEnabled,
	}
}

func corePrograms(objs ransomwareObjects) sensorPrograms {
	return sensorPrograms{
		TraceExecve:              objs.TraceExecve,
		TraceExecSuccess:         objs.TraceExecSuccess,
		TraceProcessExit:         objs.TraceProcessExit,
		TraceOpenat:              objs.TraceOpenat,
		TraceOpenatExit:          objs.TraceOpenatExit,
		TraceOpenat2:             objs.TraceOpenat2,
		TraceOpenat2Exit:         objs.TraceOpenat2Exit,
		TraceWrite:               objs.TraceWrite,
		TraceWriteExit:           objs.TraceWriteExit,
		TracePwrite64:            objs.TracePwrite64,
		TracePwrite64Exit:        objs.TracePwrite64Exit,
		TraceWritev:              objs.TraceWritev,
		TraceWritevExit:          objs.TraceWritevExit,
		TraceCopyFileRange:       objs.TraceCopyFileRange,
		TraceGetdents64:          objs.TraceGetdents64,
		TraceMmap:                objs.TraceMmap,
		TraceIoUringEnter:        objs.TraceIoUringEnter,
		TraceConnect:             objs.TraceConnect,
		TraceClose:               objs.TraceClose,
		TraceDup:                 objs.TraceDup,
		TraceDupExit:             objs.TraceDupExit,
		TraceDup2:                objs.TraceDup2,
		TraceDup2Exit:            objs.TraceDup2Exit,
		TraceDup3:                objs.TraceDup3,
		TraceDup3Exit:            objs.TraceDup3Exit,
		TraceFcntl:               objs.TraceFcntl,
		TraceFcntlExit:           objs.TraceFcntlExit,
		TraceRename:              objs.TraceRename,
		TraceRenameat:            objs.TraceRenameat,
		TraceRenameat2:           objs.TraceRenameat2,
		TraceLink:                objs.TraceLink,
		TraceLinkat:              objs.TraceLinkat,
		TraceSymlink:             objs.TraceSymlink,
		TraceSymlinkat:           objs.TraceSymlinkat,
		TraceUnlink:              objs.TraceUnlink,
		TraceUnlinkat:            objs.TraceUnlinkat,
		TraceTruncate:            objs.TraceTruncate,
		TraceFtruncate:           objs.TraceFtruncate,
		EnforceFileOpen:          objs.EnforceFileOpen,
		EnforceFilePermission:    objs.EnforceFilePermission,
		EnforcePathTruncate:      objs.EnforcePathTruncate,
		EnforcePathRename:        objs.EnforcePathRename,
		EnforceInodeRename:       objs.EnforceInodeRename,
		EnforcePathMknod:         objs.EnforcePathMknod,
		EnforceInodeCreate:       objs.EnforceInodeCreate,
		EnforcePathUnlink:        objs.EnforcePathUnlink,
		EnforceBprmCheckSecurity: objs.EnforceBprmCheckSecurity,
		KpOverrideOpenat:         objs.KpOverrideOpenat,
		KpOverrideOpenat2:        objs.KpOverrideOpenat2,
		KpOverrideRename:         objs.KpOverrideRename,
		KpOverrideRenameat:       objs.KpOverrideRenameat,
		KpOverrideRenameat2:      objs.KpOverrideRenameat2,
		KpOverrideLink:           objs.KpOverrideLink,
		KpOverrideLinkat:         objs.KpOverrideLinkat,
		KpOverrideSymlink:        objs.KpOverrideSymlink,
		KpOverrideSymlinkat:      objs.KpOverrideSymlinkat,
		KpOverrideUnlink:         objs.KpOverrideUnlink,
		KpOverrideUnlinkat:       objs.KpOverrideUnlinkat,
		KpOverrideTruncate:       objs.KpOverrideTruncate,
		KpOverrideFtruncate:      objs.KpOverrideFtruncate,
		KpOverrideExecve:         objs.KpOverrideExecve,
		KpOverrideWrite:          objs.KpOverrideWrite,
		KpOverridePwrite64:       objs.KpOverridePwrite64,
		KpOverrideWritev:         objs.KpOverrideWritev,
		KpOverrideCopyFileRange:  objs.KpOverrideCopyFileRange,
		KpOverrideGetdents64:     objs.KpOverrideGetdents64,
		KpOverrideMmap:           objs.KpOverrideMmap,
		KpOverrideIoUringEnter:   objs.KpOverrideIoUringEnter,
	}
}

func legacyPerfPrograms(objs ransomwareLegacyObjects) sensorPrograms {
	return sensorPrograms{
		TraceExecve:             objs.TraceExecve,
		TraceExecSuccess:        objs.TraceExecSuccess,
		TraceProcessExit:        objs.TraceProcessExit,
		TraceOpenat:             objs.TraceOpenat,
		TraceOpenatExit:         objs.TraceOpenatExit,
		TraceOpenat2:            objs.TraceOpenat2,
		TraceOpenat2Exit:        objs.TraceOpenat2Exit,
		TraceWrite:              objs.TraceWrite,
		TraceWriteExit:          objs.TraceWriteExit,
		TracePwrite64:           objs.TracePwrite64,
		TracePwrite64Exit:       objs.TracePwrite64Exit,
		TraceWritev:             objs.TraceWritev,
		TraceWritevExit:         objs.TraceWritevExit,
		TraceCopyFileRange:      objs.TraceCopyFileRange,
		TraceGetdents64:         objs.TraceGetdents64,
		TraceMmap:               objs.TraceMmap,
		TraceIoUringEnter:       objs.TraceIoUringEnter,
		TraceConnect:            objs.TraceConnect,
		TraceClose:              objs.TraceClose,
		TraceDup:                objs.TraceDup,
		TraceDupExit:            objs.TraceDupExit,
		TraceDup2:               objs.TraceDup2,
		TraceDup2Exit:           objs.TraceDup2Exit,
		TraceDup3:               objs.TraceDup3,
		TraceDup3Exit:           objs.TraceDup3Exit,
		TraceFcntl:              objs.TraceFcntl,
		TraceFcntlExit:          objs.TraceFcntlExit,
		TraceRename:             objs.TraceRename,
		TraceRenameat:           objs.TraceRenameat,
		TraceRenameat2:          objs.TraceRenameat2,
		TraceLink:               objs.TraceLink,
		TraceLinkat:             objs.TraceLinkat,
		TraceSymlink:            objs.TraceSymlink,
		TraceSymlinkat:          objs.TraceSymlinkat,
		TraceUnlink:             objs.TraceUnlink,
		TraceUnlinkat:           objs.TraceUnlinkat,
		TraceTruncate:           objs.TraceTruncate,
		TraceFtruncate:          objs.TraceFtruncate,
		KpOverrideOpenat:        objs.KpOverrideOpenat,
		KpOverrideOpenat2:       objs.KpOverrideOpenat2,
		KpOverrideRename:        objs.KpOverrideRename,
		KpOverrideRenameat:      objs.KpOverrideRenameat,
		KpOverrideRenameat2:     objs.KpOverrideRenameat2,
		KpOverrideLink:          objs.KpOverrideLink,
		KpOverrideLinkat:        objs.KpOverrideLinkat,
		KpOverrideSymlink:       objs.KpOverrideSymlink,
		KpOverrideSymlinkat:     objs.KpOverrideSymlinkat,
		KpOverrideUnlink:        objs.KpOverrideUnlink,
		KpOverrideUnlinkat:      objs.KpOverrideUnlinkat,
		KpOverrideTruncate:      objs.KpOverrideTruncate,
		KpOverrideFtruncate:     objs.KpOverrideFtruncate,
		KpOverrideExecve:        objs.KpOverrideExecve,
		KpOverrideWrite:         objs.KpOverrideWrite,
		KpOverridePwrite64:      objs.KpOverridePwrite64,
		KpOverrideWritev:        objs.KpOverrideWritev,
		KpOverrideCopyFileRange: objs.KpOverrideCopyFileRange,
		KpOverrideGetdents64:    objs.KpOverrideGetdents64,
		KpOverrideMmap:          objs.KpOverrideMmap,
		KpOverrideIoUringEnter:  objs.KpOverrideIoUringEnter,
	}
}

func ultraLegacyMapPrograms(objs ransomwareUltraLegacyObjects) sensorPrograms {
	return sensorPrograms{
		KpOverrideOpen:      objs.KpOverrideOpen,
		KpOverrideOpenat:    objs.KpOverrideOpenat,
		KpRetOpen:           objs.KpRetOpen,
		KpRetOpenat:         objs.KpRetOpenat,
		KpOverrideRename:    objs.KpOverrideRename,
		KpOverrideLink:      objs.KpOverrideLink,
		KpOverrideSymlink:   objs.KpOverrideSymlink,
		KpOverrideUnlink:    objs.KpOverrideUnlink,
		KpOverrideTruncate:  objs.KpOverrideTruncate,
		KpOverrideFtruncate: objs.KpOverrideFtruncate,
		KpOverrideExecve:    objs.KpOverrideExecve,
		KpOverrideWrite:     objs.KpOverrideWrite,
		KpRetWrite:          objs.KpRetWrite,
		KpOverridePwrite64:  objs.KpOverridePwrite64,
		KpRetPwrite64:       objs.KpRetPwrite64,
		KpOverrideWritev:    objs.KpOverrideWritev,
		KpRetWritev:         objs.KpRetWritev,
		KpProcessExit:       objs.KpProcessExit,
	}
}

func nonNilPrograms(programs []*ebpf.Program) []*ebpf.Program {
	out := programs[:0]
	for _, prog := range programs {
		if prog != nil {
			out = append(out, prog)
		}
	}
	return out
}

func newEventReader(mode runtimeMode, events *ebpf.Map, eventCursor *ebpf.Map) (eventReader, error) {
	if events == nil {
		return nil, fmt.Errorf("events map missing")
	}
	if mode == runtimeModeUltraLegacyMap {
		if eventCursor == nil {
			return nil, fmt.Errorf("event cursor map missing")
		}
		rd := newMapPollingEventReader(events, eventCursor)
		if rd.initErr != nil {
			return nil, rd.initErr
		}
		if rd.guarded {
			possible, err := os.ReadFile("/sys/devices/system/cpu/possible")
			if err != nil {
				return nil, fmt.Errorf("read CPU coverage for sharded event map: %w", err)
			}
			if err := validateCPUShardCoverage(string(possible), uint32(len(rd.shards))); err != nil {
				return nil, err
			}
		}
		return rd, nil
	}
	if mode == runtimeModeLegacyPerf {
		rd, err := perf.NewReader(events, os.Getpagesize()*16)
		if err != nil {
			return nil, err
		}
		return &perfEventReader{Reader: rd}, nil
	}
	rd, err := ringbuf.NewReader(events)
	if err != nil {
		return nil, err
	}
	return ringbufEventReader{Reader: rd}, nil
}

type ringbufEventReader struct {
	*ringbuf.Reader
}

func (r ringbufEventReader) Read() (eventRecord, error) {
	record, err := r.Reader.Read()
	return eventRecord{RawSample: record.RawSample}, err
}

type perfEventReader struct {
	*perf.Reader
	lost atomic.Uint64
}

type pollingEventMap interface {
	Lookup(key, valueOut interface{}) error
	MaxEntries() uint32
	ValueSize() uint32
}

type pollingShard struct {
	tail uint64
	head uint64
}

type mapPollingEventReader struct {
	events      pollingEventMap
	cursor      pollingEventMap
	shards      []pollingShard
	slotsPerCPU uint32
	guarded     bool
	nextCPU     uint32
	pending     []eventRecord
	lost        atomic.Uint64
	initErr     error
	closed      chan struct{}
	once        sync.Once
}

func newMapPollingEventReader(events, cursor pollingEventMap) *mapPollingEventReader {
	r := &mapPollingEventReader{events: events, cursor: cursor, closed: make(chan struct{})}
	if events == nil || cursor == nil {
		r.initErr = fmt.Errorf("map polling requires events and cursor maps")
		return r
	}
	if err := validateUltraLegacySlotSize(events.ValueSize()); err != nil {
		r.initErr = err
		return r
	}
	shards := cursor.MaxEntries()
	if cursor.ValueSize() != 8 || shards == 0 || shards > ultraLegacyMaxCPUs || events.MaxEntries() == 0 || events.MaxEntries()%shards != 0 {
		r.initErr = fmt.Errorf("invalid map polling layout: cursor_entries=%d cursor_size=%d event_entries=%d", shards, cursor.ValueSize(), events.MaxEntries())
		return r
	}
	r.guarded = events.ValueSize() == 16+eventV2Size
	if shards > 1 && !r.guarded {
		r.initErr = fmt.Errorf("CPU-sharded event slots require commit sequence guards")
		return r
	}
	r.shards = make([]pollingShard, shards)
	r.slotsPerCPU = events.MaxEntries() / shards
	return r
}

func validateCPUShardCoverage(possible string, shards uint32) error {
	if strings.TrimSpace(possible) == "" {
		return fmt.Errorf("possible CPU list is empty")
	}
	for _, span := range strings.Split(strings.TrimSpace(possible), ",") {
		bounds := strings.Split(strings.TrimSpace(span), "-")
		if len(bounds) > 2 {
			return fmt.Errorf("invalid possible CPU range %q", span)
		}
		first, err := strconv.ParseUint(bounds[0], 10, 32)
		if err != nil {
			return fmt.Errorf("invalid possible CPU range %q", span)
		}
		last := first
		if len(bounds) == 2 {
			last, err = strconv.ParseUint(bounds[1], 10, 32)
			if err != nil || last < first {
				return fmt.Errorf("invalid possible CPU range %q", span)
			}
		}
		if last >= uint64(shards) {
			return fmt.Errorf("possible CPU %d exceeds event map coverage [0,%d); refusing incomplete collection", last, shards)
		}
	}
	return nil
}

func (r *mapPollingEventReader) Read() (eventRecord, error) {
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-r.closed:
			return eventRecord{}, io.ErrClosedPipe
		default:
		}
		if r.initErr != nil {
			return eventRecord{}, r.initErr
		}
		if len(r.pending) == 0 {
			if err := r.pollBatch(); err != nil {
				return eventRecord{}, err
			}
		}
		if len(r.pending) > 0 {
			record := r.pending[0]
			r.pending = r.pending[1:]
			return record, nil
		}

		select {
		case <-r.closed:
			return eventRecord{}, io.ErrClosedPipe
		case <-ticker.C:
		}
	}
}

func (r *mapPollingEventReader) pollBatch() error {
	active := make([]uint32, 0, len(r.shards)+mapPollingBatchSize)
	for offset := range r.shards {
		cpu := (r.nextCPU + uint32(offset)) % uint32(len(r.shards))
		shard := &r.shards[cpu]
		if err := r.cursor.Lookup(cpu, &shard.head); err != nil {
			return err
		}
		if shard.head < shard.tail {
			return fmt.Errorf("event cursor regressed on CPU %d: head=%d tail=%d", cpu, shard.head, shard.tail)
		}
		if unread := shard.head - shard.tail; unread > uint64(r.slotsPerCPU) {
			r.recordLoss(cpu, shard.tail+1, unread-uint64(r.slotsPerCPU))
			shard.tail = shard.head - uint64(r.slotsPerCPU)
		}
		if shard.tail < shard.head {
			active = append(active, cpu)
		}
	}
	for next := 0; next < len(active) && len(r.pending) < mapPollingBatchSize; next++ {
		cpu := active[next]
		shard := &r.shards[cpu]
		expected := shard.tail + 1
		slot := cpu*r.slotsPerCPU + uint32(shard.tail%uint64(r.slotsPerCPU))
		rawSlot := make([]byte, r.events.ValueSize())
		if err := r.events.Lookup(slot, rawSlot); err != nil {
			return err
		}
		seq := committedSlotSequence(rawSlot, r.guarded)
		if r.guarded && seq == expected {
			// ARRAY lookup copies are not atomic, and memcpy may read the slot
			// guards before its middle. Recheck publication after the full copy.
			confirmed := make([]byte, len(rawSlot))
			if err := r.events.Lookup(slot, confirmed); err != nil {
				return err
			}
			if confirmedSeq := committedSlotSequence(confirmed, true); confirmedSeq != expected {
				seq = confirmedSeq
			}
		}
		if seq == expected {
			shard.tail = expected
			r.pending = append(r.pending, eventRecord{RawSample: ultraLegacySlotEvent(rawSlot)})
			if shard.tail < shard.head {
				active = append(active, cpu)
			}
		} else if seq > expected {
			// The slot wrapped after its cursor snapshot. Catch up only through
			// that snapshot; the next batch will fetch the newer head.
			lastLost := min(seq-1, shard.head)
			r.recordLoss(cpu, expected, lastLost-shard.tail)
			shard.tail = lastLost
		}
		// Uncommitted or torn snapshots are retried without advancing tail.
		r.nextCPU = (cpu + 1) % uint32(len(r.shards))
	}
	// This orders the bounded snapshots, not events arriving after collection.
	// Per-CPU order is preserved; a global real-time ordering is not promised.
	sort.SliceStable(r.pending, func(i, j int) bool {
		return binary.NativeEndian.Uint64(r.pending[i].RawSample) < binary.NativeEndian.Uint64(r.pending[j].RawSample)
	})
	return nil
}

func committedSlotSequence(raw []byte, guarded bool) uint64 {
	if len(raw) < 8 {
		return 0
	}
	seq := binary.NativeEndian.Uint64(raw)
	if guarded && (len(raw) < 16 || binary.NativeEndian.Uint64(raw[len(raw)-8:]) != seq) {
		return 0
	}
	return seq
}

func (r *mapPollingEventReader) recordLoss(cpu uint32, first, count uint64) {
	if count == 0 {
		return
	}
	r.lost.Add(count)
	log.Printf("ultra_legacy_map_lost_event cpu=%d first_seq=%d lost=%d", cpu, first, count)
}

func ultraLegacySlotEvent(rawSlot []byte) []byte {
	if len(rawSlot) <= 8 {
		return nil
	}
	end := len(rawSlot)
	if end == 16+eventV2Size {
		end -= 8
	}
	raw := make([]byte, end-8)
	copy(raw, rawSlot[8:end])
	return raw
}

func validateUltraLegacySlotSize(size uint32) error {
	if size != 8+eventSize && size != 8+eventV2Size && size != 16+eventV2Size {
		return fmt.Errorf("unsupported ultra legacy event slot size: %d", size)
	}
	return nil
}

func (r *mapPollingEventReader) Close() error {
	r.once.Do(func() {
		close(r.closed)
	})
	return nil
}

func (r *perfEventReader) Read() (eventRecord, error) {
	for {
		record, err := r.Reader.Read()
		if err != nil {
			return eventRecord{}, err
		}
		if record.LostSamples > 0 {
			r.lost.Add(record.LostSamples)
			log.Printf("perf_lost_samples cpu=%d lost=%d", record.CPU, record.LostSamples)
			continue
		}
		return eventRecord{RawSample: record.RawSample}, nil
	}
}

type lsmAttachResult struct {
	lsmAttachSummary
	links []link.Link
}

func attachLSMPrograms(programs []*ebpf.Program, attach lsmAttachFunc) lsmAttachResult {
	var result lsmAttachResult
	for _, prog := range programs {
		l, err := attach(prog)
		if err != nil {
			log.Printf("optional BPF LSM %s unavailable: %v", lsmProgramName(prog), err)
			result.Skipped++
			continue
		}
		if l != nil {
			result.links = append(result.links, l)
		}
		result.Attached++
	}
	return result
}

func lsmProgramName(prog *ebpf.Program) string {
	if prog == nil {
		return "<nil>"
	}
	return prog.String()
}

func bpfLSMActive() bool {
	data, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return false
	}
	return bpfLSMActiveFromData(string(data))
}

func bpfLSMActiveFromData(data string) bool {
	for _, lsm := range strings.Split(strings.TrimSpace(data), ",") {
		if lsm == "bpf" {
			return true
		}
	}
	return false
}

func attachKprobe(op string, prog *ebpf.Program) (link.Link, string, error) {
	return attachKprobeWith(op, prog, attachEntryKprobe, nil)
}

type kprobeAttachFunc func(symbol string, prog *ebpf.Program) (link.Link, error)

func attachEntryKprobe(symbol string, prog *ebpf.Program) (link.Link, error) {
	return link.Kprobe(symbol, prog, nil)
}

func attachReturnKprobe(symbol string, prog *ebpf.Program) (link.Link, error) {
	return link.Kretprobe(symbol, prog, nil)
}

func attachKprobeWith(op string, prog *ebpf.Program, attach kprobeAttachFunc, configure func(string) error) (link.Link, string, error) {
	var errs []string
	for _, symbol := range kprobeSymbols(op, runtime.GOARCH) {
		l, err := attach(symbol, prog)
		if err == nil {
			if configure != nil {
				if err := configure(symbol); err != nil {
					if l != nil {
						l.Close()
					}
					return nil, "", fmt.Errorf("configure kprobe %s: %w", symbol, err)
				}
			}
			return l, symbol, nil
		}
		errs = append(errs, fmt.Sprintf("%s: %v", symbol, err))
	}
	return nil, "", errors.New(strings.Join(errs, "; "))
}

func attachKretprobe(op string, prog *ebpf.Program) (link.Link, string, error) {
	var errs []string
	for _, symbol := range kprobeSymbols(op, runtime.GOARCH) {
		l, err := link.Kretprobe(symbol, prog, nil)
		if err == nil {
			return l, symbol, nil
		}
		errs = append(errs, fmt.Sprintf("%s: %v", symbol, err))
	}
	return nil, "", errors.New(strings.Join(errs, "; "))
}

func attachKprobePair(op string, entry, exit *ebpf.Program) ([]link.Link, string, error) {
	return attachKprobePairWith(op, entry, exit, attachEntryKprobe, attachReturnKprobe, nil)
}

func attachKprobePairWith(op string, entry, exit *ebpf.Program, attachEntry, attachExit kprobeAttachFunc, configure func(string) error) ([]link.Link, string, error) {
	if entry == nil || exit == nil {
		return nil, "", fmt.Errorf("missing entry or exit program for %s", op)
	}
	var errs []string
	for _, symbol := range kprobeSymbols(op, runtime.GOARCH) {
		entryLink, err := attachEntry(symbol, entry)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s entry: %v", symbol, err))
			continue
		}
		// Both probes must observe the same wrapper, or arguments and returns
		// can belong to different nesting levels of one syscall invocation.
		exitLink, err := attachExit(symbol, exit)
		if err == nil {
			if configure != nil {
				if err := configure(symbol); err != nil {
					if entryLink != nil {
						entryLink.Close()
					}
					if exitLink != nil {
						exitLink.Close()
					}
					return nil, "", fmt.Errorf("configure kprobe pair %s: %w", symbol, err)
				}
			}
			return []link.Link{entryLink, exitLink}, symbol, nil
		}
		if entryLink != nil {
			entryLink.Close()
		}
		errs = append(errs, fmt.Sprintf("%s exit: %v", symbol, err))
	}
	return nil, "", errors.New(strings.Join(errs, "; "))
}

func kprobeSymbols(op, arch string) []string {
	switch arch {
	case "amd64":
		return []string{"__x64_sys_" + op, "__se_sys_" + op, "sys_" + op}
	case "arm64":
		return []string{"__arm64_sys_" + op, "__se_sys_" + op, "sys_" + op}
	default:
		return []string{"__" + arch + "_sys_" + op, "__se_sys_" + op, "sys_" + op}
	}
}

func (s *Sensor) configureKprobeABI(op, symbol string) error {
	if s.mode != runtimeModeUltraLegacyMap {
		return nil
	}
	if s.maps.SyscallABI == nil {
		return fmt.Errorf("syscall ABI map missing")
	}
	key, abi, err := syscallABIForSymbol(op, symbol)
	if err != nil {
		return err
	}
	if err := s.maps.SyscallABI.Put(key, abi); err != nil {
		return fmt.Errorf("write syscall ABI op=%s symbol=%s: %w", op, symbol, err)
	}
	log.Printf("configured_syscall_abi op=%s symbol=%s abi=%d", op, symbol, abi)
	return nil
}

func syscallABIForSymbol(op, symbol string) (uint32, uint32, error) {
	// Keys mirror enum syscall_abi_op in the ultra-legacy BPF object.
	var key uint32
	switch op {
	case "execve":
		key = 1
	case "open":
		key = 2
	case "openat":
		key = 3
	case "write":
		key = 4
	case "pwrite64":
		key = 5
	case "writev":
		key = 6
	case "rename":
		key = 7
	case "link":
		key = 8
	case "symlink":
		key = 9
	case "unlink":
		key = 10
	case "truncate":
		key = 11
	case "ftruncate":
		key = 12
	default:
		return 0, 0, fmt.Errorf("unsupported syscall ABI operation %q", op)
	}
	switch symbol {
	case "__x64_sys_" + op:
		return key, 2, nil
	case "__se_sys_" + op, "sys_" + op:
		return key, 1, nil
	default:
		return 0, 0, fmt.Errorf("unsupported syscall ABI symbol %q for %s", symbol, op)
	}
}

func (s *Sensor) BlockTGID(tgid uint32, action uint32, ttl time.Duration) error {
	if s == nil || s.maps.BlockedTgids == nil {
		return fmt.Errorf("blocked tgids map missing")
	}
	if tgid == 0 {
		return fmt.Errorf("tgid must be non-zero")
	}
	if action != BlockActionDeny && action != BlockActionKill {
		return fmt.Errorf("unsupported block action %d", action)
	}
	if action == BlockActionDeny && !s.capabilities.DenyAvailable {
		return fmt.Errorf("%w: mode=%s", ErrDenyUnavailable, s.mode)
	}
	entry := BlockEntry{
		Reason: BlockReasonPolicy,
		Action: action,
	}
	if ttl > 0 {
		uptime, err := monotonicUptime()
		if err != nil {
			return err
		}
		entry.ExpiresNs = uint64((uptime + ttl).Nanoseconds())
	}
	return s.maps.BlockedTgids.Put(tgid, entry)
}

func (s *Sensor) UnblockTGID(tgid uint32) error {
	if s == nil || s.maps.BlockedTgids == nil {
		return fmt.Errorf("blocked tgids map missing")
	}
	if tgid == 0 {
		return fmt.Errorf("tgid must be non-zero")
	}
	return s.maps.BlockedTgids.Delete(tgid)
}

func (s *Sensor) ConfigurePolicy(policy config.Policy) error {
	extensions, err := syncHashSet(s.maps.IocExtensions, policy.SuspiciousExtensions, iocHash)
	if err != nil {
		return fmt.Errorf("sync suspicious extensions: %w", err)
	}
	notes, err := syncHashSet(s.maps.IocRansomNotes, policy.RansomNoteNames, iocHash)
	if err != nil {
		return fmt.Errorf("sync ransom note names: %w", err)
	}
	protected, err := syncProtectedDirs(s.maps.ProtectedDirs, policy.ProtectedDirs)
	if err != nil {
		return fmt.Errorf("sync protected dirs: %w", err)
	}
	cgroups, err := syncCgroupScope(s.maps.AllowedCgroups, s.maps.CgroupScopeEnabled, policy.CgroupPaths)
	if err != nil {
		return fmt.Errorf("sync cgroup scope: %w", err)
	}
	log.Printf("synced_bpf_policy ioc_extensions=%d ransom_notes=%d protected_dirs=%d cgroup_scope=%d", extensions, notes, protected, cgroups)
	return nil
}

func (s *Sensor) ConfigureEnforcement(action string, dryRun bool) error {
	if s == nil {
		return fmt.Errorf("sensor missing")
	}

	var value uint32
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "log":
	case "deny":
		value = BlockActionDeny
	case "kill":
		value = BlockActionKill
	default:
		return fmt.Errorf("unsupported enforcement action %q", action)
	}
	if dryRun {
		value = 0
	}
	if s.maps.InlineIOCAction == nil {
		log.Printf("synced_bpf_enforcement inline_ioc_action=unavailable requested=%s dry_run=%t", actionName(value), dryRun)
		return nil
	}
	if err := s.maps.InlineIOCAction.Put(uint32(0), value); err != nil {
		return fmt.Errorf("sync inline IOC action: %w", err)
	}
	log.Printf("synced_bpf_enforcement inline_ioc_action=%s dry_run=%t", actionName(value), dryRun)
	return nil
}

func actionName(action uint32) string {
	switch action {
	case 0:
		return "observe"
	case BlockActionDeny:
		return "deny"
	case BlockActionKill:
		return "kill"
	default:
		return fmt.Sprintf("unknown(%d)", action)
	}
}

func (s *Sensor) RingbufDrops() (uint64, error) {
	if s.maps.RingbufDrops == nil {
		return 0, nil
	}
	var drops uint64
	if err := s.maps.RingbufDrops.Lookup(uint32(0), &drops); err != nil {
		return 0, err
	}
	return drops, nil
}

func (s *Sensor) CaptureGaps() (uint64, error) {
	var gaps uint64
	if s.maps.CaptureGaps != nil {
		if err := s.maps.CaptureGaps.Lookup(uint32(0), &gaps); err != nil {
			return 0, err
		}
	}
	switch reader := s.reader.(type) {
	case *mapPollingEventReader:
		gaps += reader.lost.Load()
	case *perfEventReader:
		gaps += reader.lost.Load()
	}
	return gaps, nil
}

func syncHashSet(m *ebpf.Map, values []string, hash func(string) uint64) (int, error) {
	if m == nil {
		return 0, fmt.Errorf("map missing")
	}
	if hash == nil {
		return 0, fmt.Errorf("hash function missing")
	}
	if err := clearMap(m); err != nil {
		return 0, err
	}
	var one uint8 = 1
	count := 0
	seen := make(map[uint64]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := hash(value)
		if _, ok := seen[key]; ok {
			continue
		}
		if err := m.Put(key, one); err != nil {
			return 0, err
		}
		seen[key] = struct{}{}
		count++
	}
	return count, nil
}

func syncProtectedDirs(m *ebpf.Map, dirs []string) (int, error) {
	if m == nil {
		return 0, fmt.Errorf("map missing")
	}
	if err := clearMap(m); err != nil {
		return 0, err
	}
	var one uint8 = 1
	count := 0
	seen := make(map[dirKey]struct{}, len(dirs))
	for _, dir := range dirs {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			continue
		}
		info, err := os.Stat(dir)
		if err != nil {
			log.Printf("skip protected_dir=%q for BPF IOC scope: %v", dir, err)
			continue
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			log.Printf("skip protected_dir=%q for BPF IOC scope: missing stat data", dir)
			continue
		}
		key := dirKey{Dev: uint64(stat.Dev), Ino: stat.Ino}
		if _, ok := seen[key]; ok {
			continue
		}
		if err := m.Put(key, one); err != nil {
			return 0, err
		}
		seen[key] = struct{}{}
		count++
	}
	return count, nil
}

func syncCgroupScope(allowed *ebpf.Map, enabled *ebpf.Map, paths []string) (int, error) {
	if allowed == nil || enabled == nil {
		return 0, fmt.Errorf("cgroup scope map missing")
	}
	if err := clearMap(allowed); err != nil {
		return 0, err
	}
	var key uint32
	if len(paths) == 0 {
		var off uint8
		if err := enabled.Put(key, off); err != nil {
			return 0, err
		}
		return 0, nil
	}

	var one uint8 = 1
	count := 0
	ids := make(map[uint64]struct{}, len(paths))
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		cgroupPath := cgroupFSPath(path)
		if cgroupPath == "" {
			log.Printf("skip cgroup_path=%q for BPF scope: path escapes cgroup root", path)
			continue
		}
		info, err := os.Stat(cgroupPath)
		if err != nil {
			log.Printf("skip cgroup_path=%q for BPF scope: %v", path, err)
			continue
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			log.Printf("skip cgroup_path=%q for BPF scope: missing stat data", path)
			continue
		}
		cgid := uint64(stat.Ino)
		if _, ok := ids[cgid]; ok {
			continue
		}
		if err := allowed.Put(cgid, one); err != nil {
			return 0, err
		}
		ids[cgid] = struct{}{}
		count++
	}
	var on uint8
	if count > 0 {
		on = 1
	}
	if err := enabled.Put(key, on); err != nil {
		return 0, err
	}
	return count, nil
}

func cgroupFSPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" || path == "/" {
		return "/sys/fs/cgroup"
	}
	relative := filepath.Clean(strings.TrimPrefix(path, "/"))
	if relative == ".." || strings.HasPrefix(relative, "../") {
		return ""
	}
	return filepath.Join("/sys/fs/cgroup", relative)
}

func clearMap(m *ebpf.Map) error {
	if m == nil {
		return fmt.Errorf("map missing")
	}
	var keys []any
	var key any
	var value any
	switch m.KeySize() {
	case 8:
		var k uint64
		key = &k
	case 16:
		var k dirKey
		key = &k
	default:
		return fmt.Errorf("unsupported key size %d", m.KeySize())
	}
	var v uint8
	value = &v
	it := m.Iterate()
	for it.Next(key, value) {
		switch typed := key.(type) {
		case *uint64:
			keys = append(keys, *typed)
		case *dirKey:
			keys = append(keys, *typed)
		}
	}
	if err := it.Err(); err != nil {
		return err
	}
	for _, key := range keys {
		if err := m.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	return nil
}

func iocHash(value string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(strings.ToLower(value)))
	return h.Sum64()
}

func (s *Sensor) Events(ctx context.Context) (<-chan Event, <-chan error) {
	if ctx == nil {
		ctx = context.Background()
	}
	events := make(chan Event, 1024)
	errs := make(chan error, 1)

	go func() {
		defer close(events)
		defer close(errs)
		if s == nil || s.reader == nil {
			errs <- fmt.Errorf("event reader missing")
			return
		}
		stopCloser := make(chan struct{})
		go func() {
			select {
			case <-ctx.Done():
				_ = s.reader.Close()
			case <-stopCloser:
			}
		}()
		defer close(stopCloser)

		for {
			record, err := s.reader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, perf.ErrClosed) || ctx.Err() != nil {
					return
				}
				select {
				case errs <- fmt.Errorf("read event reader: %w", err):
				case <-ctx.Done():
				}
				return
			}
			ev, err := DecodeEvent(record.RawSample)
			if err != nil {
				select {
				case errs <- err:
				default:
				}
				continue
			}
			select {
			case events <- ev:
			case <-ctx.Done():
				return
			}
		}
	}()

	return events, errs
}

func (s *Sensor) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		if s.reader != nil {
			s.closeErr = errors.Join(s.closeErr, s.reader.Close())
		}
		for _, l := range s.links {
			if l != nil {
				s.closeErr = errors.Join(s.closeErr, l.Close())
			}
		}
		if s.closer != nil {
			s.closeErr = errors.Join(s.closeErr, s.closer.Close())
		}
	})
	return s.closeErr
}
