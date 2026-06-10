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
	"runtime"
	"strings"
	"sync"
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
	BlockReasonPolicy uint32 = 1

	BlockActionDeny uint32 = 1
	BlockActionKill uint32 = 2

	ultraLegacyEventSlots = 1024
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
	closer   interface{ Close() error }
	maps     sensorMaps
	programs sensorPrograms
	links    []link.Link
	reader   eventReader
	mode     runtimeMode
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
	BlockedTgids       *ebpf.Map
	IocExtensions      *ebpf.Map
	IocRansomNotes     *ebpf.Map
	ProtectedDirs      *ebpf.Map
	AllowedCgroups     *ebpf.Map
	CgroupScopeEnabled *ebpf.Map
}

type sensorPrograms struct {
	TraceExecve        *ebpf.Program
	TraceOpenat        *ebpf.Program
	TraceOpenatExit    *ebpf.Program
	TraceOpenat2       *ebpf.Program
	TraceOpenat2Exit   *ebpf.Program
	TraceWrite         *ebpf.Program
	TracePwrite64      *ebpf.Program
	TraceWritev        *ebpf.Program
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
	KpOverridePwrite64      *ebpf.Program
	KpOverrideWritev        *ebpf.Program
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
	loaded, err := loadSensorObjects()
	if err != nil {
		return nil, err
	}

	s := &Sensor{
		closer:   loaded.closer,
		maps:     loaded.maps,
		programs: loaded.programs,
		mode:     loaded.mode,
	}
	log.Printf("bpf_runtime mode=%s", s.mode)
	if err := s.ConfigurePolicy(policy); err != nil {
		s.Close()
		return nil, err
	}

	if err := s.attachTracepoints(); err != nil {
		s.Close()
		return nil, err
	}
	if err := s.attachLSMPrograms(); err != nil {
		s.Close()
		return nil, err
	}
	if err := s.attachKprobePrograms(); err != nil {
		s.Close()
		return nil, err
	}

	rd, err := newEventReader(s.mode, s.maps.Events, s.maps.EventCursor)
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("open event reader: %w", err)
	}
	s.reader = rd
	return s, nil
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
		{"syscalls", "sys_enter_openat", s.programs.TraceOpenat, false},
		{"syscalls", "sys_exit_openat", s.programs.TraceOpenatExit, false},
		{"syscalls", "sys_enter_openat2", s.programs.TraceOpenat2, true},
		{"syscalls", "sys_exit_openat2", s.programs.TraceOpenat2Exit, true},
		{"syscalls", "sys_enter_write", s.programs.TraceWrite, false},
		{"syscalls", "sys_enter_pwrite64", s.programs.TracePwrite64, false},
		{"syscalls", "sys_enter_writev", s.programs.TraceWritev, false},
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
	return nil
}

func (s *Sensor) attachLSMPrograms() error {
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
			return link.AttachLSM(link.LSMOptions{Program: prog})
		})
	} else {
		log.Printf("optional BPF LSM inactive in /sys/kernel/security/lsm; skipping LSM attach")
	}
	s.links = append(s.links, lsmSummary.links...)
	log.Printf("bpf_lsm attached=%d skipped=%d mode=optional", lsmSummary.Attached, lsmSummary.Skipped)
	return nil
}

func (s *Sensor) attachKprobePrograms() error {
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
		optional := kp.optional || s.mode == runtimeModeLegacyPerf || s.mode == runtimeModeUltraLegacyMap
		if kp.prog == nil {
			if optional {
				log.Printf("optional override kprobe op=%s unavailable in bpf object", kp.op)
				continue
			}
			return fmt.Errorf("missing required override kprobe program %s", kp.op)
		}
		l, symbol, err := attachKprobe(kp.op, kp.prog)
		if err != nil {
			if optional {
				log.Printf("optional override kprobe op=%s unavailable: %v", kp.op, err)
				continue
			}
			return fmt.Errorf("attach override kprobe %s: %w", kp.op, err)
		}
		log.Printf("attached override kprobe op=%s symbol=%s", kp.op, symbol)
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
	if err := loadRansomwareObjects(&objs, opts); err != nil {
		return loadedSensorObjects{}, fmt.Errorf("load core bpf objects: %w", err)
	}
	return loadedSensorObjects{
		closer:   &objs,
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
		return nil, fmt.Errorf("load EBPFFLS_BTF=%q: %w", btfPath, err)
	}
	log.Printf("btf source=%q", btfPath)
	return &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{KernelTypes: spec},
	}, nil
}

func loadLegacyPerfSensorObjects() (loadedSensorObjects, error) {
	var objs ransomwareLegacyObjects
	if err := loadRansomwareLegacyObjects(&objs, nil); err != nil {
		return loadedSensorObjects{}, fmt.Errorf("load legacy_perf bpf objects: %w", err)
	}
	return loadedSensorObjects{
		closer:   &objs,
		maps:     legacyPerfMaps(objs),
		programs: legacyPerfPrograms(objs),
		mode:     runtimeModeLegacyPerf,
	}, nil
}

func loadUltraLegacyMapSensorObjects() (loadedSensorObjects, error) {
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

func coreMaps(objs ransomwareObjects) sensorMaps {
	return sensorMaps{
		Events:             objs.Events,
		RingbufDrops:       objs.RingbufDrops,
		BlockedTgids:       objs.BlockedTgids,
		IocExtensions:      objs.IocExtensions,
		IocRansomNotes:     objs.IocRansomNotes,
		ProtectedDirs:      objs.ProtectedDirs,
		AllowedCgroups:     objs.AllowedCgroups,
		CgroupScopeEnabled: objs.CgroupScopeEnabled,
	}
}

func legacyPerfMaps(objs ransomwareLegacyObjects) sensorMaps {
	return sensorMaps{
		Events:             objs.Events,
		RingbufDrops:       objs.RingbufDrops,
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
		TraceOpenat:              objs.TraceOpenat,
		TraceOpenatExit:          objs.TraceOpenatExit,
		TraceOpenat2:             objs.TraceOpenat2,
		TraceOpenat2Exit:         objs.TraceOpenat2Exit,
		TraceWrite:               objs.TraceWrite,
		TracePwrite64:            objs.TracePwrite64,
		TraceWritev:              objs.TraceWritev,
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
		TraceOpenat:             objs.TraceOpenat,
		TraceOpenatExit:         objs.TraceOpenatExit,
		TraceOpenat2:            objs.TraceOpenat2,
		TraceOpenat2Exit:        objs.TraceOpenat2Exit,
		TraceWrite:              objs.TraceWrite,
		TracePwrite64:           objs.TracePwrite64,
		TraceWritev:             objs.TraceWritev,
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
		KpOverridePwrite64:  objs.KpOverridePwrite64,
		KpOverrideWritev:    objs.KpOverrideWritev,
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
		return newMapPollingEventReader(events, eventCursor), nil
	}
	if mode == runtimeModeLegacyPerf {
		rd, err := perf.NewReader(events, os.Getpagesize()*16)
		if err != nil {
			return nil, err
		}
		return perfEventReader{Reader: rd}, nil
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
}

type mapPollingEventReader struct {
	events *ebpf.Map
	cursor *ebpf.Map
	tail   uint64
	closed chan struct{}
	once   sync.Once
}

func newMapPollingEventReader(events, cursor *ebpf.Map) *mapPollingEventReader {
	return &mapPollingEventReader{
		events: events,
		cursor: cursor,
		closed: make(chan struct{}),
	}
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

		var head uint64
		if err := r.cursor.Lookup(uint32(0), &head); err != nil {
			return eventRecord{}, err
		}
		if r.tail < head {
			seq := r.tail + 1
			slot := uint32(r.tail % ultraLegacyEventSlots)
			rawSlot := make([]byte, 8+eventSize)
			if err := r.events.Lookup(slot, rawSlot); err != nil {
				return eventRecord{}, err
			}
			if binary.LittleEndian.Uint64(rawSlot[:8]) != seq {
				r.tail++
				log.Printf("ultra_legacy_map_lost_event expected_seq=%d slot=%d", seq, slot)
				continue
			}
			r.tail++
			return eventRecord{RawSample: ultraLegacySlotEvent(rawSlot)}, nil
		}

		select {
		case <-r.closed:
			return eventRecord{}, io.ErrClosedPipe
		case <-ticker.C:
		}
	}
}

func ultraLegacySlotEvent(rawSlot []byte) []byte {
	raw := make([]byte, eventSize)
	if len(rawSlot) <= 8 {
		return raw
	}
	copy(raw, rawSlot[8:])
	return raw
}

func (r *mapPollingEventReader) Close() error {
	r.once.Do(func() {
		close(r.closed)
	})
	return nil
}

func (r perfEventReader) Read() (eventRecord, error) {
	for {
		record, err := r.Reader.Read()
		if err != nil {
			return eventRecord{}, err
		}
		if record.LostSamples > 0 {
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
	var errs []string
	for _, symbol := range kprobeSymbols(op, runtime.GOARCH) {
		l, err := link.Kprobe(symbol, prog, nil)
		if err == nil {
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

func kprobeSymbols(op, arch string) []string {
	switch arch {
	case "amd64":
		return []string{"__x64_sys_" + op, "__se_sys_" + op}
	case "arm64":
		return []string{"__arm64_sys_" + op, "__se_sys_" + op}
	default:
		return []string{"__" + arch + "_sys_" + op, "__se_sys_" + op}
	}
}

func (s *Sensor) BlockTGID(tgid uint32, action uint32, ttl time.Duration) error {
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

func syncHashSet(m *ebpf.Map, values []string, hash func(string) uint64) (int, error) {
	if err := clearMap(m); err != nil {
		return 0, err
	}
	var one uint8 = 1
	count := 0
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := hash(value)
		if err := m.Put(key, one); err != nil {
			return 0, err
		}
		count++
	}
	return count, nil
}

func syncProtectedDirs(m *ebpf.Map, dirs []string) (int, error) {
	if err := clearMap(m); err != nil {
		return 0, err
	}
	var one uint8 = 1
	count := 0
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
		if err := m.Put(key, one); err != nil {
			return 0, err
		}
		count++
	}
	return count, nil
}

func syncCgroupScope(allowed *ebpf.Map, enabled *ebpf.Map, paths []string) (int, error) {
	if err := clearMap(allowed); err != nil {
		return 0, err
	}
	var key uint32
	var on uint8
	if len(paths) > 0 {
		on = 1
	}
	if err := enabled.Put(key, on); err != nil {
		return 0, err
	}
	if on == 0 {
		return 0, nil
	}

	var one uint8 = 1
	count := 0
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		cgroupPath := cgroupFSPath(path)
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
		if err := allowed.Put(cgid, one); err != nil {
			return 0, err
		}
		count++
	}
	return count, nil
}

func cgroupFSPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" || path == "/" {
		return "/sys/fs/cgroup"
	}
	return filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(path, "/"))
}

func clearMap(m *ebpf.Map) error {
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
	events := make(chan Event, 1024)
	errs := make(chan error, 1)

	go func() {
		defer close(events)
		defer close(errs)
		go func() {
			<-ctx.Done()
			_ = s.reader.Close()
		}()

		for {
			record, err := s.reader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, perf.ErrClosed) || ctx.Err() != nil {
					return
				}
				errs <- fmt.Errorf("read event reader: %w", err)
				return
			}
			ev, err := DecodeEvent(record.RawSample)
			if err != nil {
				errs <- err
				continue
			}
			events <- ev
		}
	}()

	return events, errs
}

func (s *Sensor) Close() error {
	var err error
	if s.reader != nil {
		err = errors.Join(err, s.reader.Close())
	}
	for _, l := range s.links {
		err = errors.Join(err, l.Close())
	}
	if s.closer != nil {
		err = errors.Join(err, s.closer.Close())
	}
	return err
}
