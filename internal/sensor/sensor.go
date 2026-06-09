package sensor

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"log"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/panzhenyu/ebpffls/internal/config"
)

const (
	BlockReasonPolicy uint32 = 1

	BlockActionDeny uint32 = 1
	BlockActionKill uint32 = 2
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
	objects ransomwareObjects
	links   []link.Link
	reader  *ringbuf.Reader
}

func New(policy config.Policy) (*Sensor, error) {
	var objs ransomwareObjects
	if err := loadRansomwareObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load bpf objects: %w", err)
	}

	s := &Sensor{objects: objs}
	if err := s.ConfigurePolicy(policy); err != nil {
		s.Close()
		return nil, err
	}

	tracepoints := []struct {
		category string
		name     string
		prog     *ebpf.Program
		optional bool
	}{
		{"syscalls", "sys_enter_execve", objs.TraceExecve, false},
		{"syscalls", "sys_enter_openat", objs.TraceOpenat, false},
		{"syscalls", "sys_exit_openat", objs.TraceOpenatExit, false},
		{"syscalls", "sys_enter_openat2", objs.TraceOpenat2, false},
		{"syscalls", "sys_exit_openat2", objs.TraceOpenat2Exit, false},
		{"syscalls", "sys_enter_write", objs.TraceWrite, false},
		{"syscalls", "sys_enter_pwrite64", objs.TracePwrite64, false},
		{"syscalls", "sys_enter_writev", objs.TraceWritev, false},
		{"syscalls", "sys_enter_copy_file_range", objs.TraceCopyFileRange, false},
		{"syscalls", "sys_enter_getdents64", objs.TraceGetdents64, false},
		{"syscalls", "sys_enter_mmap", objs.TraceMmap, false},
		{"syscalls", "sys_enter_io_uring_enter", objs.TraceIoUringEnter, true},
		{"syscalls", "sys_enter_connect", objs.TraceConnect, true},
		{"syscalls", "sys_enter_close", objs.TraceClose, false},
		{"syscalls", "sys_enter_dup", objs.TraceDup, false},
		{"syscalls", "sys_exit_dup", objs.TraceDupExit, false},
		{"syscalls", "sys_enter_dup2", objs.TraceDup2, false},
		{"syscalls", "sys_exit_dup2", objs.TraceDup2Exit, false},
		{"syscalls", "sys_enter_dup3", objs.TraceDup3, false},
		{"syscalls", "sys_exit_dup3", objs.TraceDup3Exit, false},
		{"syscalls", "sys_enter_fcntl", objs.TraceFcntl, false},
		{"syscalls", "sys_exit_fcntl", objs.TraceFcntlExit, false},
		{"syscalls", "sys_enter_rename", objs.TraceRename, false},
		{"syscalls", "sys_enter_renameat", objs.TraceRenameat, false},
		{"syscalls", "sys_enter_renameat2", objs.TraceRenameat2, false},
		{"syscalls", "sys_enter_unlink", objs.TraceUnlink, false},
		{"syscalls", "sys_enter_unlinkat", objs.TraceUnlinkat, false},
		{"syscalls", "sys_enter_truncate", objs.TraceTruncate, false},
		{"syscalls", "sys_enter_ftruncate", objs.TraceFtruncate, false},
	}
	for _, tp := range tracepoints {
		l, err := link.Tracepoint(tp.category, tp.name, tp.prog, nil)
		if err != nil {
			if tp.optional {
				log.Printf("optional tracepoint %s/%s unavailable: %v", tp.category, tp.name, err)
				continue
			}
			s.Close()
			return nil, fmt.Errorf("attach tracepoint %s/%s: %w", tp.category, tp.name, err)
		}
		s.links = append(s.links, l)
	}

	lsms := []*ebpf.Program{
		objs.EnforceFileOpen,
		objs.EnforceFilePermission,
		objs.EnforcePathTruncate,
		objs.EnforcePathRename,
		objs.EnforceInodeRename,
		objs.EnforcePathMknod,
		objs.EnforceInodeCreate,
		objs.EnforcePathUnlink,
		objs.EnforceBprmCheckSecurity,
	}
	for _, prog := range lsms {
		l, err := link.AttachLSM(link.LSMOptions{Program: prog})
		if err != nil {
			s.Close()
			return nil, fmt.Errorf("attach BPF LSM %s: %w", prog.String(), err)
		}
		s.links = append(s.links, l)
	}

	kprobes := []struct {
		op       string
		prog     *ebpf.Program
		optional bool
	}{
		{"openat", objs.KpOverrideOpenat, false},
		{"openat2", objs.KpOverrideOpenat2, false},
		{"rename", objs.KpOverrideRename, false},
		{"renameat", objs.KpOverrideRenameat, false},
		{"renameat2", objs.KpOverrideRenameat2, false},
		{"unlink", objs.KpOverrideUnlink, false},
		{"unlinkat", objs.KpOverrideUnlinkat, false},
		{"truncate", objs.KpOverrideTruncate, false},
		{"ftruncate", objs.KpOverrideFtruncate, false},
		{"execve", objs.KpOverrideExecve, false},
		{"write", objs.KpOverrideWrite, false},
		{"pwrite64", objs.KpOverridePwrite64, false},
		{"writev", objs.KpOverrideWritev, false},
		{"copy_file_range", objs.KpOverrideCopyFileRange, false},
		{"getdents64", objs.KpOverrideGetdents64, false},
		{"mmap", objs.KpOverrideMmap, false},
		{"io_uring_enter", objs.KpOverrideIoUringEnter, true},
	}
	for _, kp := range kprobes {
		l, symbol, err := attachKprobe(kp.op, kp.prog)
		if err != nil {
			if kp.optional {
				log.Printf("optional override kprobe op=%s unavailable: %v", kp.op, err)
				continue
			}
			s.Close()
			return nil, fmt.Errorf("attach override kprobe %s: %w", kp.op, err)
		}
		log.Printf("attached override kprobe op=%s symbol=%s", kp.op, symbol)
		s.links = append(s.links, l)
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("open ringbuf: %w", err)
	}
	s.reader = rd
	return s, nil
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
	return s.objects.BlockedTgids.Put(tgid, entry)
}

func (s *Sensor) UnblockTGID(tgid uint32) error {
	return s.objects.BlockedTgids.Delete(tgid)
}

func (s *Sensor) ConfigurePolicy(policy config.Policy) error {
	extensions, err := syncHashSet(s.objects.IocExtensions, policy.SuspiciousExtensions, iocHash)
	if err != nil {
		return fmt.Errorf("sync suspicious extensions: %w", err)
	}
	notes, err := syncHashSet(s.objects.IocRansomNotes, policy.RansomNoteNames, iocHash)
	if err != nil {
		return fmt.Errorf("sync ransom note names: %w", err)
	}
	protected, err := syncProtectedDirs(s.objects.ProtectedDirs, policy.ProtectedDirs)
	if err != nil {
		return fmt.Errorf("sync protected dirs: %w", err)
	}
	log.Printf("synced_bpf_policy ioc_extensions=%d ransom_notes=%d protected_dirs=%d", extensions, notes, protected)
	return nil
}

func (s *Sensor) RingbufDrops() (uint64, error) {
	var drops uint64
	if err := s.objects.RingbufDrops.Lookup(uint32(0), &drops); err != nil {
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
				if errors.Is(err, ringbuf.ErrClosed) || ctx.Err() != nil {
					return
				}
				errs <- fmt.Errorf("read ringbuf: %w", err)
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
	err = errors.Join(err, s.objects.Close())
	return err
}
