package sensor

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"log"
	"os"
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
	}{
		{"syscalls", "sys_enter_execve", objs.TraceExecve},
		{"syscalls", "sys_enter_openat", objs.TraceOpenat},
		{"syscalls", "sys_exit_openat", objs.TraceOpenatExit},
		{"syscalls", "sys_enter_openat2", objs.TraceOpenat2},
		{"syscalls", "sys_exit_openat2", objs.TraceOpenat2Exit},
		{"syscalls", "sys_enter_write", objs.TraceWrite},
		{"syscalls", "sys_enter_pwrite64", objs.TracePwrite64},
		{"syscalls", "sys_enter_writev", objs.TraceWritev},
		{"syscalls", "sys_enter_copy_file_range", objs.TraceCopyFileRange},
		{"syscalls", "sys_enter_getdents64", objs.TraceGetdents64},
		{"syscalls", "sys_enter_mmap", objs.TraceMmap},
		{"syscalls", "sys_enter_close", objs.TraceClose},
		{"syscalls", "sys_enter_dup", objs.TraceDup},
		{"syscalls", "sys_exit_dup", objs.TraceDupExit},
		{"syscalls", "sys_enter_dup2", objs.TraceDup2},
		{"syscalls", "sys_exit_dup2", objs.TraceDup2Exit},
		{"syscalls", "sys_enter_dup3", objs.TraceDup3},
		{"syscalls", "sys_exit_dup3", objs.TraceDup3Exit},
		{"syscalls", "sys_enter_fcntl", objs.TraceFcntl},
		{"syscalls", "sys_exit_fcntl", objs.TraceFcntlExit},
		{"syscalls", "sys_enter_rename", objs.TraceRename},
		{"syscalls", "sys_enter_renameat", objs.TraceRenameat},
		{"syscalls", "sys_enter_renameat2", objs.TraceRenameat2},
		{"syscalls", "sys_enter_unlink", objs.TraceUnlink},
		{"syscalls", "sys_enter_unlinkat", objs.TraceUnlinkat},
		{"syscalls", "sys_enter_truncate", objs.TraceTruncate},
		{"syscalls", "sys_enter_ftruncate", objs.TraceFtruncate},
	}
	for _, tp := range tracepoints {
		l, err := link.Tracepoint(tp.category, tp.name, tp.prog, nil)
		if err != nil {
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
		symbol string
		prog   *ebpf.Program
	}{
		{"__x64_sys_openat", objs.KpOverrideOpenat},
		{"__x64_sys_openat2", objs.KpOverrideOpenat2},
		{"__x64_sys_rename", objs.KpOverrideRename},
		{"__x64_sys_renameat", objs.KpOverrideRenameat},
		{"__x64_sys_renameat2", objs.KpOverrideRenameat2},
		{"__x64_sys_unlink", objs.KpOverrideUnlink},
		{"__x64_sys_unlinkat", objs.KpOverrideUnlinkat},
		{"__x64_sys_truncate", objs.KpOverrideTruncate},
		{"__x64_sys_ftruncate", objs.KpOverrideFtruncate},
		{"__x64_sys_execve", objs.KpOverrideExecve},
		{"__x64_sys_write", objs.KpOverrideWrite},
		{"__x64_sys_pwrite64", objs.KpOverridePwrite64},
		{"__x64_sys_writev", objs.KpOverrideWritev},
		{"__x64_sys_copy_file_range", objs.KpOverrideCopyFileRange},
		{"__x64_sys_getdents64", objs.KpOverrideGetdents64},
		{"__x64_sys_mmap", objs.KpOverrideMmap},
	}
	for _, kp := range kprobes {
		l, err := link.Kprobe(kp.symbol, kp.prog, nil)
		if err != nil {
			s.Close()
			return nil, fmt.Errorf("attach override kprobe %s: %w", kp.symbol, err)
		}
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
