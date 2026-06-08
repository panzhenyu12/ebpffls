package sensor

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
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

type Sensor struct {
	objects ransomwareObjects
	links   []link.Link
	reader  *ringbuf.Reader
}

func New() (*Sensor, error) {
	var objs ransomwareObjects
	if err := loadRansomwareObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load bpf objects: %w", err)
	}

	s := &Sensor{objects: objs}

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
