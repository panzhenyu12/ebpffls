package sensor

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

const (
	EventExec uint32 = iota + 1
	EventOpen
	EventWrite
	EventRename
	EventUnlink
	EventTruncate
	EventBlock
	EventClose
	EventDup
	EventScan
	EventMmap
	EventIOUring
	EventConnect
	EventLink
)

const (
	taskCommLen = 16
	pathMaxLen  = 256
	eventSize   = 8 + 4 + 4 + 4 + 4 + 4 + 4 + 4 + 4 + 8 + taskCommLen + pathMaxLen + pathMaxLen
	eventV2Size = eventSize + 64
	afInet6     = 10
)

type EventPhase uint32

const (
	PhaseUnknown EventPhase = iota
	PhaseAttempt
	PhaseSuccess
	PhaseFailure
	PhaseBlocked
	PhaseObservation
)

type EventSource uint32

const (
	SourceUnknown EventSource = iota
	SourceTracepoint
	SourceKprobe
	SourceLSM
	SourceSched
)

const (
	EventFlagResultValid uint32 = 1 << iota
	EventFlagRequestedBytesValid
	EventFlagActualBytesValid
	EventFlagSyscallIDValid
	EventFlagVectorCountValid
)

type Event struct {
	Timestamp time.Time
	PID       uint32
	TGID      uint32
	PPID      uint32
	UID       uint32
	Type      uint32
	Arg0      int32
	Arg1      int32
	Size      uint64
	Comm      string
	Path      string
	Path2     string

	ABIVersion     uint32
	Phase          EventPhase
	Source         EventSource
	Flags          uint32
	SyscallID      int64
	Result         int64
	OperationID    uint64
	RequestedBytes uint64
	ActualBytes    uint64
	VectorCount    uint32
	MonotonicNS    uint64
}

var (
	eventClockOnce sync.Once
	eventClockWall time.Time
	eventClockMono uint64
)

func DecodeEvent(raw []byte) (Event, error) {
	// ABI v1 has no byte-order marker. Its transport is native-endian; v2's
	// version field also makes archived samples portable between architectures.
	var order binary.ByteOrder = binary.NativeEndian
	if len(raw) >= eventV2Size {
		switch {
		case binary.LittleEndian.Uint32(raw[eventSize:]) == 2:
			order = binary.LittleEndian
		case binary.BigEndian.Uint32(raw[eventSize:]) == 2:
			order = binary.BigEndian
		}
	}
	return decodeEvent(raw, order)
}

func decodeEvent(raw []byte, order binary.ByteOrder) (Event, error) {
	if len(raw) < eventSize {
		return Event{}, fmt.Errorf("short event: got %d bytes, want %d", len(raw), eventSize)
	}
	// perf samples may contain up to seven trailing bytes of alignment padding.
	legacy := len(raw) <= eventSize+7
	if !legacy && (len(raw) < eventV2Size || len(raw) > eventV2Size+7) {
		return Event{}, fmt.Errorf("invalid event length: got %d bytes, want %d or %d (plus up to 7 padding bytes)", len(raw), eventSize, eventV2Size)
	}

	e := Event{ABIVersion: 1}
	off := 0
	ts := order.Uint64(raw[off:])
	off += 8
	e.Timestamp = eventTimestamp(ts)
	e.MonotonicNS = ts
	e.PID = order.Uint32(raw[off:])
	off += 4
	e.TGID = order.Uint32(raw[off:])
	off += 4
	e.PPID = order.Uint32(raw[off:])
	off += 4
	e.UID = order.Uint32(raw[off:])
	off += 4
	e.Type = order.Uint32(raw[off:])
	off += 4
	e.Arg0 = int32(order.Uint32(raw[off:]))
	off += 4
	e.Arg1 = int32(order.Uint32(raw[off:]))
	off += 4
	off += 4 // C struct padding before the u64 size field.
	e.Size = order.Uint64(raw[off:])
	off += 8
	e.Comm = cString(raw[off : off+taskCommLen])
	off += taskCommLen
	if e.Type == EventConnect && e.Size == afInet6 {
		e.Path = string(raw[off : off+16])
	} else {
		e.Path = cString(raw[off : off+pathMaxLen])
	}
	off += pathMaxLen
	e.Path2 = cString(raw[off : off+pathMaxLen])
	if legacy {
		return e, nil
	}

	off = eventSize
	e.ABIVersion = order.Uint32(raw[off:])
	if e.ABIVersion != 2 {
		return Event{}, fmt.Errorf("unsupported event ABI version: %d", e.ABIVersion)
	}
	e.Phase = EventPhase(order.Uint32(raw[off+4:]))
	e.Source = EventSource(order.Uint32(raw[off+8:]))
	e.Flags = order.Uint32(raw[off+12:])
	if e.Phase > PhaseObservation {
		return Event{}, fmt.Errorf("invalid event phase: %d", e.Phase)
	}
	if e.Source > SourceSched {
		return Event{}, fmt.Errorf("invalid event source: %d", e.Source)
	}
	const knownFlags = EventFlagResultValid | EventFlagRequestedBytesValid | EventFlagActualBytesValid | EventFlagSyscallIDValid | EventFlagVectorCountValid
	if e.Flags & ^uint32(knownFlags) != 0 {
		return Event{}, fmt.Errorf("invalid event flags: %#x", e.Flags)
	}
	e.SyscallID = int64(order.Uint64(raw[off+16:]))
	e.Result = int64(order.Uint64(raw[off+24:]))
	e.OperationID = order.Uint64(raw[off+32:])
	e.RequestedBytes = order.Uint64(raw[off+40:])
	e.ActualBytes = order.Uint64(raw[off+48:])
	e.VectorCount = order.Uint32(raw[off+56:])
	return e, nil
}

func (e Event) HasResult() bool { return e.Flags&EventFlagResultValid != 0 }

func (e Event) HasRequestedBytes() bool { return e.Flags&EventFlagRequestedBytesValid != 0 }

func (e Event) HasActualBytes() bool { return e.Flags&EventFlagActualBytesValid != 0 }

func (e Event) HasSyscallID() bool { return e.Flags&EventFlagSyscallIDValid != 0 }

func (e Event) HasVectorCount() bool { return e.Flags&EventFlagVectorCountValid != 0 }

func (e Event) PhaseName() string {
	switch e.Phase {
	case PhaseUnknown:
		return "unknown"
	case PhaseAttempt:
		return "attempt"
	case PhaseSuccess:
		return "success"
	case PhaseFailure:
		return "failure"
	case PhaseBlocked:
		return "blocked"
	case PhaseObservation:
		return "observation"
	default:
		return fmt.Sprintf("unknown(%d)", e.Phase)
	}
}

func (e Event) SourceName() string {
	switch e.Source {
	case SourceUnknown:
		return "unknown"
	case SourceTracepoint:
		return "tracepoint"
	case SourceKprobe:
		return "kprobe"
	case SourceLSM:
		return "lsm"
	case SourceSched:
		return "sched"
	default:
		return fmt.Sprintf("unknown(%d)", e.Source)
	}
}

// eventTimestamp converts bpf_ktime_get_ns values into wall-clock time so the
// agent's duration-based windows remain meaningful across all event readers.
// The conversion base is initialized once to avoid reading /proc/uptime for
// every event. On non-Linux hosts, tests and tooling still receive a sensible
// timestamp relative to the first decoded event.
func eventTimestamp(ts uint64) time.Time {
	if ts == 0 {
		return time.Now()
	}
	eventClockOnce.Do(func() {
		eventClockWall = time.Now()
		if uptime, err := monotonicUptime(); err == nil && uptime >= 0 {
			eventClockMono = uint64(uptime.Nanoseconds())
			return
		}
		// Keep the first event near now when /proc/uptime is unavailable.
		eventClockMono = ts
	})

	const maxInt64 = uint64(^uint64(0) >> 1)
	var delta int64
	if ts >= eventClockMono {
		d := ts - eventClockMono
		if d > maxInt64 {
			return eventClockWall
		}
		delta = int64(d)
	} else {
		d := eventClockMono - ts
		if d > maxInt64 {
			return eventClockWall
		}
		delta = -int64(d)
	}
	return eventClockWall.Add(time.Duration(delta))
}

func (e Event) TypeName() string {
	switch e.Type {
	case EventExec:
		return "exec"
	case EventOpen:
		return "open"
	case EventWrite:
		return "write"
	case EventRename:
		return "rename"
	case EventUnlink:
		return "unlink"
	case EventTruncate:
		return "truncate"
	case EventBlock:
		return "block"
	case EventClose:
		return "close"
	case EventDup:
		return "dup"
	case EventScan:
		return "scan"
	case EventMmap:
		return "mmap"
	case EventIOUring:
		return "io_uring"
	case EventConnect:
		return "connect"
	case EventLink:
		return "link"
	default:
		return fmt.Sprintf("unknown(%d)", e.Type)
	}
}

func cString(buf []byte) string {
	if i := bytes.IndexByte(buf, 0); i >= 0 {
		return string(buf[:i])
	}
	return string(buf)
}
