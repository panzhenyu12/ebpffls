package sensor

import (
	"encoding/binary"
	"fmt"
	"strings"
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
)

const (
	taskCommLen = 16
	pathMaxLen  = 256
	eventSize   = 8 + 4 + 4 + 4 + 4 + 4 + 4 + 4 + 4 + 8 + taskCommLen + pathMaxLen + pathMaxLen
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
}

func DecodeEvent(raw []byte) (Event, error) {
	if len(raw) < eventSize {
		return Event{}, fmt.Errorf("short event: got %d bytes, want %d", len(raw), eventSize)
	}

	var e Event
	off := 0
	ts := binary.LittleEndian.Uint64(raw[off:])
	off += 8
	_ = ts
	e.Timestamp = time.Now()
	e.PID = binary.LittleEndian.Uint32(raw[off:])
	off += 4
	e.TGID = binary.LittleEndian.Uint32(raw[off:])
	off += 4
	e.PPID = binary.LittleEndian.Uint32(raw[off:])
	off += 4
	e.UID = binary.LittleEndian.Uint32(raw[off:])
	off += 4
	e.Type = binary.LittleEndian.Uint32(raw[off:])
	off += 4
	e.Arg0 = int32(binary.LittleEndian.Uint32(raw[off:]))
	off += 4
	e.Arg1 = int32(binary.LittleEndian.Uint32(raw[off:]))
	off += 4
	off += 4 // C struct padding before the u64 size field.
	e.Size = binary.LittleEndian.Uint64(raw[off:])
	off += 8
	e.Comm = cString(raw[off : off+taskCommLen])
	off += taskCommLen
	e.Path = cString(raw[off : off+pathMaxLen])
	off += pathMaxLen
	e.Path2 = cString(raw[off : off+pathMaxLen])
	return e, nil
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
	default:
		return fmt.Sprintf("unknown(%d)", e.Type)
	}
}

func cString(buf []byte) string {
	if i := strings.IndexByte(string(buf), 0); i >= 0 {
		return string(buf[:i])
	}
	return string(buf)
}
