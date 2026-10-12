package sensor

import (
	"encoding/binary"
	"testing"

	"github.com/cilium/ebpf"
)

func eventV2Sample(order binary.ByteOrder, phase EventPhase, flags uint32) []byte {
	raw := make([]byte, eventV2Size)
	order.PutUint64(raw, 123_456_789)
	order.PutUint32(raw[8:], 7)
	order.PutUint32(raw[12:], 6)
	order.PutUint32(raw[16:], 5)
	order.PutUint32(raw[20:], 1000)
	order.PutUint32(raw[24:], EventWrite)
	order.PutUint32(raw[28:], 4)
	order.PutUint64(raw[40:], 4096)
	copy(raw[48:], "writer")
	copy(raw[64:], "/tmp/data")
	copy(raw[320:], "/tmp/data.new")
	order.PutUint32(raw[eventSize:], 2)
	order.PutUint32(raw[eventSize+4:], uint32(phase))
	order.PutUint32(raw[eventSize+8:], uint32(SourceTracepoint))
	order.PutUint32(raw[eventSize+12:], flags)
	order.PutUint64(raw[eventSize+16:], 1)
	order.PutUint64(raw[eventSize+24:], 1024)
	order.PutUint64(raw[eventSize+32:], 987_654)
	order.PutUint64(raw[eventSize+40:], 4096)
	order.PutUint64(raw[eventSize+48:], 1024)
	order.PutUint32(raw[eventSize+56:], 3)
	return raw
}

func TestDecodeEventV2EndianAndPartialWrite(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		t.Run(order.String(), func(t *testing.T) {
			raw := eventV2Sample(order, PhaseSuccess, EventFlagResultValid|EventFlagRequestedBytesValid|EventFlagActualBytesValid|EventFlagSyscallIDValid)
			ev, err := DecodeEvent(raw)
			if err != nil {
				t.Fatal(err)
			}
			if ev.ABIVersion != 2 || ev.Phase != PhaseSuccess || ev.Source != SourceTracepoint || ev.MonotonicNS != 123_456_789 {
				t.Fatalf("event metadata = %+v", ev)
			}
			if ev.PID != 7 || ev.TGID != 6 || ev.PPID != 5 || ev.UID != 1000 || ev.Type != EventWrite || ev.Arg0 != 4 || ev.Size != 4096 {
				t.Fatalf("event prefix = %+v", ev)
			}
			if ev.Comm != "writer" || ev.Path != "/tmp/data" || ev.Path2 != "/tmp/data.new" {
				t.Fatalf("event strings = %+v", ev)
			}
			if !ev.HasResult() || !ev.HasRequestedBytes() || !ev.HasActualBytes() || !ev.HasSyscallID() || ev.HasVectorCount() {
				t.Fatalf("event validity = %#x", ev.Flags)
			}
			if ev.Result != 1024 || ev.RequestedBytes != 4096 || ev.ActualBytes != 1024 || ev.OperationID != 987_654 || ev.SyscallID != 1 {
				t.Fatalf("partial write was not preserved: %+v", ev)
			}
		})
	}
}

func TestDecodeEventV1RetainsUnknownSemantics(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		t.Run(order.String(), func(t *testing.T) {
			raw := eventV2Sample(order, PhaseSuccess, ^uint32(0))[:eventSize]
			ev, err := decodeEvent(raw, order)
			if err != nil {
				t.Fatal(err)
			}
			if ev.ABIVersion != 1 || ev.Phase != PhaseUnknown || ev.Source != SourceUnknown || ev.Flags != 0 {
				t.Fatalf("legacy semantics were invented: %+v", ev)
			}
			if ev.HasResult() || ev.HasRequestedBytes() || ev.HasActualBytes() || ev.HasSyscallID() || ev.HasVectorCount() {
				t.Fatalf("legacy validity flags = %#x", ev.Flags)
			}
			if ev.Size != 4096 || ev.MonotonicNS != 123_456_789 {
				t.Fatalf("legacy data lost: %+v", ev)
			}
		})
	}
}

func TestDecodeEventV2FailedWrite(t *testing.T) {
	raw := eventV2Sample(binary.LittleEndian, PhaseFailure, EventFlagResultValid|EventFlagRequestedBytesValid)
	result := int64(-9)
	binary.LittleEndian.PutUint64(raw[eventSize+24:], uint64(result))
	ev, err := DecodeEvent(raw)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Result != -9 || !ev.HasResult() || ev.Phase != PhaseFailure || ev.HasActualBytes() {
		t.Fatalf("failure was not preserved: %+v", ev)
	}
}

func TestDecodeEventV2WritevCountIsNotBytes(t *testing.T) {
	raw := eventV2Sample(binary.LittleEndian, PhaseAttempt, EventFlagVectorCountValid|EventFlagSyscallIDValid)
	binary.LittleEndian.PutUint64(raw[40:], 0)
	binary.LittleEndian.PutUint64(raw[eventSize+40:], 0)
	ev, err := DecodeEvent(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !ev.HasVectorCount() || ev.VectorCount != 3 || ev.HasRequestedBytes() || ev.HasActualBytes() || ev.HasResult() {
		t.Fatalf("writev vector count was treated as a byte count: %+v", ev)
	}
}

func TestDecodeEventV2ValidityIsNotInferredFromValue(t *testing.T) {
	raw := eventV2Sample(binary.LittleEndian, PhaseSuccess, 0)
	ev, err := DecodeEvent(raw)
	if err != nil {
		t.Fatal(err)
	}
	if ev.HasResult() || ev.HasRequestedBytes() || ev.HasActualBytes() || ev.HasSyscallID() || ev.HasVectorCount() {
		t.Fatalf("unmarked values became valid: %+v", ev)
	}
	raw = eventV2Sample(binary.LittleEndian, PhaseSuccess, EventFlagResultValid|EventFlagRequestedBytesValid|EventFlagActualBytesValid)
	binary.LittleEndian.PutUint64(raw[eventSize+24:], 0)
	binary.LittleEndian.PutUint64(raw[eventSize+40:], 0)
	binary.LittleEndian.PutUint64(raw[eventSize+48:], 0)
	ev, err = DecodeEvent(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !ev.HasResult() || !ev.HasRequestedBytes() || !ev.HasActualBytes() || ev.Result != 0 || ev.RequestedBytes != 0 || ev.ActualBytes != 0 {
		t.Fatalf("valid zero values became unknown: %+v", ev)
	}
}

func TestDecodeEventAllowsPerfPadding(t *testing.T) {
	for _, size := range []int{eventSize, eventV2Size} {
		for padding := 0; padding <= 7; padding++ {
			raw := eventV2Sample(binary.NativeEndian, PhaseSuccess, EventFlagResultValid)[:size]
			raw = append(raw, make([]byte, padding)...)
			if _, err := DecodeEvent(raw); err != nil {
				t.Fatalf("size=%d padding=%d: %v", size, padding, err)
			}
		}
	}
}

func TestDecodeEventRejectsMalformedV2(t *testing.T) {
	for _, test := range []struct {
		name   string
		offset int
		value  uint32
	}{
		{"zero version", eventSize, 0},
		{"unknown version", eventSize, 3},
		{"unknown phase", eventSize + 4, 6},
		{"unknown source", eventSize + 8, 5},
		{"unknown flags", eventSize + 12, 32},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := eventV2Sample(binary.NativeEndian, PhaseSuccess, 0)
			binary.NativeEndian.PutUint32(raw[test.offset:], test.value)
			if _, err := DecodeEvent(raw); err == nil {
				t.Fatal("expected malformed event error")
			}
		})
	}
	for size := 0; size < eventSize; size++ {
		if _, err := DecodeEvent(make([]byte, size)); err == nil {
			t.Fatalf("accepted short event size=%d", size)
		}
	}
	for size := eventSize + 8; size < eventV2Size; size++ {
		if _, err := DecodeEvent(eventV2Sample(binary.NativeEndian, PhaseSuccess, 0)[:size]); err == nil {
			t.Fatalf("accepted truncated v2 event size=%d", size)
		}
	}
	if _, err := DecodeEvent(make([]byte, eventV2Size+8)); err == nil {
		t.Fatal("accepted oversized event")
	}
}

func TestEventV2Names(t *testing.T) {
	for phase, want := range []string{"unknown", "attempt", "success", "failure", "blocked", "observation"} {
		if got := (Event{Phase: EventPhase(phase)}).PhaseName(); got != want {
			t.Fatalf("phase %d = %q, want %q", phase, got, want)
		}
	}
	for source, want := range []string{"unknown", "tracepoint", "kprobe", "lsm", "sched"} {
		if got := (Event{Source: EventSource(source)}).SourceName(); got != want {
			t.Fatalf("source %d = %q, want %q", source, got, want)
		}
	}
}

func TestUltraLegacySlotPreservesVersionedPayload(t *testing.T) {
	for _, size := range []int{eventSize, eventV2Size} {
		raw := eventV2Sample(binary.NativeEndian, PhaseSuccess, EventFlagResultValid)[:size]
		slot := make([]byte, 8+size)
		binary.NativeEndian.PutUint64(slot, 42)
		copy(slot[8:], raw)
		payload := ultraLegacySlotEvent(slot)
		if len(payload) != size {
			t.Fatalf("payload size=%d, want %d", len(payload), size)
		}
		if _, err := DecodeEvent(payload); err != nil {
			t.Fatal(err)
		}
		if err := validateUltraLegacySlotSize(uint32(len(slot))); err != nil {
			t.Fatal(err)
		}
	}
	for _, size := range []uint32{0, 8, 8 + eventSize - 1, 8 + eventSize + 1, 8 + eventV2Size + 1} {
		if err := validateUltraLegacySlotSize(size); err == nil {
			t.Fatalf("accepted slot size=%d", size)
		}
	}
	if raw := ultraLegacySlotEvent(make([]byte, 10)); len(raw) != 2 {
		t.Fatalf("truncated payload was padded: length=%d", len(raw))
	}
	if raw := ultraLegacySlotEvent(nil); len(raw) != 0 {
		t.Fatalf("empty slot was padded: length=%d", len(raw))
	}
}

func TestMapPollingEventReaderReadsV2Slot(t *testing.T) {
	events := newTestMap(t, &ebpf.MapSpec{
		Name: "event_v2_slots", Type: ebpf.Array, KeySize: 4, ValueSize: 8 + eventV2Size, MaxEntries: ultraLegacyEventSlots,
	})
	defer events.Close()
	cursor := newTestMap(t, &ebpf.MapSpec{
		Name: "event_v2_cursor", Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1,
	})
	defer cursor.Close()
	slot := make([]byte, 8+eventV2Size)
	binary.NativeEndian.PutUint64(slot, 1)
	copy(slot[8:], eventV2Sample(binary.NativeEndian, PhaseSuccess, EventFlagResultValid))
	if err := events.Put(uint32(0), slot); err != nil {
		t.Fatal(err)
	}
	if err := cursor.Put(uint32(0), uint64(1)); err != nil {
		t.Fatal(err)
	}
	reader, err := newEventReader(runtimeModeUltraLegacyMap, events, cursor)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	record, err := reader.Read()
	if err != nil {
		t.Fatal(err)
	}
	ev, err := DecodeEvent(record.RawSample)
	if err != nil || ev.ABIVersion != 2 || ev.OperationID != 987_654 {
		t.Fatalf("map v2 event=%+v, err=%v", ev, err)
	}
}

func TestUltraLegacyV2ObjectSlotSize(t *testing.T) {
	spec, err := loadRansomwareUltraLegacy()
	if err != nil {
		t.Fatal(err)
	}
	events := spec.Maps["events"]
	if events == nil || events.ValueSize != 16+eventV2Size || events.MaxEntries != 256*128 {
		t.Fatalf("generated events map must contain CPU-sharded guarded v2 payloads: %+v", events)
	}
	if cursor := spec.Maps["event_cursor"]; cursor == nil || cursor.MaxEntries != 256 || cursor.ValueSize != 8 {
		t.Fatalf("generated cursor map must contain one counter per CPU: %+v", cursor)
	}
}

func TestKprobePairRequiresBothPrograms(t *testing.T) {
	if _, _, err := attachKprobePair("write", nil, nil); err == nil {
		t.Fatal("accepted missing paired probes")
	}
}
