package sensor

import (
	"encoding/binary"
	"fmt"
	"testing"
)

type fakePollingMap struct {
	entries     uint32
	size        uint32
	values      map[uint32][]byte
	afterLookup func(uint32)
}

func (m *fakePollingMap) MaxEntries() uint32 { return m.entries }
func (m *fakePollingMap) ValueSize() uint32  { return m.size }

func (m *fakePollingMap) Lookup(key, out interface{}) error {
	index := key.(uint32)
	if index >= m.entries {
		return fmt.Errorf("key %d outside map", index)
	}
	raw := m.values[index]
	if raw == nil {
		raw = make([]byte, m.size)
	}
	switch value := out.(type) {
	case *uint64:
		*value = binary.NativeEndian.Uint64(raw)
	case []byte:
		if len(value) != int(m.size) {
			return fmt.Errorf("lookup buffer size=%d, want %d", len(value), m.size)
		}
		copy(value, raw)
	default:
		return fmt.Errorf("unsupported output %T", out)
	}
	if m.afterLookup != nil {
		m.afterLookup(index)
	}
	return nil
}

func pollingFixture(shards, slots, size uint32) (*mapPollingEventReader, *fakePollingMap, *fakePollingMap) {
	events := &fakePollingMap{entries: shards * slots, size: size, values: make(map[uint32][]byte)}
	cursor := &fakePollingMap{entries: shards, size: 8, values: make(map[uint32][]byte)}
	return newMapPollingEventReader(events, cursor), events, cursor
}

func setPollingHead(cursor *fakePollingMap, cpu uint32, seq uint64) {
	raw := make([]byte, 8)
	binary.NativeEndian.PutUint64(raw, seq)
	cursor.values[cpu] = raw
}

func setPollingEvent(events *fakePollingMap, slots, cpu uint32, seq, timestamp uint64) {
	raw := make([]byte, events.size)
	binary.NativeEndian.PutUint64(raw, seq)
	payload := eventV2Sample(binary.NativeEndian, PhaseSuccess, EventFlagResultValid|EventFlagActualBytesValid)
	binary.NativeEndian.PutUint64(payload, timestamp)
	binary.NativeEndian.PutUint32(payload[8:], 100+cpu)
	binary.NativeEndian.PutUint32(payload[12:], 100+cpu)
	binary.NativeEndian.PutUint64(payload[eventSize+32:], uint64(cpu+1)*1000+seq)
	copy(raw[8:], payload)
	if events.size == 16+eventV2Size {
		binary.NativeEndian.PutUint64(raw[len(raw)-8:], seq)
	}
	events.values[cpu*slots+uint32((seq-1)%uint64(slots))] = raw
}

func TestShardedPollingInterleavesWithoutMixingIdentity(t *testing.T) {
	r, events, cursor := pollingFixture(2, 4, 16+eventV2Size)
	setPollingEvent(events, 4, 0, 1, 20)
	setPollingEvent(events, 4, 0, 2, 40)
	setPollingEvent(events, 4, 1, 1, 10)
	setPollingEvent(events, 4, 1, 2, 30)
	setPollingHead(cursor, 0, 2)
	setPollingHead(cursor, 1, 2)
	if err := r.pollBatch(); err != nil {
		t.Fatal(err)
	}
	if len(r.pending) != 4 {
		t.Fatalf("got %d events", len(r.pending))
	}
	for i, record := range r.pending {
		event, err := DecodeEvent(record.RawSample)
		if err != nil {
			t.Fatal(err)
		}
		wantCPU := uint32(1 - i%2)
		wantSeq := uint64(i/2 + 1)
		if event.MonotonicNS != uint64((i+1)*10) || event.TGID != 100+wantCPU || event.PID != event.TGID || event.OperationID != uint64(wantCPU+1)*1000+wantSeq {
			t.Fatalf("mixed or misordered CPU event %d: %+v", i, event)
		}
	}
	if r.shards[0].tail != 2 || r.shards[1].tail != 2 || r.lost.Load() != 0 {
		t.Fatalf("incorrect per-CPU progress: %+v lost=%d", r.shards, r.lost.Load())
	}
}

func TestShardedPollingRejectsUncommittedAndTornSnapshots(t *testing.T) {
	for _, test := range []struct {
		name       string
		begin, end uint64
	}{
		{"uncommitted", 0, 0},
		{"payload being replaced", 0, 1},
		{"commit in progress", 1, 0},
		{"torn sequence", 1, 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			r, events, cursor := pollingFixture(1, 4, 16+eventV2Size)
			setPollingEvent(events, 4, 0, 1, 10)
			raw := events.values[0]
			binary.NativeEndian.PutUint64(raw, test.begin)
			binary.NativeEndian.PutUint64(raw[len(raw)-8:], test.end)
			setPollingHead(cursor, 0, 1)
			if err := r.pollBatch(); err != nil {
				t.Fatal(err)
			}
			if len(r.pending) != 0 || r.shards[0].tail != 0 || r.lost.Load() != 0 {
				t.Fatalf("uncommitted event consumed: pending=%d tail=%d lost=%d", len(r.pending), r.shards[0].tail, r.lost.Load())
			}
			setPollingEvent(events, 4, 0, 1, 10)
			if err := r.pollBatch(); err != nil || len(r.pending) != 1 {
				t.Fatalf("committed retry failed: pending=%d err=%v", len(r.pending), err)
			}
		})
	}
}

func TestShardedPollingRechecksPublicationAfterCopy(t *testing.T) {
	r, events, cursor := pollingFixture(1, 2, 16+eventV2Size)
	setPollingEvent(events, 2, 0, 1, 10)
	setPollingHead(cursor, 0, 1)
	reads := 0
	events.afterLookup = func(uint32) {
		reads++
		if reads == 1 {
			// Simulate an overwrite during the first syscall's snapshot copy.
			setPollingEvent(events, 2, 0, 3, 30)
		}
	}
	if err := r.pollBatch(); err != nil {
		t.Fatal(err)
	}
	if reads != 2 || len(r.pending) != 0 || r.lost.Load() != 1 || r.shards[0].tail != 1 {
		t.Fatalf("overwritten candidate escaped: reads=%d pending=%d lost=%d tail=%d", reads, len(r.pending), r.lost.Load(), r.shards[0].tail)
	}
}

func TestShardedPollingOverflowCatchesUpAndCountsLoss(t *testing.T) {
	r, events, cursor := pollingFixture(2, 2, 16+eventV2Size)
	setPollingHead(cursor, 0, 6)
	setPollingEvent(events, 2, 0, 5, 50)
	setPollingEvent(events, 2, 0, 6, 60)
	setPollingHead(cursor, 1, 1)
	setPollingEvent(events, 2, 1, 1, 10)
	if err := r.pollBatch(); err != nil {
		t.Fatal(err)
	}
	if len(r.pending) != 3 || r.lost.Load() != 4 || r.shards[0].tail != 6 || r.shards[1].tail != 1 {
		t.Fatalf("incorrect overflow recovery: pending=%d lost=%d shards=%+v", len(r.pending), r.lost.Load(), r.shards)
	}
	s := &Sensor{reader: r}
	if drops, err := s.CaptureGaps(); err != nil || drops != 4 {
		t.Fatalf("reader loss missing from metrics: drops=%d err=%v", drops, err)
	}
	if drops, err := s.RingbufDrops(); err != nil || drops != 0 {
		t.Fatalf("reader gaps changed ringbuf metric semantics: drops=%d err=%v", drops, err)
	}
	r.pending = nil
	if err := r.pollBatch(); err != nil || len(r.pending) != 0 || r.lost.Load() != 4 {
		t.Fatalf("loss double-counted: pending=%d lost=%d err=%v", len(r.pending), r.lost.Load(), err)
	}
}

func TestShardedPollingFairBoundedBatches(t *testing.T) {
	r, events, cursor := pollingFixture(256, 128, 16+eventV2Size)
	for cpu := uint32(0); cpu < 256; cpu++ {
		setPollingHead(cursor, cpu, 1)
		setPollingEvent(events, 128, cpu, 1, uint64(cpu+1))
	}
	for batch := 0; batch < 2; batch++ {
		if err := r.pollBatch(); err != nil {
			t.Fatal(err)
		}
		if len(r.pending) != mapPollingBatchSize {
			t.Fatalf("batch %d size=%d", batch, len(r.pending))
		}
		r.pending = nil
	}
	for cpu, shard := range r.shards {
		if shard.tail != 1 {
			t.Fatalf("CPU %d starved: tail=%d", cpu, shard.tail)
		}
	}
	if r.lost.Load() != 0 {
		t.Fatalf("unexpected loss=%d", r.lost.Load())
	}
}

func TestShardedPollingHotCPUDoesNotStarveSparseCPU(t *testing.T) {
	r, events, cursor := pollingFixture(256, 128, 16+eventV2Size)
	for seq := uint64(1); seq <= 128; seq++ {
		setPollingEvent(events, 128, 0, seq, seq)
	}
	setPollingHead(cursor, 0, 128)
	setPollingEvent(events, 128, 255, 1, 1000)
	setPollingHead(cursor, 255, 1)
	if err := r.pollBatch(); err != nil {
		t.Fatal(err)
	}
	if len(r.pending) != 128 || r.shards[255].tail != 1 || r.shards[0].tail != 127 {
		t.Fatalf("unfair batch: size=%d hot=%d sparse=%d", len(r.pending), r.shards[0].tail, r.shards[255].tail)
	}
}

func TestMapPollingLegacySlotLayouts(t *testing.T) {
	for _, size := range []uint32{8 + eventSize, 8 + eventV2Size} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			r, events, cursor := pollingFixture(1, 1024, size)
			setPollingEvent(events, 1024, 0, 1, 10)
			setPollingHead(cursor, 0, 1)
			if err := r.pollBatch(); err != nil || len(r.pending) != 1 {
				t.Fatalf("legacy slot read failed: pending=%d err=%v", len(r.pending), err)
			}
			event, err := DecodeEvent(r.pending[0].RawSample)
			if err != nil {
				t.Fatal(err)
			}
			wantABI := uint32(1)
			if size == 8+eventV2Size {
				wantABI = 2
			}
			if event.ABIVersion != wantABI || event.TGID != 100 || r.slotsPerCPU != 1024 {
				t.Fatalf("wrong legacy layout: event=%+v slots=%d", event, r.slotsPerCPU)
			}
		})
	}
}

func TestMapPollingRejectsInvalidLayouts(t *testing.T) {
	for _, test := range []struct {
		shards, entries, size, cursorSize uint32
	}{
		{0, 1, 16 + eventV2Size, 8},
		{257, 257, 16 + eventV2Size, 8},
		{2, 3, 16 + eventV2Size, 8},
		{1, 0, 16 + eventV2Size, 8},
		{1, 1, 16 + eventV2Size, 4},
		{2, 4, 8 + eventV2Size, 8},
	} {
		events := &fakePollingMap{entries: test.entries, size: test.size}
		cursor := &fakePollingMap{entries: test.shards, size: test.cursorSize}
		if r := newMapPollingEventReader(events, cursor); r.initErr == nil {
			t.Fatalf("accepted invalid layout: %+v", test)
		}
	}
}

func TestCPUShardCoverageUsesIndicesNotCount(t *testing.T) {
	for _, possible := range []string{"0", "0-255\n", "0-3,8,16-31"} {
		if err := validateCPUShardCoverage(possible, 256); err != nil {
			t.Fatalf("rejected %q: %v", possible, err)
		}
	}
	for _, possible := range []string{"", "0-256", "0-3,512", "3-1", "-1", "one", "0-1-2", "0,"} {
		if err := validateCPUShardCoverage(possible, 256); err == nil {
			t.Fatalf("accepted unsupported CPU layout %q", possible)
		}
	}
}

func TestUltraLegacyArchitectureGuard(t *testing.T) {
	if err := validateUltraLegacyArchitecture("amd64"); err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"arm64", "386", "s390x", "riscv64"} {
		if err := validateUltraLegacyArchitecture(arch); err == nil {
			t.Fatalf("unsupported legacy register layout accepted: %s", arch)
		}
	}
}

func TestCaptureGapsIncludesPerfLossWithoutChangingRingbufDrops(t *testing.T) {
	reader := &perfEventReader{}
	reader.lost.Add(9)
	s := &Sensor{reader: reader}
	if gaps, err := s.CaptureGaps(); err != nil || gaps != 9 {
		t.Fatalf("perf loss missing: gaps=%d err=%v", gaps, err)
	}
	if drops, err := s.RingbufDrops(); err != nil || drops != 0 {
		t.Fatalf("perf loss changed ringbuf metric: drops=%d err=%v", drops, err)
	}
}
