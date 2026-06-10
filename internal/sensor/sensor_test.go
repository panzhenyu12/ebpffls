package sensor

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func TestRingbufDropsReadsCounterMap(t *testing.T) {
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "ringbuf_drops_test",
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 1,
	})
	if err != nil {
		t.Fatalf("create map: %v", err)
	}
	defer m.Close()

	var key uint32
	if err := m.Put(key, uint64(42)); err != nil {
		t.Fatalf("put counter: %v", err)
	}

	s := &Sensor{
		maps: sensorMaps{RingbufDrops: m},
	}
	drops, err := s.RingbufDrops()
	if err != nil {
		t.Fatalf("RingbufDrops: %v", err)
	}
	if drops != 42 {
		t.Fatalf("drops = %d, want 42", drops)
	}
}

func TestLoadSensorObjectsWithModes(t *testing.T) {
	coreObj := loadedSensorObjects{mode: runtimeModeCore}
	legacyPerfObj := loadedSensorObjects{mode: runtimeModeLegacyPerf}
	ultraLegacyObj := loadedSensorObjects{mode: runtimeModeUltraLegacyMap}
	loaders := objectLoaders{
		core: func() (loadedSensorObjects, error) {
			return coreObj, nil
		},
		legacyPerf: func() (loadedSensorObjects, error) {
			return legacyPerfObj, nil
		},
		ultraLegacyMap: func() (loadedSensorObjects, error) {
			return ultraLegacyObj, nil
		},
	}

	got, err := loadSensorObjectsWith("core", loaders)
	if err != nil {
		t.Fatalf("core mode: %v", err)
	}
	if got.mode != runtimeModeCore {
		t.Fatalf("core mode selected %q", got.mode)
	}

	got, err = loadSensorObjectsWith("legacy_perf", loaders)
	if err != nil {
		t.Fatalf("legacy_perf mode: %v", err)
	}
	if got.mode != runtimeModeLegacyPerf {
		t.Fatalf("legacy_perf mode selected %q", got.mode)
	}

	got, err = loadSensorObjectsWith("legacy", loaders)
	if err != nil {
		t.Fatalf("legacy alias mode: %v", err)
	}
	if got.mode != runtimeModeLegacyPerf {
		t.Fatalf("legacy alias mode selected %q", got.mode)
	}

	got, err = loadSensorObjectsWith("ultra_legacy_map", loaders)
	if err != nil {
		t.Fatalf("ultra_legacy_map mode: %v", err)
	}
	if got.mode != runtimeModeUltraLegacyMap {
		t.Fatalf("ultra_legacy_map mode selected %q", got.mode)
	}
}

func TestLoadSensorObjectsWithAutoFallsBackToLegacyPerf(t *testing.T) {
	loaders := objectLoaders{
		core: func() (loadedSensorObjects, error) {
			return loadedSensorObjects{}, fmt.Errorf("missing BTF")
		},
		legacyPerf: func() (loadedSensorObjects, error) {
			return loadedSensorObjects{mode: runtimeModeLegacyPerf}, nil
		},
		ultraLegacyMap: func() (loadedSensorObjects, error) {
			t.Fatal("ultra legacy should not be called when legacy_perf succeeds")
			return loadedSensorObjects{}, nil
		},
	}

	got, err := loadSensorObjectsWith("auto", loaders)
	if err != nil {
		t.Fatalf("auto fallback: %v", err)
	}
	if got.mode != runtimeModeLegacyPerf {
		t.Fatalf("auto mode selected %q, want legacy_perf", got.mode)
	}
}

func TestLoadSensorObjectsWithAutoFallsBackToUltraLegacyMap(t *testing.T) {
	loaders := objectLoaders{
		core: func() (loadedSensorObjects, error) {
			return loadedSensorObjects{}, fmt.Errorf("missing BTF")
		},
		legacyPerf: func() (loadedSensorObjects, error) {
			return loadedSensorObjects{}, fmt.Errorf("perf unavailable")
		},
		ultraLegacyMap: func() (loadedSensorObjects, error) {
			return loadedSensorObjects{mode: runtimeModeUltraLegacyMap}, nil
		},
	}

	got, err := loadSensorObjectsWith("auto", loaders)
	if err != nil {
		t.Fatalf("auto ultra fallback: %v", err)
	}
	if got.mode != runtimeModeUltraLegacyMap {
		t.Fatalf("auto mode selected %q, want ultra_legacy_map", got.mode)
	}
}

func TestLoadSensorObjectsWithInvalidMode(t *testing.T) {
	_, err := loadSensorObjectsWith("definitely-not-real", objectLoaders{})
	if err == nil {
		t.Fatal("expected invalid mode error")
	}
}

func TestKprobeSymbolsAreArchitectureAware(t *testing.T) {
	tests := []struct {
		name string
		op   string
		arch string
		want []string
	}{
		{
			name: "amd64",
			op:   "openat",
			arch: "amd64",
			want: []string{"__x64_sys_openat", "__se_sys_openat"},
		},
		{
			name: "arm64",
			op:   "openat",
			arch: "arm64",
			want: []string{"__arm64_sys_openat", "__se_sys_openat"},
		},
		{
			name: "fallback",
			op:   "write",
			arch: "riscv64",
			want: []string{"__riscv64_sys_write", "__se_sys_write"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := kprobeSymbols(tt.op, tt.arch)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("symbols = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestAttachLSMProgramsTreatsFailuresAsOptional(t *testing.T) {
	result := attachLSMPrograms([]*ebpf.Program{nil, nil}, func(*ebpf.Program) (link.Link, error) {
		return nil, fmt.Errorf("lsm unavailable")
	})
	if result.Attached != 0 {
		t.Fatalf("attached = %d, want 0", result.Attached)
	}
	if result.Skipped != 2 {
		t.Fatalf("skipped = %d, want 2", result.Skipped)
	}
	if len(result.links) != 0 {
		t.Fatalf("links len = %d, want 0", len(result.links))
	}
}

func TestAttachLSMProgramsCountsPartialSuccess(t *testing.T) {
	calls := 0
	result := attachLSMPrograms([]*ebpf.Program{nil, nil, nil}, func(*ebpf.Program) (link.Link, error) {
		calls++
		if calls == 2 {
			return nil, fmt.Errorf("lsm unavailable")
		}
		return nil, nil
	})
	if result.Attached != 2 {
		t.Fatalf("attached = %d, want 2", result.Attached)
	}
	if result.Skipped != 1 {
		t.Fatalf("skipped = %d, want 1", result.Skipped)
	}
	if len(result.links) != 0 {
		t.Fatalf("links len = %d, want 0 for nil fake links", len(result.links))
	}
}

func TestBPFLSMActiveFromData(t *testing.T) {
	if !bpfLSMActiveFromData("lockdown,capability,bpf,apparmor\n") {
		t.Fatal("expected active bpf LSM")
	}
	if bpfLSMActiveFromData("lockdown,capability,apparmor\n") {
		t.Fatal("unexpected active bpf LSM")
	}
}

func TestDecodeUltraLegacyEventSlot(t *testing.T) {
	rawEvent := make([]byte, eventSize)
	binary.LittleEndian.PutUint32(rawEvent[8+4+4+4+4:], EventLink)
	copy(rawEvent[8+4+4+4+4+4+4+4+4+8+taskCommLen:], []byte("/src"))
	copy(rawEvent[8+4+4+4+4+4+4+4+4+8+taskCommLen+pathMaxLen:], []byte("/dst"))

	rawSlot := make([]byte, 8+eventSize)
	binary.LittleEndian.PutUint64(rawSlot[:8], 1)
	copy(rawSlot[8:], rawEvent)

	raw := ultraLegacySlotEvent(rawSlot)
	ev, err := DecodeEvent(raw)
	if err != nil {
		t.Fatalf("DecodeEvent: %v", err)
	}
	if ev.Type != EventLink || ev.Path != "/src" || ev.Path2 != "/dst" {
		t.Fatalf("decoded event = %#v", ev)
	}
}

func TestMapPollingEventReaderClose(t *testing.T) {
	r := newMapPollingEventReader(nil, nil)
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := r.Read(); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("Read err = %v, want ErrClosedPipe", err)
	}
}

func TestSyncHashSetClearsAndWritesPolicyValues(t *testing.T) {
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "ioc_hash_test",
		Type:       ebpf.Hash,
		KeySize:    8,
		ValueSize:  1,
		MaxEntries: 8,
	})
	if err != nil {
		t.Fatalf("create map: %v", err)
	}
	defer m.Close()

	var one uint8 = 1
	if err := m.Put(iocHash(".old"), one); err != nil {
		t.Fatalf("put old value: %v", err)
	}
	count, err := syncHashSet(m, []string{".LOCKED", " .enc "}, iocHash)
	if err != nil {
		t.Fatalf("syncHashSet: %v", err)
	}
	if count != 2 {
		t.Fatalf("count = %d, want 2", count)
	}

	var got uint8
	if err := m.Lookup(iocHash(".locked"), &got); err != nil {
		t.Fatalf("lookup .locked: %v", err)
	}
	if err := m.Lookup(iocHash(".enc"), &got); err != nil {
		t.Fatalf("lookup .enc: %v", err)
	}
	if err := m.Lookup(iocHash(".old"), &got); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("old value err = %v, want ErrKeyNotExist", err)
	}
}

func TestSyncProtectedDirsWritesStatKey(t *testing.T) {
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "protected_dirs_test",
		Type:       ebpf.Hash,
		KeySize:    16,
		ValueSize:  1,
		MaxEntries: 8,
	})
	if err != nil {
		t.Fatalf("create map: %v", err)
	}
	defer m.Close()

	dir := t.TempDir()
	count, err := syncProtectedDirs(m, []string{"/definitely/not/here", dir})
	if err != nil {
		t.Fatalf("syncProtectedDirs: %v", err)
	}
	if count != 1 {
		t.Fatalf("count = %d, want 1", count)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat temp dir: %v", err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	key := dirKey{Dev: uint64(stat.Dev), Ino: stat.Ino}
	var got uint8
	if err := m.Lookup(key, &got); err != nil {
		t.Fatalf("lookup protected dir key: %v", err)
	}
}

func TestCgroupFSPath(t *testing.T) {
	if got := cgroupFSPath("/user.slice/session.scope"); got != "/sys/fs/cgroup/user.slice/session.scope" {
		t.Fatalf("cgroupFSPath = %q", got)
	}
	if got := cgroupFSPath("/"); got != "/sys/fs/cgroup" {
		t.Fatalf("root cgroupFSPath = %q", got)
	}
}

func TestSyncCgroupScopeWritesIDsAndToggle(t *testing.T) {
	allowed, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "allowed_cgroups_test",
		Type:       ebpf.Hash,
		KeySize:    8,
		ValueSize:  1,
		MaxEntries: 8,
	})
	if err != nil {
		t.Fatalf("create allowed map: %v", err)
	}
	defer allowed.Close()
	enabled, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "cgroup_scope_enabled_test",
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  1,
		MaxEntries: 1,
	})
	if err != nil {
		t.Fatalf("create enabled map: %v", err)
	}
	defer enabled.Close()

	count, err := syncCgroupScope(allowed, enabled, []string{"/"})
	if err != nil {
		t.Fatalf("syncCgroupScope: %v", err)
	}
	if count != 1 {
		t.Fatalf("count = %d, want 1", count)
	}
	var on uint8
	if err := enabled.Lookup(uint32(0), &on); err != nil {
		t.Fatalf("lookup enabled: %v", err)
	}
	if on != 1 {
		t.Fatalf("enabled = %d, want 1", on)
	}
	info, err := os.Stat("/sys/fs/cgroup")
	if err != nil {
		t.Fatalf("stat cgroup root: %v", err)
	}
	cgid := uint64(info.Sys().(*syscall.Stat_t).Ino)
	var got uint8
	if err := allowed.Lookup(cgid, &got); err != nil {
		t.Fatalf("lookup cgroup id: %v", err)
	}

	count, err = syncCgroupScope(allowed, enabled, nil)
	if err != nil {
		t.Fatalf("disable syncCgroupScope: %v", err)
	}
	if count != 0 {
		t.Fatalf("disabled count = %d, want 0", count)
	}
	if err := enabled.Lookup(uint32(0), &on); err != nil {
		t.Fatalf("lookup disabled: %v", err)
	}
	if on != 0 {
		t.Fatalf("disabled flag = %d, want 0", on)
	}
	if err := allowed.Lookup(cgid, &got); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("old cgroup id err = %v, want ErrKeyNotExist", err)
	}
}

func TestDecodeEventPreservesIPv6ConnectBytes(t *testing.T) {
	raw := make([]byte, eventSize)
	off := 8 + 4 + 4 + 4 + 4
	binary.LittleEndian.PutUint32(raw[off:], EventConnect)
	off += 4
	off += 4
	off += 4
	off += 4
	binary.LittleEndian.PutUint64(raw[off:], 10)
	off += 8
	off += taskCommLen
	copy(raw[off:], []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})

	ev, err := DecodeEvent(raw)
	if err != nil {
		t.Fatalf("DecodeEvent: %v", err)
	}
	if len(ev.Path) != 16 {
		t.Fatalf("IPv6 path len = %d, want 16", len(ev.Path))
	}
	if ev.Path[15] != 1 {
		t.Fatalf("last IPv6 byte = %d, want 1", ev.Path[15])
	}
}
