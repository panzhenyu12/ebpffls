package sensor

import (
	"errors"
	"os"
	"reflect"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
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
		objects: ransomwareObjects{
			ransomwareMaps: ransomwareMaps{
				RingbufDrops: m,
			},
		},
	}
	drops, err := s.RingbufDrops()
	if err != nil {
		t.Fatalf("RingbufDrops: %v", err)
	}
	if drops != 42 {
		t.Fatalf("drops = %d, want 42", drops)
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
