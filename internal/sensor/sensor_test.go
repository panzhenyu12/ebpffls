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
