package sensor

import (
	"fmt"
	"reflect"
	"runtime"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type testProbeLink struct {
	link.Link
	closed bool
}

func (l *testProbeLink) Close() error {
	l.closed = true
	return nil
}

func TestSyscallABIUsesExactOperationAndSymbol(t *testing.T) {
	ops := []string{"execve", "open", "openat", "write", "pwrite64", "writev", "rename", "link", "symlink", "unlink", "truncate", "ftruncate"}
	for index, op := range ops {
		for _, symbol := range []string{"__x64_sys_" + op, "__se_sys_" + op, "sys_" + op} {
			key, abi, err := syscallABIForSymbol(op, symbol)
			wantABI := uint32(1)
			if symbol == "__x64_sys_"+op {
				wantABI = 2
			}
			if err != nil || key != uint32(index+1) || abi != wantABI {
				t.Fatalf("op=%s symbol=%s: key=%d abi=%d err=%v", op, symbol, key, abi, err)
			}
		}
	}
	for _, test := range []struct{ op, symbol string }{
		{"write", "__x64_sys_writev"},
		{"write", "__ia32_sys_write"},
		{"write", "__arm64_sys_write"},
		{"write", "__do_sys_write"},
		{"execveat", "__x64_sys_execveat"},
		{"do_exit", "do_exit"},
	} {
		if _, _, err := syscallABIForSymbol(test.op, test.symbol); err == nil {
			t.Fatalf("guessed unsupported ABI: %+v", test)
		}
	}
}

func TestKprobeConfiguresOnlyAfterSuccessfulAttachment(t *testing.T) {
	symbols := kprobeSymbols("execve", runtime.GOARCH)
	var steps []string
	probe := &testProbeLink{}
	got, symbol, err := attachKprobeWith("execve", nil, func(candidate string, _ *ebpf.Program) (link.Link, error) {
		steps = append(steps, "attach "+candidate)
		if candidate == symbols[0] {
			return nil, fmt.Errorf("symbol unavailable")
		}
		return probe, nil
	}, func(candidate string) error {
		steps = append(steps, "configure "+candidate)
		return nil
	})
	if err != nil || got != probe || symbol != symbols[1] || probe.closed {
		t.Fatalf("attach result: link=%v symbol=%s err=%v closed=%v", got, symbol, err, probe.closed)
	}
	want := []string{"attach " + symbols[0], "attach " + symbols[1], "configure " + symbols[1]}
	if !reflect.DeepEqual(steps, want) {
		t.Fatalf("ABI enabled before successful attachment: %v", steps)
	}
}

func TestKprobeConfigurationFailureClosesAttachment(t *testing.T) {
	probe := &testProbeLink{}
	attachCalls := 0
	got, symbol, err := attachKprobeWith("execve", nil, func(string, *ebpf.Program) (link.Link, error) {
		attachCalls++
		return probe, nil
	}, func(string) error { return fmt.Errorf("map update failed") })
	if err == nil || got != nil || symbol != "" || !probe.closed || attachCalls != 1 {
		t.Fatalf("configuration failure retained a probe: link=%v symbol=%s err=%v closed=%v attempts=%d", got, symbol, err, probe.closed, attachCalls)
	}
}

func TestKprobePairEnablesABIOnlyAfterBothHooks(t *testing.T) {
	symbols := kprobeSymbols("write", runtime.GOARCH)
	var steps []string
	var entries []*testProbeLink
	exit := &testProbeLink{}
	links, symbol, err := attachKprobePairWith("write", &ebpf.Program{}, &ebpf.Program{},
		func(candidate string, _ *ebpf.Program) (link.Link, error) {
			steps = append(steps, "entry "+candidate)
			entry := &testProbeLink{}
			entries = append(entries, entry)
			return entry, nil
		},
		func(candidate string, _ *ebpf.Program) (link.Link, error) {
			steps = append(steps, "exit "+candidate)
			if candidate == symbols[0] {
				return nil, fmt.Errorf("return hook unavailable")
			}
			return exit, nil
		},
		func(candidate string) error {
			steps = append(steps, "configure "+candidate)
			return nil
		})
	if err != nil || symbol != symbols[1] || len(links) != 2 || !entries[0].closed || entries[1].closed || exit.closed {
		t.Fatalf("pair fallback retained wrong hooks: symbol=%s links=%d entries=%+v err=%v", symbol, len(links), entries, err)
	}
	want := []string{"entry " + symbols[0], "exit " + symbols[0], "entry " + symbols[1], "exit " + symbols[1], "configure " + symbols[1]}
	if !reflect.DeepEqual(steps, want) {
		t.Fatalf("pair configuration order=%v, want %v", steps, want)
	}
}

func TestKprobePairConfigurationFailureClosesBothHooks(t *testing.T) {
	entry, exit := &testProbeLink{}, &testProbeLink{}
	links, symbol, err := attachKprobePairWith("write", &ebpf.Program{}, &ebpf.Program{},
		func(string, *ebpf.Program) (link.Link, error) { return entry, nil },
		func(string, *ebpf.Program) (link.Link, error) { return exit, nil },
		func(string) error { return fmt.Errorf("map update failed") })
	if err == nil || len(links) != 0 || symbol != "" || !entry.closed || !exit.closed {
		t.Fatalf("pair configuration failure leaked hooks: links=%v symbol=%s err=%v entryClosed=%v exitClosed=%v", links, symbol, err, entry.closed, exit.closed)
	}
}

func TestKprobePairNeverMixesSymbolsOrEnablesFailedCandidates(t *testing.T) {
	var entrySymbol string
	var entries []*testProbeLink
	configured := false
	links, _, err := attachKprobePairWith("write", &ebpf.Program{}, &ebpf.Program{},
		func(candidate string, _ *ebpf.Program) (link.Link, error) {
			entrySymbol = candidate
			entry := &testProbeLink{}
			entries = append(entries, entry)
			return entry, nil
		},
		func(candidate string, _ *ebpf.Program) (link.Link, error) {
			if candidate != entrySymbol {
				t.Fatalf("mixed entry=%s exit=%s", entrySymbol, candidate)
			}
			return nil, fmt.Errorf("return hooks unavailable")
		},
		func(string) error { configured = true; return nil })
	if err == nil || len(links) != 0 || configured {
		t.Fatalf("enabled incomplete pair: links=%v configured=%v err=%v", links, configured, err)
	}
	for _, entry := range entries {
		if !entry.closed {
			t.Fatal("failed candidate's entry hook remained attached")
		}
	}
}

func TestKprobeABIConfigurationIsUltraOnly(t *testing.T) {
	for _, mode := range []runtimeMode{runtimeModeCore, runtimeModeLegacyPerf} {
		s := &Sensor{mode: mode}
		if err := s.configureKprobeABI("write", "unsupported-for-ultra"); err != nil {
			t.Fatalf("%s unexpectedly requires ABI map: %v", mode, err)
		}
	}
	s := &Sensor{mode: runtimeModeUltraLegacyMap}
	if err := s.configureKprobeABI("write", "__x64_sys_write"); err == nil {
		t.Fatal("ultra silently accepted a missing ABI map")
	}
}

func TestKprobeABIMapKeepsRelatedSyscallsIndependent(t *testing.T) {
	m := newTestMap(t, &ebpf.MapSpec{
		Name: "syscall_abi_test", Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 13,
	})
	defer m.Close()
	s := &Sensor{mode: runtimeModeUltraLegacyMap, maps: sensorMaps{SyscallABI: m}}
	for _, test := range []struct {
		op, symbol string
		key, abi   uint32
	}{
		{"write", "__x64_sys_write", 4, 2},
		{"pwrite64", "__se_sys_pwrite64", 5, 1},
		{"writev", "sys_writev", 6, 1},
	} {
		if err := s.configureKprobeABI(test.op, test.symbol); err != nil {
			t.Fatal(err)
		}
		var got uint32
		if err := m.Lookup(test.key, &got); err != nil || got != test.abi {
			t.Fatalf("op=%s ABI=%d want=%d err=%v", test.op, got, test.abi, err)
		}
	}
	var unset uint32
	if err := m.Lookup(uint32(1), &unset); err != nil || unset != 0 {
		t.Fatalf("unattached exec was enabled: abi=%d err=%v", unset, err)
	}
}

func TestUltraLegacyObjectIncludesSyscallABIMap(t *testing.T) {
	spec, err := loadRansomwareUltraLegacy()
	if err != nil {
		t.Fatal(err)
	}
	abi := spec.Maps["syscall_abi"]
	if abi == nil || abi.Type != ebpf.Array || abi.KeySize != 4 || abi.ValueSize != 4 || abi.MaxEntries != 13 {
		t.Fatalf("unexpected syscall ABI schema: %+v", abi)
	}
}
