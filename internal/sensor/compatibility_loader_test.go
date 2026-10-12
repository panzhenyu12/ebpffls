package sensor

import (
	"errors"
	"fmt"
	"io"
	"reflect"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/panzhenyu/ebpffls/internal/config"
)

type trackedStartupCloser struct {
	closed int
	err    error
}

func (c *trackedStartupCloser) Close() error { c.closed++; return c.err }

type trackedStartupReader struct{ closed int }

func (r *trackedStartupReader) Read() (eventRecord, error) { return eventRecord{}, io.EOF }
func (r *trackedStartupReader) Close() error               { r.closed++; return nil }

func TestStartupFallbackIncludesLoadAttachAndReader(t *testing.T) {
	for _, stage := range []string{"load", "attach", "reader"} {
		t.Run(stage, func(t *testing.T) {
			coreCloser := &trackedStartupCloser{}
			legacyCloser := &trackedStartupCloser{}
			probe := &testProbeLink{}
			reader := &trackedStartupReader{}
			var attempts []runtimeMode
			loaders := objectLoaders{
				core: func() (loadedSensorObjects, error) {
					attempts = append(attempts, runtimeModeCore)
					obj := loadedSensorObjects{mode: runtimeModeCore, closer: coreCloser}
					if stage == "load" {
						return obj, fmt.Errorf("core load unsupported")
					}
					return obj, nil
				},
				legacyPerf: func() (loadedSensorObjects, error) {
					attempts = append(attempts, runtimeModeLegacyPerf)
					return loadedSensorObjects{mode: runtimeModeLegacyPerf, closer: legacyCloser}, nil
				},
				ultraLegacyMap: func() (loadedSensorObjects, error) {
					t.Fatal("unexpected extra fallback")
					return loadedSensorObjects{}, nil
				},
			}
			s, err := newSensorWith("auto", loaders, func(s *Sensor) error {
				if s.mode == runtimeModeCore {
					s.links = []link.Link{probe}
					if stage == "reader" {
						s.reader = reader
					}
					return fmt.Errorf("%s unsupported", stage)
				}
				if coreCloser.closed != 1 {
					t.Fatal("fallback started before old objects were closed")
				}
				return nil
			})
			if err != nil || s.mode != runtimeModeLegacyPerf {
				t.Fatalf("result=%+v err=%v", s, err)
			}
			defer s.Close()
			if !reflect.DeepEqual(attempts, []runtimeMode{runtimeModeCore, runtimeModeLegacyPerf}) || coreCloser.closed != 1 {
				t.Fatalf("attempts=%v closed=%d", attempts, coreCloser.closed)
			}
			if stage != "load" && !probe.closed {
				t.Fatal("failed attachment was not closed")
			}
			if stage == "reader" && reader.closed != 1 {
				t.Fatal("failed candidate reader was not closed")
			}
		})
	}
}

func TestStartupConfigurationErrorsDoNotFallback(t *testing.T) {
	closer := &trackedStartupCloser{}
	loaders := objectLoaders{
		core: func() (loadedSensorObjects, error) { return loadedSensorObjects{closer: closer}, nil },
		legacyPerf: func() (loadedSensorObjects, error) {
			t.Fatal("configuration error triggered fallback")
			return loadedSensorObjects{}, nil
		},
	}
	_, err := newSensorWith("auto", loaders, func(*Sensor) error { return &configurationError{fmt.Errorf("invalid policy action")} })
	var configErr *configurationError
	if !errors.As(err, &configErr) || closer.closed != 1 {
		t.Fatalf("err=%v closed=%d", err, closer.closed)
	}
}

func TestForcedModeAndCleanupFailurePreventFallback(t *testing.T) {
	for _, mode := range []string{"core", "auto"} {
		t.Run(mode, func(t *testing.T) {
			closer := &trackedStartupCloser{}
			if mode == "auto" {
				closer.err = fmt.Errorf("cleanup incomplete")
			}
			loaders := objectLoaders{
				core:       func() (loadedSensorObjects, error) { return loadedSensorObjects{closer: closer}, nil },
				legacyPerf: func() (loadedSensorObjects, error) { t.Fatal("unsafe fallback"); return loadedSensorObjects{}, nil },
			}
			_, err := newSensorWith(mode, loaders, func(*Sensor) error { return fmt.Errorf("attach unsupported") })
			if err == nil || closer.closed != 1 {
				t.Fatalf("err=%v closed=%d", err, closer.closed)
			}
		})
	}
}

func TestSuccessfulStartupResourcesCloseExactlyOnce(t *testing.T) {
	closer, reader, probe := &trackedStartupCloser{}, &trackedStartupReader{}, &testProbeLink{}
	s, err := newSensorWith("core", objectLoaders{core: func() (loadedSensorObjects, error) { return loadedSensorObjects{closer: closer}, nil }}, func(s *Sensor) error {
		s.reader, s.links = reader, []link.Link{probe}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if closer.closed != 1 || reader.closed != 1 || !probe.closed {
		t.Fatalf("resource lifecycle: closer=%d reader=%d probe=%v", closer.closed, reader.closed, probe.closed)
	}
}

func TestGroupedLoaderKeepsOptionalProgramsOutOfBaseAndSharesMaps(t *testing.T) {
	spec := &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{"shared": {Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1}},
		Programs: map[string]*ebpf.ProgramSpec{
			"trace_execve":       {Type: ebpf.TracePoint},
			"enforce_file_open":  {Type: ebpf.LSM},
			"kp_override_openat": {Type: ebpf.Kprobe},
		},
	}
	shared := &ebpf.Map{}
	var calls []string
	var base *ebpf.Collection
	bundle, err := loadGroupedCollections(runtimeModeCore, spec, ebpf.CollectionOptions{}, func(group *ebpf.CollectionSpec, opts ebpf.CollectionOptions) (*ebpf.Collection, error) {
		if len(calls) == 0 {
			if len(group.Programs) != 1 || group.Programs["trace_execve"] == nil || opts.MapReplacements != nil {
				t.Fatal("optional enforcement contaminated base load")
			}
			calls = append(calls, "base")
			base = &ebpf.Collection{Maps: map[string]*ebpf.Map{"shared": shared}, Programs: map[string]*ebpf.Program{"trace_execve": nil}}
			return base, nil
		}
		if len(group.Programs) != 1 || opts.MapReplacements["shared"] != shared {
			t.Fatal("optional program does not share the base map")
		}
		for name := range group.Programs {
			calls = append(calls, name)
			if name == "enforce_file_open" {
				return nil, fmt.Errorf("LSM unsupported")
			}
			return &ebpf.Collection{Programs: map[string]*ebpf.Program{name: nil}}, nil
		}
		panic("unreachable")
	})
	if err != nil {
		t.Fatal(err)
	}
	// The fake map has no kernel FD; real bundles own cloned map references.
	base.Maps["shared"] = nil
	defer bundle.Close()
	if !reflect.DeepEqual(calls, []string{"base", "enforce_file_open", "kp_override_openat"}) {
		t.Fatalf("group order=%v", calls)
	}
	if _, exists := bundle.programs["enforce_file_open"]; exists {
		t.Fatal("failed optional program was retained")
	}
	if _, exists := bundle.programs["kp_override_openat"]; !exists {
		t.Fatal("one optional failure discarded other capabilities")
	}
	if len(spec.Programs) != 3 {
		t.Fatal("grouping mutated original program spec")
	}
}

func TestGroupedLoaderStopsWhenCoreCollectionFails(t *testing.T) {
	calls := 0
	_, err := loadGroupedCollections(runtimeModeCore, &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{"optional": {Type: ebpf.LSM}}}, ebpf.CollectionOptions{}, func(*ebpf.CollectionSpec, ebpf.CollectionOptions) (*ebpf.Collection, error) {
		calls++
		return nil, fmt.Errorf("maps unavailable")
	})
	if err == nil || calls != 1 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
}

func TestGeneratedOptionalBindingsRemainNil(t *testing.T) {
	var objects struct {
		Events   *ebpf.Map     `ebpf:"events"`
		Optional *ebpf.Program `ebpf:"optional"`
	}
	mapObject := &ebpf.Map{}
	bindAvailableObjects(&objects, map[string]*ebpf.Map{"events": mapObject}, map[string]*ebpf.Program{})
	if objects.Events != mapObject || objects.Optional != nil {
		t.Fatalf("wrong optional bindings: %+v", objects)
	}
}

func TestArchitectureSpecificRequiredTracepoints(t *testing.T) {
	for _, op := range []string{"dup2", "rename", "unlink", "link", "symlink"} {
		for _, phase := range []string{"sys_enter_", "sys_exit_"} {
			if !optionalSyscallTracepoint("syscalls", phase+op, "arm64") {
				t.Fatalf("absent arm64 syscall %s remained required", op)
			}
			if optionalSyscallTracepoint("syscalls", phase+op, "amd64") {
				t.Fatalf("amd64 syscall %s was weakened", op)
			}
		}
	}
	for _, op := range []string{"openat", "renameat", "unlinkat", "dup3", "write", "pwrite64", "writev"} {
		if optionalSyscallTracepoint("syscalls", "sys_enter_"+op, "arm64") {
			t.Fatalf("required arm64 coverage %s weakened", op)
		}
	}
}

func TestDenyCapabilitiesAreExplicitAndNeverBecomeKill(t *testing.T) {
	s := &Sensor{mode: runtimeModeLegacyPerf, maps: sensorMaps{BlockedTgids: &ebpf.Map{}}}
	for _, policy := range []config.Policy{
		{Action: "deny"}, {Action: "kill", Rules: []config.Rule{{Name: "scoped", Action: "deny"}}},
		{Action: "log", Rules: []config.Rule{{Name: "alias", Action: "block"}}},
	} {
		if err := s.validatePolicyCapabilities(policy, false); !errors.Is(err, ErrDenyUnavailable) {
			t.Fatalf("unsupported deny accepted: policy=%+v err=%v", policy, err)
		}
		if err := s.validatePolicyCapabilities(policy, true); err != nil {
			t.Fatalf("dry-run rejected: %v", err)
		}
	}
	if err := s.BlockTGID(42, BlockActionDeny, time.Second); !errors.Is(err, ErrDenyUnavailable) {
		t.Fatalf("deny was not rejected before map mutation: %v", err)
	}
	if err := s.validatePolicyCapabilities(config.Policy{Action: "kill"}, false); err != nil {
		t.Fatalf("userspace kill fallback rejected: %v", err)
	}
	s.recordDenyHook("override", "renameat")
	if !s.capabilities.DenyAvailable || s.capabilities.DenyOpenat {
		t.Fatal("partial hook claimed openat coverage")
	}
	if err := s.validatePolicyCapabilities(config.Policy{Action: "deny"}, false); err != nil {
		t.Fatal(err)
	}
	s.recordDenyHook("lsm", "file_open")
	if !s.capabilities.DenyOpenat {
		t.Fatal("file_open LSM did not advertise openat coverage")
	}
}

func TestCapabilitySnapshotsDoNotExposeMutableHookLists(t *testing.T) {
	s := &Sensor{}
	s.recordDenyHook("override", "openat")
	caps := s.Capabilities()
	caps.OverrideHooks[0] = "unknown"
	if s.capabilities.OverrideHooks[0] != "openat" {
		t.Fatal("snapshot mutated sensor capability state")
	}
}

func TestPathRenameVariantMatchesExactTargetPrototype(t *testing.T) {
	for _, tc := range []struct {
		count int
		name  string
	}{{4, "enforce_path_rename_legacy"}, {5, "enforce_path_rename"}, {3, ""}, {6, ""}} {
		if got := pathRenameVariant(tc.count); got != tc.name {
			t.Fatalf("params=%d program=%q want=%q", tc.count, got, tc.name)
		}
	}
}

func TestInvalidExplicitBTFIsConfigurationError(t *testing.T) {
	t.Setenv("EBPFFLS_BTF", t.TempDir()+"/missing.btf")
	_, err := coreCollectionOptions()
	var configuration *configurationError
	if !errors.As(err, &configuration) {
		t.Fatalf("invalid explicit BTF was treated as kernel capability: %v", err)
	}
}
