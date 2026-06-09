package sensor

import (
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
