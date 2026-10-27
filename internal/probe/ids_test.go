package probe_test

import (
	"testing"

	"github.com/aaronburt/netscan/internal/config"
	"github.com/aaronburt/netscan/internal/probe"
)

func idsByAddress(ts []probe.Target) map[string]int {
	m := map[string]int{}
	for _, t := range ts {
		m[t.Address] = t.ID
	}
	return m
}

func TestDefaultHostsKeepLegacyIDs(t *testing.T) {
	r := probe.NewTargetRegistry(config.DefaultConfig())
	for i, tg := range r.GetWANICMP() {
		if tg.ID != 10+i {
			t.Errorf("icmp %s id %d, want %d", tg.Address, tg.ID, 10+i)
		}
	}
	for i, tg := range r.GetWANTCP() {
		if tg.ID != 20+i {
			t.Errorf("tcp %s id %d, want %d", tg.Address, tg.ID, 20+i)
		}
	}
	for i, tg := range r.GetDNS() {
		if tg.ID != 30+i {
			t.Errorf("dns %s id %d, want %d", tg.Address, tg.ID, 30+i)
		}
	}
	for i, tg := range r.GetHTTP() {
		if tg.ID != 50+i {
			t.Errorf("http %s id %d, want %d", tg.Address, tg.ID, 50+i)
		}
	}
}

func TestIDsFollowHostNotPosition(t *testing.T) {
	cfg := config.DefaultConfig()
	ids := probe.NewIDAllocator(nil)
	first := idsByAddress(probe.NewTargetRegistryWithIDs(cfg, ids).GetWANICMP())

	cfg.Targets.WANICMP = []string{"9.9.9.9", "10.1.1.1", "1.1.1.1"}
	second := idsByAddress(probe.NewTargetRegistryWithIDs(cfg, ids).GetWANICMP())

	for _, addr := range []string{"1.1.1.1", "9.9.9.9"} {
		if first[addr] != second[addr] {
			t.Errorf("%s changed id from %d to %d after reorder", addr, first[addr], second[addr])
		}
	}
	if second["10.1.1.1"] < 1000 {
		t.Errorf("new host got id %d, want >= 1000", second["10.1.1.1"])
	}
}

func TestIDsSurviveRestartFromKnownTargets(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Targets.WANICMP = []string{"10.1.1.1", "10.2.2.2"}
	r1 := probe.NewTargetRegistryWithIDs(cfg, probe.NewIDAllocator(nil))

	var known []probe.KnownTarget
	for _, tg := range r1.GetAllTargets() {
		known = append(known, probe.KnownTarget{ID: tg.ID, Layer: tg.Layer, Address: tg.Address})
	}

	cfg.Targets.WANICMP = []string{"10.3.3.3", "10.2.2.2", "10.1.1.1"}
	r2 := probe.NewTargetRegistryWithIDs(cfg, probe.NewIDAllocator(known))
	a, b := idsByAddress(r1.GetWANICMP()), idsByAddress(r2.GetWANICMP())
	for _, addr := range []string{"10.1.1.1", "10.2.2.2"} {
		if a[addr] != b[addr] {
			t.Errorf("%s id %d became %d across restart", addr, a[addr], b[addr])
		}
	}
	if b["10.3.3.3"] == a["10.1.1.1"] || b["10.3.3.3"] == a["10.2.2.2"] {
		t.Error("new host reused an existing id")
	}
}

// A database written by an older version labelled position 0 as id 10 even
// when that was not 1.1.1.1. The default host must not steal that id back.
func TestDefaultHostDoesNotTakeIDOfAnotherHost(t *testing.T) {
	known := []probe.KnownTarget{{ID: 10, Layer: probe.LayerWANICMP, Address: "10.9.9.9"}}
	r := probe.NewTargetRegistryWithIDs(config.DefaultConfig(), probe.NewIDAllocator(known))
	got := idsByAddress(r.GetWANICMP())
	if got["10.9.9.9"] != 0 && got["10.9.9.9"] != 10 {
		t.Fatalf("unexpected id %d", got["10.9.9.9"])
	}
	if got["1.1.1.1"] == 10 || got["1.1.1.1"] < 1000 {
		t.Fatalf("1.1.1.1 got id %d, want a fresh id >= 1000", got["1.1.1.1"])
	}
}

func TestSystemResolversKeepIDs(t *testing.T) {
	r := probe.NewTargetRegistry(config.DefaultConfig())
	r.UpdateSystemResolvers([]string{"192.168.1.1", "192.168.1.2"})
	before := map[string]int{}
	for _, tg := range r.GetDNS() {
		before[tg.Address] = tg.ID
	}
	if before["192.168.1.1"] != 40 || before["192.168.1.2"] != 41 {
		t.Fatalf("system resolver ids = %v, want 40 and 41", before)
	}

	r.UpdateSystemResolvers([]string{"192.168.1.2", "192.168.1.1"})
	for _, tg := range r.GetDNS() {
		if want, ok := before[tg.Address]; ok && tg.ID != want {
			t.Errorf("%s id %d, want %d", tg.Address, tg.ID, want)
		}
	}
}

func TestDuplicateConfiguredHostIsListedOnce(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Targets.WANTCP = []string{"1.1.1.1:443", "1.1.1.1:443"}
	if got := len(probe.NewTargetRegistry(cfg).GetWANTCP()); got != 1 {
		t.Fatalf("got %d tcp targets, want 1", got)
	}
}
