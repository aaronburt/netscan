package probe_test

import (
	"fmt"
	"testing"

	"github.com/aaronburt/netscan/internal/config"
	"github.com/aaronburt/netscan/internal/probe"
)

func TestRegistryIDsStayUniqueWithManyTargets(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Targets.WANICMP = nil
	for i := 0; i < 12; i++ {
		cfg.Targets.WANICMP = append(cfg.Targets.WANICMP, fmt.Sprintf("10.0.0.%d", i+1))
	}
	r := probe.NewTargetRegistry(cfg)

	seen := map[int]probe.Target{}
	for _, t2 := range r.GetAllTargets() {
		if prev, dup := seen[t2.ID]; dup {
			t.Fatalf("id %d used by %s and %s", t2.ID, prev.Label, t2.Label)
		}
		seen[t2.ID] = t2
	}
	if got := len(r.GetWANICMP()); got != 12 {
		t.Fatalf("got %d ICMP targets, want 12", got)
	}
	// Default ids stay the same so existing databases line up.
	if r.GetWANICMP()[0].ID != 10 || r.GetWANTCP()[0].ID != 20 || r.GetHTTP()[0].ID != 50 {
		t.Fatal("default target ids changed")
	}
}

func TestSystemResolversReplaceOldOnes(t *testing.T) {
	r := probe.NewTargetRegistry(config.DefaultConfig())
	r.UpdateSystemResolvers([]string{"192.168.1.1", "fec0:0:0:ffff::1", "1.1.1.1"})
	if got := len(r.GetDNS()); got != 5 { // 3 configured + 2 new (1.1.1.1 is a duplicate)
		t.Fatalf("got %d DNS targets after first update, want 5", got)
	}

	r.UpdateSystemResolvers([]string{"192.168.1.1"})
	if got := len(r.GetDNS()); got != 4 {
		t.Fatalf("got %d DNS targets after second update, want 4", got)
	}
	dnsCount := 0
	for _, t2 := range r.GetAllTargets() {
		if t2.Layer == probe.LayerDNS {
			dnsCount++
		}
	}
	if dnsCount != 4 {
		t.Fatalf("allTargets still holds %d DNS targets, want 4", dnsCount)
	}
}

func TestWithDefaultPort(t *testing.T) {
	cases := map[string]string{
		"1.1.1.1":          "1.1.1.1:53",
		"1.1.1.1:5353":     "1.1.1.1:5353",
		"fec0:0:0:ffff::1": "[fec0:0:0:ffff::1]:53",
		"[::1]:53":         "[::1]:53",
		"[::1]":            "[::1]:53",
	}
	for in, want := range cases {
		if got := probe.WithDefaultPort(in, "53"); got != want {
			t.Errorf("WithDefaultPort(%q) = %q, want %q", in, got, want)
		}
	}
}
