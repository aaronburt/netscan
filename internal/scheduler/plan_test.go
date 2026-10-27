package scheduler

import (
	"net"
	"testing"
	"time"

	"github.com/aaronburt/netscan/internal/config"
	"github.com/aaronburt/netscan/internal/probe"
)

func newPlanScheduler(t *testing.T) *Scheduler {
	t.Helper()
	prof := config.Standard()
	reg := probe.NewTargetRegistry(prof)
	reg.SetGateway(net.ParseIP("192.168.1.1"))
	reg.SetISPHop(net.ParseIP("10.0.0.1"), 2)
	return NewScheduler(prof, reg, make(chan probe.ProbeResult, 1), "test", nil)
}

// Normal mode should probe the gateway and the first WAN ping host every
// second and everything else on its own slower period.
func TestNormalModeProbeRates(t *testing.T) {
	s := newPlanScheduler(t)
	const ticks = 3600 // one hour at 1s
	counts := map[probe.Layer]int{}
	perTarget := map[int]int{}
	var primary, secondary int

	for i := 0; i < ticks; i++ {
		plan := s.planTick(false, time.Second)
		for _, group := range [][]probe.Target{plan.icmp, plan.dns, plan.tcp, plan.http} {
			for _, tg := range group {
				counts[tg.Layer]++
				perTarget[tg.ID]++
				if tg.Layer == probe.LayerWANICMP {
					if tg.ID == 10 {
						primary++
					} else {
						secondary++
					}
				}
			}
		}
	}

	want := map[probe.Layer]int{
		probe.LayerGateway: 3600,
		probe.LayerISPHop:  1800,
		probe.LayerWANICMP: 3600 + 720,
		probe.LayerWANTCP:  720,
		probe.LayerDNS:     720,
		probe.LayerHTTP:    240,
	}
	for layer, n := range want {
		if counts[layer] != n {
			t.Errorf("%s probed %d times in an hour, want %d", layer, counts[layer], n)
		}
	}
	if primary != 3600 || secondary != 720 {
		t.Errorf("WAN ping: primary %d (want 3600), secondary %d (want 720)", primary, secondary)
	}
	// The two secondary hosts share their probes evenly.
	if perTarget[11] != perTarget[12] {
		t.Errorf("secondary ping hosts unevenly probed: %d vs %d", perTarget[11], perTarget[12])
	}
	// Rotation reaches every target of a layer.
	for _, id := range []int{20, 21, 22, 50, 51, 52, 30, 31, 32} {
		if perTarget[id] == 0 {
			t.Errorf("target %d was never probed", id)
		}
	}

	total := 0
	for _, n := range counts {
		total += n
	}
	// About 3.2 probes a second, against 8 before.
	if perSec := float64(total) / ticks; perSec < 3.0 || perSec > 3.4 {
		t.Errorf("%.2f probes/s, want about 3.2", perSec)
	}
}

func TestFastModeProbesEverything(t *testing.T) {
	s := newPlanScheduler(t)
	plan := s.planTick(true, 500*time.Millisecond)
	if len(plan.icmp) != 5 || len(plan.tcp) != 3 || len(plan.dns) != 3 || len(plan.http) != 3 {
		t.Fatalf("fast mode plan: icmp=%d tcp=%d dns=%d http=%d, want 5/3/3/3",
			len(plan.icmp), len(plan.tcp), len(plan.dns), len(plan.http))
	}
	// HTTP runs every other tick in fast mode.
	if plan := s.planTick(true, 500*time.Millisecond); len(plan.http) != 0 {
		t.Fatalf("expected no HTTP on the odd fast tick, got %d", len(plan.http))
	}
}

// Periods are in ticks, so a bigger normal interval keeps them consistent.
func TestEveryN(t *testing.T) {
	cases := []struct {
		periodMS int
		interval time.Duration
		want     int64
	}{
		{5000, time.Second, 5},
		{2000, time.Second, 2},
		{1000, time.Second, 1},
		{500, time.Second, 1},
		{15000, 2 * time.Second, 8}, // 7.5 rounds up
	}
	for _, c := range cases {
		if got := everyN(c.periodMS, c.interval); got != c.want {
			t.Errorf("everyN(%d, %v) = %d, want %d", c.periodMS, c.interval, got, c.want)
		}
	}
}

func TestConfirmTargetIsAnotherInTheSameLayer(t *testing.T) {
	s := newPlanScheduler(t)

	failed := s.registry.GetWANICMP()[0]
	other, ok := s.confirmTarget(failed)
	if !ok || other.ID == failed.ID || other.Layer != probe.LayerWANICMP {
		t.Fatalf("confirm target for %v = %v, %v", failed.ID, other, ok)
	}

	// The gateway and ISP hop have nothing to be confirmed against.
	if _, ok := s.confirmTarget(*s.registry.GetGateway()); ok {
		t.Fatal("gateway should have no confirm target")
	}

	// A layer with a single target can't be confirmed either.
	prof := config.Standard()
	prof.Targets.DNS = []string{"1.1.1.1:53"}
	reg := probe.NewTargetRegistry(prof)
	single := NewScheduler(prof, reg, make(chan probe.ProbeResult, 1), "test", nil)
	if _, ok := single.confirmTarget(reg.GetDNS()[0]); ok {
		t.Fatal("single DNS target should have no confirm target")
	}
}

func collect(ch chan probe.ProbeResult, want int, wait time.Duration) []probe.ProbeResult {
	var got []probe.ProbeResult
	deadline := time.After(wait)
	for len(got) < want {
		select {
		case r := <-ch:
			got = append(got, r)
		case <-deadline:
			return got
		}
	}
	// Give any unexpected extra result a moment to show up.
	select {
	case r := <-ch:
		got = append(got, r)
	case <-time.After(300 * time.Millisecond):
	}
	return got
}

func TestFailedProbeIsConfirmedOnce(t *testing.T) {
	prof := config.Standard()
	// Nothing listens on these ports, so both probes fail fast.
	prof.Targets.WANTCP = []string{"127.0.0.1:1", "127.0.0.1:2"}
	reg := probe.NewTargetRegistry(prof)
	out := make(chan probe.ProbeResult, 10)
	s := NewScheduler(prof, reg, out, "test", nil)
	target := reg.GetWANTCP()[0]

	ctx := t.Context()

	s.run(ctx, target, false, false)
	got := collect(out, 2, 3*time.Second)
	if len(got) != 2 {
		t.Fatalf("got %d results, want the failure plus one confirmation", len(got))
	}
	if got[0].TargetID != target.ID || got[1].TargetID == target.ID {
		t.Fatalf("confirmation should use another target, got ids %d then %d", got[0].TargetID, got[1].TargetID)
	}

	// A confirmation doesn't trigger another confirmation.
	s.run(ctx, reg.GetWANTCP()[1], false, true)
	if got := collect(out, 1, 3*time.Second); len(got) != 1 {
		t.Fatalf("confirmation probe produced %d results, want 1", len(got))
	}

	// Fast mode already probes everything, so there is nothing to confirm.
	s.run(ctx, target, true, false)
	if got := collect(out, 1, 3*time.Second); len(got) != 1 {
		t.Fatalf("fast mode probe produced %d results, want 1", len(got))
	}
}
