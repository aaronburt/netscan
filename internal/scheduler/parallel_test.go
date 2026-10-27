package scheduler

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/aaronburt/netscan/internal/config"
	"github.com/aaronburt/netscan/internal/probe"
)

func newProfileScheduler(prof config.Profile) *Scheduler {
	reg := probe.NewTargetRegistry(prof)
	reg.SetGateway(net.ParseIP("192.168.1.1"))
	reg.SetISPHop(net.ParseIP("10.0.0.1"), 2)
	return NewScheduler(prof, reg, make(chan probe.ProbeResult, 1), "test", nil)
}

// Aggressive probes every host of a layer each period: no rotation.
func TestParallelModeProbesEveryHostEachPeriod(t *testing.T) {
	s := newProfileScheduler(config.Aggressive())
	const ticks = 7200 // one hour at 500ms
	perTarget := map[int]int{}
	for i := 0; i < ticks; i++ {
		plan := s.planTick(false, 500*time.Millisecond)
		for _, group := range [][]probe.Target{plan.icmp, plan.dns, plan.tcp, plan.http} {
			for _, tg := range group {
				perTarget[tg.ID]++
			}
		}
	}
	want := map[int]int{
		1: 7200, 2: 7200, // gateway, ISP hop every tick
		10: 7200, 11: 7200, 12: 7200, // ping hosts every tick
		20: 1800, 21: 1800, 22: 1800, // TCP every 2s
		30: 1800, 31: 1800, 32: 1800, // DNS every 2s
		50: 720, 51: 720, 52: 720, // HTTP every 5s
	}
	for id, n := range want {
		if perTarget[id] != n {
			t.Errorf("target %d probed %d times in an hour, want %d", id, perTarget[id], n)
		}
	}
}

func TestParallelFailureIsNotConfirmed(t *testing.T) {
	prof := config.Aggressive()
	prof.Targets.WANTCP = []string{"127.0.0.1:1", "127.0.0.1:2"}
	reg := probe.NewTargetRegistry(prof)
	out := make(chan probe.ProbeResult, 10)
	s := NewScheduler(prof, reg, out, "test", nil)

	s.run(t.Context(), reg.GetWANTCP()[0], false, false)
	if got := collect(out, 1, 3*time.Second); len(got) != 1 {
		t.Fatalf("got %d results, want 1: every host is already probed each period", len(got))
	}
}

// Probes of a layer are spread over its quarter of the tick, not fired
// together.
func TestParallelHostsAreSpreadAcrossTheTick(t *testing.T) {
	prof := config.Aggressive()
	prof.Targets.WANTCP = []string{"127.0.0.1:1", "127.0.0.1:2", "127.0.0.1:3", "127.0.0.1:4"}
	reg := probe.NewTargetRegistry(prof)
	out := make(chan probe.ProbeResult, 16)
	s := NewScheduler(prof, reg, out, "test", nil)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	s.launchSpread(ctx, 0, 400*time.Millisecond, reg.GetWANTCP(), true)

	var sent []int64
	for len(sent) < 4 {
		select {
		case r := <-out:
			sent = append(sent, r.SendMonoNS)
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d of 4 probes ran", len(sent))
		}
	}
	// Judge by when each probe was sent, not when its result was read: a busy
	// machine can read them late, but the sends stay spaced out.
	lo, hi := sent[0], sent[0]
	for _, v := range sent {
		lo, hi = min(lo, v), max(hi, v)
	}
	if span := time.Duration(hi - lo); span < 200*time.Millisecond {
		t.Fatalf("probes were sent within %v of each other, want them spread across the window", span)
	}
}

func TestApplyRestartsRotationAndWakesTheLoop(t *testing.T) {
	s := newProfileScheduler(config.Standard())
	for i := 0; i < 7; i++ {
		s.planTick(false, time.Second)
	}
	if s.ticks != 7 {
		t.Fatalf("setup: ticks = %d, want 7", s.ticks)
	}

	lax := config.Lax()
	reg := probe.NewTargetRegistry(lax)
	s.Apply(lax, reg)
	select {
	case <-s.wake:
	default:
		t.Fatal("Apply should wake the run loop")
	}
	if !s.noteApply() {
		t.Fatal("noteApply should see the switch")
	}
	if s.noteApply() {
		t.Fatal("noteApply should report a switch once")
	}
	if s.ticks != 0 || s.tcpIdx != 0 {
		t.Fatalf("rotation not restarted: ticks=%d tcpIdx=%d", s.ticks, s.tcpIdx)
	}
	// Every layer is due on the first tick of the new plan.
	plan := s.planTick(false, 5*time.Second)
	if len(plan.tcp) != 1 || len(plan.dns) != 1 || len(plan.http) != 1 {
		t.Fatalf("first tick after switch: tcp=%d dns=%d http=%d, want 1/1/1", len(plan.tcp), len(plan.dns), len(plan.http))
	}
	if p, r := s.current(); p.ID != config.ProfileLax || r != reg {
		t.Fatalf("current = %s, want lax", p.ID)
	}
}

// A running scheduler picks up a new profile's interval immediately instead
// of finishing a long wait first.
func TestApplyCutsShortAWait(t *testing.T) {
	prof := config.Lax()
	prof.Targets.WANTCP = []string{"127.0.0.1:1", "127.0.0.1:2"}
	prof.Targets.DNS = nil
	prof.Targets.HTTP = nil
	prof.Targets.WANICMP = nil
	out := make(chan probe.ProbeResult, 64)
	reg := probe.NewTargetRegistry(prof)
	s := NewScheduler(prof, reg, out, "test", nil)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	go func() { _ = s.Run(ctx); close(done) }()

	// The first tick runs at once; the next would be five seconds away.
	if got := collect(out, 1, 3*time.Second); len(got) == 0 {
		t.Fatal("no probe on the first tick")
	}
	for len(out) > 0 {
		<-out
	}

	fast := config.Aggressive()
	fast.Targets = prof.Targets
	reg.Reconfigure(fast)
	s.Apply(fast, reg)
	select {
	case <-out:
	case <-time.After(2 * time.Second):
		t.Fatal("no probe within 2s of switching from a 5s interval to a 500ms one")
	}
	cancel()
	<-done
}
