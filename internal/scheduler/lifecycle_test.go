package scheduler

import (
	"net"
	"testing"
	"time"

	"github.com/aaronburt/netscan/internal/config"
	"github.com/aaronburt/netscan/internal/detector"
	"github.com/aaronburt/netscan/internal/probe"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time { return c.t }

// sim runs the real planner and detector against a fake clock and a network
// that is down between downFrom and downTo (the gateway stays up, as in a
// WAN outage).
type sim struct {
	t      *testing.T
	clock  *fakeClock
	sched  *Scheduler
	det    *detector.Detector
	reg    *probe.TargetRegistry
	start  time.Time
	downAt time.Duration
	upAt   time.Duration

	created []*detector.Event
	closed  []*detector.Event

	// notOutage counts ticks inside [watchFrom, watchTo) where the detector
	// did not report an outage.
	watchFrom, watchTo time.Duration
	notOutage          int

	// unknown counts ticks in [knownFrom, knownTo) where a probed layer had
	// no fresh result.
	knownFrom, knownTo time.Duration
	unknown            int
}

func newSim(t *testing.T, prof config.Profile, downAt, upAt time.Duration) *sim {
	t.Helper()
	reg := probe.NewTargetRegistry(prof)
	reg.SetGateway(net.ParseIP("192.168.1.1"))
	reg.SetISPHop(net.ParseIP("10.0.0.1"), 2)
	s := &sim{
		t:      t,
		clock:  &fakeClock{t: time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)},
		reg:    reg,
		downAt: downAt,
		upAt:   upAt,
	}
	s.start = s.clock.t
	s.sched = NewScheduler(prof, reg, make(chan probe.ProbeResult, 1), "test", nil)
	s.det = detector.NewDetector(config.DefaultConfig(), prof, s.clock, func(fast bool) { s.sched.SetFastMode(fast) })
	return s
}

func (s *sim) elapsed() time.Duration { return s.clock.t.Sub(s.start) }

func (s *sim) networkUp(t probe.Target) bool {
	if t.Layer == probe.LayerGateway {
		return true
	}
	e := s.elapsed()
	return e < s.downAt || e >= s.upAt
}

func (s *sim) probeOnce(t probe.Target, fast bool) {
	ok := s.networkUp(t)
	res := probe.ProbeResult{
		TargetID:    t.ID,
		Target:      t,
		SendTimeUTC: s.clock.t.UnixMilli(),
		Reached:     ok,
		OK:          ok,
		RTTUS:       15000,
	}
	_, c, cl := s.det.ProcessProbe(res)
	s.record(c, cl)
}

func (s *sim) record(c, cl *detector.Event) {
	if c != nil {
		s.created = append(s.created, c)
	}
	if cl != nil {
		s.closed = append(s.closed, cl)
	}
}

// step runs one scheduler tick and one detector tick, and advances the clock
// by the tick's interval.
func (s *sim) step() {
	prof, _ := s.sched.current()
	fast := s.sched.IsFastMode()
	iv := time.Duration(prof.Intervals.NormalMS) * time.Millisecond
	if fast {
		iv = time.Duration(prof.Intervals.FastMS) * time.Millisecond
	}
	// As Run does at the top of each tick.
	s.sched.noteApply()
	plan := s.sched.planTick(fast, iv)
	for _, group := range [][]probe.Target{plan.icmp, plan.dns, plan.tcp, plan.http} {
		for _, tg := range group {
			s.probeOnce(tg, fast)
			if !s.networkUp(tg) && !fast && prof.Mode != config.ModeParallel {
				if other, ok := s.sched.confirmTarget(tg); ok {
					s.probeOnce(other, fast)
				}
			}
		}
	}
	c, cl := s.det.Tick(s.clock.t)
	s.record(c, cl)
	if e := s.elapsed(); e >= s.watchFrom && e < s.watchTo && s.det.GetSnapshot().State != detector.StateOutage {
		s.notOutage++
	}
	if e := s.elapsed(); e >= s.knownFrom && e < s.knownTo {
		st := s.det.GetSnapshot().LayerStatuses
		for _, l := range []probe.Layer{probe.LayerWANTCP, probe.LayerDNS, probe.LayerHTTP} {
			if st[l] == detector.LayerStatusUnknown {
				s.unknown++
			}
		}
	}
	s.clock.t = s.clock.t.Add(iv)
}

func (s *sim) runUntil(d time.Duration) {
	for s.elapsed() < d {
		s.step()
	}
}

// Every built-in profile should see one outage start and end, and not invent
// events while healthy, even when slow layers are only probed every minute.
func TestOutageLifecycleUnderEachBuiltIn(t *testing.T) {
	const (
		downAt = 3 * time.Minute
		upAt   = 6 * time.Minute
	)
	// The latest an outage may be reported after the network came back, and
	// the latest it may be noticed after it began.
	slack := map[string]time.Duration{
		config.ProfileStandard:   time.Minute,
		config.ProfileAggressive: 30 * time.Second,
		config.ProfileLax:        3 * time.Minute,
	}
	noticed := map[string]time.Duration{
		config.ProfileStandard:   30 * time.Second,
		config.ProfileAggressive: 15 * time.Second,
		config.ProfileLax:        2 * time.Minute,
	}

	for _, prof := range config.BuiltInProfiles() {
		t.Run(prof.ID, func(t *testing.T) {
			s := newSim(t, prof, downAt, upAt)
			// Once every layer has been probed, none should fall back to
			// Unknown between probes, however slow its period.
			s.knownFrom, s.knownTo = 2*time.Minute, downAt
			s.runUntil(downAt - time.Second)
			if s.unknown != 0 {
				t.Errorf("a probed layer was Unknown on %d healthy ticks", s.unknown)
			}
			if len(s.created)+len(s.closed) != 0 {
				t.Fatalf("events while healthy: %d created, %d closed", len(s.created), len(s.closed))
			}

			s.watchFrom, s.watchTo = downAt+noticed[prof.ID], upAt
			s.runUntil(upAt - time.Second)
			if s.notOutage != 0 {
				t.Errorf("detector left the outage state on %d ticks while the network was down", s.notOutage)
			}
			if len(s.created) != 1 || s.created[0].Kind != detector.EventKindOutage {
				t.Fatalf("want one outage open during the outage, got %d events", len(s.created))
			}
			if len(s.closed) != 0 {
				t.Fatalf("outage closed %d times before the network came back", len(s.closed))
			}
			startedAfter := time.UnixMilli(s.created[0].StartMS).Sub(s.start.Add(downAt))
			if startedAfter < -time.Second || startedAfter > noticed[prof.ID] {
				t.Errorf("outage start is %v after the real start, want within %v", startedAfter, noticed[prof.ID])
			}

			s.runUntil(upAt + 4*time.Minute)
			if len(s.created) != 1 {
				t.Fatalf("recovery created %d extra events", len(s.created)-1)
			}
			if len(s.closed) != 1 {
				t.Fatalf("want the outage closed once, got %d", len(s.closed))
			}
			endedAfter := time.UnixMilli(*s.closed[0].EndMS).Sub(s.start.Add(upAt))
			if endedAfter < 0 || endedAfter > slack[prof.ID] {
				t.Errorf("outage ended %v after the network came back, want within %v", endedAfter, slack[prof.ID])
			}
		})
	}
}

// Switching profiles in the middle of an outage must neither end it nor open
// a second one, including onto a profile whose slow layers are probed rarely.
func TestSwitchDuringOutageKeepsItOpen(t *testing.T) {
	for _, target := range []config.Profile{config.Lax(), config.Aggressive()} {
		t.Run("to "+target.ID, func(t *testing.T) {
			s := newSim(t, config.Standard(), 90*time.Second, 6*time.Minute)
			s.runUntil(3 * time.Minute)
			if len(s.created) != 1 {
				t.Fatalf("setup: want an open outage, got %d events", len(s.created))
			}
			evtID := s.created[0].ID

			s.det.Apply(target, 0)
			s.reg.Reconfigure(target)
			s.sched.Apply(target, s.reg)

			s.runUntil(5 * time.Minute)
			if len(s.created) != 1 || len(s.closed) != 0 {
				t.Fatalf("after switch: %d created, %d closed; the outage should simply continue", len(s.created), len(s.closed))
			}

			s.runUntil(9 * time.Minute)
			if len(s.closed) != 1 || s.closed[0].ID != evtID {
				t.Fatalf("outage %d should close once the network is back, closed: %v", evtID, s.closed)
			}
		})
	}
}
