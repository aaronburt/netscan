package scheduler

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aaronburt/netscan/internal/config"
	"github.com/aaronburt/netscan/internal/platform"
	"github.com/aaronburt/netscan/internal/probe"
)

type Scheduler struct {
	// profile and registry change on Apply, so goroutines read them through
	// current.
	planLock sync.RWMutex
	profile  config.Profile
	registry *probe.TargetRegistry
	applied  uint64 // bumped by Apply
	wake     chan struct{}

	outCh      chan probe.ProbeResult
	fastMode   atomic.Bool
	paused     atomic.Bool
	seq        atomic.Uint64
	dropped    atomic.Int64
	inFlight   map[int]*atomic.Int32
	flightLock sync.Mutex
	version    string

	// Only touched by the Run goroutine (through planTick).
	seenApply uint64
	ticks     int64
	tcpIdx    int
	dnsIdx    int
	httpIdx   int
	secIdx    int

	onGap func(gapDuration time.Duration)
}

func NewScheduler(profile config.Profile, registry *probe.TargetRegistry, outCh chan probe.ProbeResult, version string, onGap func(time.Duration)) *Scheduler {
	return &Scheduler{
		profile:  profile,
		registry: registry,
		wake:     make(chan struct{}, 1),
		outCh:    outCh,
		inFlight: make(map[int]*atomic.Int32),
		version:  version,
		onGap:    onGap,
	}
}

// current returns the profile and registry in force.
func (s *Scheduler) current() (config.Profile, *probe.TargetRegistry) {
	s.planLock.RLock()
	defer s.planLock.RUnlock()
	return s.profile, s.registry
}

// Apply switches to a new profile without a restart. reg is the registry to
// plan from; pass the same registry after Reconfigure to keep ids stable.
// The next tick runs at once on the new plan, with every layer due, and
// the timing grid restarts. Probes already in flight finish under the old
// timeouts.
func (s *Scheduler) Apply(profile config.Profile, reg *probe.TargetRegistry) {
	s.planLock.Lock()
	s.profile = profile
	s.registry = reg
	s.applied++
	s.planLock.Unlock()

	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *Scheduler) SetFastMode(fast bool) {
	s.fastMode.Store(fast)
}

func (s *Scheduler) IsFastMode() bool {
	return s.fastMode.Load()
}

func (s *Scheduler) Pause() {
	s.paused.Store(true)
}

func (s *Scheduler) Resume() {
	s.paused.Store(false)
}

func (s *Scheduler) IsPaused() bool {
	return s.paused.Load()
}

func (s *Scheduler) getInFlightCounter(targetID int) *atomic.Int32 {
	s.flightLock.Lock()
	defer s.flightLock.Unlock()
	ctr, ok := s.inFlight[targetID]
	if !ok {
		ctr = &atomic.Int32{}
		s.inFlight[targetID] = ctr
	}
	return ctr
}

// gapSlack is how much later than expected a tick can run before we treat
// the delay as the machine having slept.
const gapSlack = 3 * time.Second

// pacer keeps ticks on a fixed grid so probes don't drift, and spots
// wall-clock gaps such as a suspend. The grid restarts whenever the interval
// changes or monitoring resumes from a pause.
//
// The pacer works on a clock reading (time since boot) rather than wall time,
// so a post-boot NTP step on a board without an RTC is not mistaken for a
// suspend. The reading must keep counting through a suspend, or real gaps
// would go unnoticed.
type pacer struct {
	start    time.Duration
	lastTick time.Duration
	tick     int64
	interval time.Duration
	synced   bool
}

// reset makes the next step start a fresh grid without reporting a gap.
func (p *pacer) reset() {
	p.synced = false
}

// step is called once per tick. It returns how long to wait before the next
// tick and, if this tick came much later than expected, how long the gap was.
func (p *pacer) step(now, interval time.Duration) (wait, gap time.Duration) {
	if p.synced {
		expected := max(interval, p.interval)
		if d := now - p.lastTick; d > expected+gapSlack {
			gap = d
			p.synced = false
		} else if interval != p.interval {
			p.synced = false
		}
	}
	if !p.synced {
		p.start = now
		p.tick = 0
		p.interval = interval
		p.synced = true
	}
	p.lastTick = now

	p.tick++
	next := p.start + time.Duration(p.tick)*interval
	if now-next > interval {
		// We fell behind; skip the ticks we missed instead of bursting.
		p.tick = int64((now-p.start)/interval) + 1
		next = p.start + time.Duration(p.tick)*interval
	}
	return next - now, gap
}

func (s *Scheduler) Run(ctx context.Context) error {
	var p pacer

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		if s.paused.Load() {
			// Time spent paused is not a gap.
			p.reset()
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(200 * time.Millisecond):
				continue
			}
		}

		// A new plan starts on a fresh grid, and is not a gap.
		if s.noteApply() {
			p.reset()
		}

		prof, _ := s.current()
		isFast := s.fastMode.Load()
		intervalMS := prof.Intervals.NormalMS
		if isFast {
			intervalMS = prof.Intervals.FastMS
		}
		interval := time.Duration(intervalMS) * time.Millisecond

		wait, gap := p.step(platform.BootElapsed(), interval)
		if gap > 0 && s.onGap != nil {
			s.onGap(gap)
		}

		s.dispatchTick(ctx, isFast, interval)

		if wait > 0 {
			select {
			case <-ctx.Done():
				return nil
			case <-s.wake:
			case <-time.After(wait):
			}
		}
	}
}

// noteApply reports whether Apply was called since the last tick, and if so
// restarts rotation so the first tick on the new plan probes every layer.
func (s *Scheduler) noteApply() bool {
	s.planLock.RLock()
	n := s.applied
	s.planLock.RUnlock()
	if n == s.seenApply {
		return false
	}
	s.seenApply = n
	s.ticks, s.tcpIdx, s.dnsIdx, s.httpIdx, s.secIdx = 0, 0, 0, 0, 0
	return true
}

// tickPlan is what one tick will probe, per layer.
type tickPlan struct {
	icmp, dns, tcp, http []probe.Target
}

// everyN converts a period into a number of ticks (at least 1).
func everyN(periodMS int, interval time.Duration) int64 {
	n := (time.Duration(periodMS)*time.Millisecond + interval/2) / interval
	if n < 1 {
		n = 1
	}
	return int64(n)
}

// planTick decides what to probe this tick.
//
// Fast mode probes every target, so a problem is confirmed quickly. Normal
// mode keeps the gateway and the first WAN ping host on every tick (they
// catch short drops) and runs each other layer on its own, slower period,
// one rotating target at a time. A failed probe is confirmed against another
// target straight away (see run), so the slower rates don't delay detection.
func (s *Scheduler) planTick(isFast bool, interval time.Duration) tickPlan {
	tick := s.ticks
	s.ticks++
	prof, reg := s.current()
	iv := prof.Intervals
	due := func(periodMS int) bool { return tick%everyN(periodMS, interval) == 0 }

	var plan tickPlan
	wanICMP := reg.GetWANICMP()
	if gw := reg.GetGateway(); gw != nil {
		plan.icmp = append(plan.icmp, *gw)
	}

	if prof.Mode == config.ModeParallel && !isFast {
		return s.planParallel(prof, reg, due, plan, wanICMP)
	}

	if isFast {
		if isp := reg.GetISPHop(); isp != nil {
			plan.icmp = append(plan.icmp, *isp)
		}
		plan.icmp = append(plan.icmp, wanICMP...)
		plan.dns = reg.GetDNS()
		plan.tcp = reg.GetWANTCP()
		if tick%2 == 0 {
			plan.http = reg.GetHTTP()
		}
		return plan
	}

	if isp := reg.GetISPHop(); isp != nil && due(iv.ISPHopMS) {
		plan.icmp = append(plan.icmp, *isp)
	}
	if len(wanICMP) > 0 {
		plan.icmp = append(plan.icmp, wanICMP[0])
		if due(iv.WANICMPSecondaryMS) {
			plan.icmp = append(plan.icmp, pickNext(wanICMP[1:], &s.secIdx)...)
		}
	}
	if due(iv.DNSMS) {
		plan.dns = pickNext(reg.GetDNS(), &s.dnsIdx)
	}
	if due(iv.WANTCPMS) {
		plan.tcp = pickNext(reg.GetWANTCP(), &s.tcpIdx)
	}
	if due(iv.HTTPMS) {
		plan.http = pickNext(reg.GetHTTP(), &s.httpIdx)
	}
	return plan
}

// planParallel is normal mode for a parallel profile: no rotation, every host
// of a layer is probed whenever the layer is due. plan already holds the
// gateway. A failure needs no confirming probe, since the other hosts are
// probed in the same period anyway.
func (s *Scheduler) planParallel(prof config.Profile, reg *probe.TargetRegistry, due func(int) bool, plan tickPlan, wanICMP []probe.Target) tickPlan {
	iv := prof.Intervals
	if isp := reg.GetISPHop(); isp != nil && due(iv.ISPHopMS) {
		plan.icmp = append(plan.icmp, *isp)
	}
	if len(wanICMP) > 0 {
		plan.icmp = append(plan.icmp, wanICMP[0])
		if due(iv.WANICMPSecondaryMS) {
			plan.icmp = append(plan.icmp, wanICMP[1:]...)
		}
	}
	if due(iv.DNSMS) {
		plan.dns = reg.GetDNS()
	}
	if due(iv.WANTCPMS) {
		plan.tcp = reg.GetWANTCP()
	}
	if due(iv.HTTPMS) {
		plan.http = reg.GetHTTP()
	}
	return plan
}

// pickNext returns the next target in turn, or nothing for an empty list.
func pickNext(all []probe.Target, idx *int) []probe.Target {
	if len(all) == 0 {
		return nil
	}
	t := all[*idx%len(all)]
	*idx++
	return []probe.Target{t}
}

func (s *Scheduler) dispatchTick(ctx context.Context, isFast bool, interval time.Duration) {
	plan := s.planTick(isFast, interval)
	staggerStep := interval / 4

	prof, _ := s.current()
	if prof.Mode == config.ModeParallel {
		// Spread the hosts of each layer across its quarter of the tick as
		// well, so probing every host doesn't land as one burst.
		s.launchSpread(ctx, 0, staggerStep, plan.icmp, isFast)
		s.launchSpread(ctx, staggerStep, staggerStep, plan.dns, isFast)
		s.launchSpread(ctx, 2*staggerStep, staggerStep, plan.tcp, isFast)
		s.launchSpread(ctx, 3*staggerStep, staggerStep, plan.http, isFast)
		return
	}

	s.launchBatch(ctx, plan.icmp, isFast)
	s.launchAfter(ctx, staggerStep, plan.dns, isFast)
	s.launchAfter(ctx, 2*staggerStep, plan.tcp, isFast)
	s.launchAfter(ctx, 3*staggerStep, plan.http, isFast)
}

// launchSpread starts targets evenly across window, beginning at start.
func (s *Scheduler) launchSpread(ctx context.Context, start, window time.Duration, targets []probe.Target, isFast bool) {
	for i, t := range targets {
		delay := start + window*time.Duration(i)/time.Duration(len(targets))
		s.launchAfter(ctx, delay, []probe.Target{t}, isFast)
	}
}

func (s *Scheduler) launchAfter(ctx context.Context, delay time.Duration, targets []probe.Target, isFast bool) {
	if len(targets) == 0 {
		return
	}
	if delay <= 0 {
		s.launchBatch(ctx, targets, isFast)
		return
	}
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		s.launchBatch(ctx, targets, isFast)
	}()
}

func (s *Scheduler) launchBatch(ctx context.Context, targets []probe.Target, isFast bool) {
	for _, t := range targets {
		if !s.launch(ctx, t, isFast, false) {
			s.emitSkipped(t, isFast)
		}
	}
}

// launch starts a probe unless that target already has too many in flight.
func (s *Scheduler) launch(ctx context.Context, target probe.Target, isFast, confirming bool) bool {
	ctr := s.getInFlightCounter(target.ID)
	if ctr.Add(1) > 3 {
		ctr.Add(-1)
		return false
	}
	go func() {
		defer ctr.Add(-1)
		s.run(ctx, target, isFast, confirming)
	}()
	return true
}

// layerTargets returns the configured targets of a layer that can be
// confirmed against each other.
func (s *Scheduler) layerTargets(layer probe.Layer) []probe.Target {
	_, reg := s.current()
	switch layer {
	case probe.LayerWANICMP:
		return reg.GetWANICMP()
	case probe.LayerWANTCP:
		return reg.GetWANTCP()
	case probe.LayerDNS:
		return reg.GetDNS()
	case probe.LayerHTTP:
		return reg.GetHTTP()
	}
	return nil
}

// confirmTarget picks another target in the same layer to double-check a
// failure, or false when the layer has no other target.
func (s *Scheduler) confirmTarget(failed probe.Target) (probe.Target, bool) {
	all := s.layerTargets(failed.Layer)
	for i, t := range all {
		if t.ID == failed.ID && len(all) > 1 {
			return all[(i+1)%len(all)], true
		}
	}
	return probe.Target{}, false
}

func (s *Scheduler) emitSkipped(t probe.Target, isFast bool) {
	seq := s.seq.Add(1)
	flags := probe.FlagSkipped
	if isFast {
		flags |= probe.FlagFastMode
	}
	res := probe.ProbeResult{
		TargetID:    t.ID,
		Target:      t,
		Seq:         seq,
		SendTimeUTC: time.Now().UTC().UnixMilli(),
		SendMonoNS:  time.Now().UnixNano(),
		Reached:     false,
		OK:          false,
		ErrCode:     probe.ErrSkipped,
		Flags:       flags,
	}
	s.sendResult(res)
}

// icmpUnavailable reports why echo requests can't be sent here, or nil. It is
// a variable so tests can simulate a host without ICMP.
var icmpUnavailable = platform.ICMPUnavailable

// run probes one target and reports the result. In normal mode a failure
// is followed straight away by one probe of another target in the same
// layer, so one failed probe is never the only evidence; the detector waits
// for that second result before calling the layer down.
func (s *Scheduler) run(ctx context.Context, t probe.Target, isFast, confirming bool) {
	seq := s.seq.Add(1)
	prof, reg := s.current()
	var res probe.ProbeResult
	switch t.Layer {
	case probe.LayerGateway, probe.LayerISPHop, probe.LayerWANICMP:
		// Without echo requests a ping says nothing about the network, so the
		// layer stays unknown instead of being reported as failed.
		if icmpUnavailable() != nil {
			return
		}
		res = probe.ProbeICMP(t, time.Duration(prof.TimeoutsMS.ICMP)*time.Millisecond, seq)
	case probe.LayerWANTCP:
		res = probe.ProbeTCP(t, time.Duration(prof.TimeoutsMS.TCP)*time.Millisecond, seq)
	case probe.LayerDNS:
		res = probe.ProbeDNS(t, reg.GetDNSQueryName(), time.Duration(prof.TimeoutsMS.DNS)*time.Millisecond, seq)
	case probe.LayerHTTP:
		res = probe.ProbeHTTP(t, time.Duration(prof.TimeoutsMS.HTTP)*time.Millisecond, seq, s.version)
	default:
		return
	}
	if isFast {
		res.Flags |= probe.FlagFastMode
	}
	s.sendResult(res)

	if res.OK || isFast || confirming || prof.Mode == config.ModeParallel || ctx.Err() != nil {
		return
	}
	if other, ok := s.confirmTarget(t); ok {
		s.launch(ctx, other, false, true)
	}
}

func (s *Scheduler) sendResult(res probe.ProbeResult) {
	select {
	case s.outCh <- res:
	default:
		s.dropped.Add(1)
	}
}

// DroppedResults is how many probe results were thrown away because the
// processor couldn't keep up.
func (s *Scheduler) DroppedResults() int64 {
	return s.dropped.Load()
}
