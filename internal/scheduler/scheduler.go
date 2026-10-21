package scheduler

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aaronburt/netscan/internal/config"
	"github.com/aaronburt/netscan/internal/probe"
)

type Scheduler struct {
	cfg        config.Config
	registry   *probe.TargetRegistry
	outCh      chan probe.ProbeResult
	fastMode   atomic.Bool
	paused     atomic.Bool
	seq        atomic.Uint64
	dropped    atomic.Int64
	inFlight   map[int]*atomic.Int32
	flightLock sync.Mutex
	version    string

	tcpIdx  int
	dnsIdx  int
	httpIdx int

	onGap func(gapDuration time.Duration)
}

func NewScheduler(cfg config.Config, registry *probe.TargetRegistry, outCh chan probe.ProbeResult, version string, onGap func(time.Duration)) *Scheduler {
	return &Scheduler{
		cfg:      cfg,
		registry: registry,
		outCh:    outCh,
		inFlight: make(map[int]*atomic.Int32),
		version:  version,
		onGap:    onGap,
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
type pacer struct {
	start    time.Time
	lastTick time.Time
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
func (p *pacer) step(now time.Time, interval time.Duration) (wait, gap time.Duration) {
	if p.synced {
		expected := max(interval, p.interval)
		if d := now.Sub(p.lastTick); d > expected+gapSlack {
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
	next := p.start.Add(time.Duration(p.tick) * interval)
	if now.Sub(next) > interval {
		// We fell behind; skip the ticks we missed instead of bursting.
		p.tick = int64(now.Sub(p.start)/interval) + 1
		next = p.start.Add(time.Duration(p.tick) * interval)
	}
	return next.Sub(now), gap
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

		isFast := s.fastMode.Load()
		intervalMS := s.cfg.Intervals.NormalMS
		if isFast {
			intervalMS = s.cfg.Intervals.FastMS
		}
		interval := time.Duration(intervalMS) * time.Millisecond

		wait, gap := p.step(time.Now(), interval)
		if gap > 0 && s.onGap != nil {
			s.onGap(gap)
		}

		s.dispatchTick(ctx, isFast, interval, p.tick)

		if wait > 0 {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(wait):
			}
		}
	}
}

func (s *Scheduler) dispatchTick(ctx context.Context, isFast bool, interval time.Duration, tickNum int64) {
	staggerStep := interval / 4

	icmpTargets := make([]probe.Target, 0)
	gw := s.registry.GetGateway()
	if gw != nil {
		icmpTargets = append(icmpTargets, *gw)
	}
	isp := s.registry.GetISPHop()
	if isp != nil {
		icmpTargets = append(icmpTargets, *isp)
	}
	icmpTargets = append(icmpTargets, s.registry.GetWANICMP()...)

	s.launchBatch(ctx, icmpTargets, s.runICMP, isFast)

	// Pick this tick's targets now, on the Run goroutine, so the round-robin
	// counters are only ever touched here.
	dnsTargets := s.pickTargets(s.registry.GetDNS(), &s.dnsIdx, isFast)
	tcpTargets := s.pickTargets(s.registry.GetWANTCP(), &s.tcpIdx, isFast)
	var httpTargets []probe.Target
	if !isFast || tickNum%2 == 0 {
		httpTargets = s.pickTargets(s.registry.GetHTTP(), &s.httpIdx, isFast)
	}

	s.launchAfter(ctx, staggerStep, dnsTargets, s.runDNS, isFast)
	s.launchAfter(ctx, 2*staggerStep, tcpTargets, s.runTCP, isFast)
	s.launchAfter(ctx, 3*staggerStep, httpTargets, s.runHTTP, isFast)
}

// pickTargets returns every target in fast mode, or the next one in turn
// otherwise.
func (s *Scheduler) pickTargets(all []probe.Target, idx *int, isFast bool) []probe.Target {
	if len(all) == 0 || isFast {
		return all
	}
	t := all[*idx%len(all)]
	*idx++
	return []probe.Target{t}
}

func (s *Scheduler) launchAfter(ctx context.Context, delay time.Duration, targets []probe.Target, fn func(context.Context, probe.Target, bool), isFast bool) {
	if len(targets) == 0 {
		return
	}
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		s.launchBatch(ctx, targets, fn, isFast)
	}()
}

func (s *Scheduler) launchBatch(ctx context.Context, targets []probe.Target, fn func(context.Context, probe.Target, bool), isFast bool) {
	for _, t := range targets {
		target := t
		ctr := s.getInFlightCounter(target.ID)
		cur := ctr.Add(1)
		if cur > 3 {
			ctr.Add(-1)
			s.emitSkipped(target, isFast)
			continue
		}

		go func() {
			defer ctr.Add(-1)
			fn(ctx, target, isFast)
		}()
	}
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

func (s *Scheduler) runICMP(_ context.Context, t probe.Target, isFast bool) {
	seq := s.seq.Add(1)
	timeout := time.Duration(s.cfg.TimeoutsMS.ICMP) * time.Millisecond
	res := probe.ProbeICMP(t, timeout, seq)
	if isFast {
		res.Flags |= probe.FlagFastMode
	}
	s.sendResult(res)
}

func (s *Scheduler) runTCP(_ context.Context, t probe.Target, isFast bool) {
	seq := s.seq.Add(1)
	timeout := time.Duration(s.cfg.TimeoutsMS.TCP) * time.Millisecond
	res := probe.ProbeTCP(t, timeout, seq)
	if isFast {
		res.Flags |= probe.FlagFastMode
	}
	s.sendResult(res)
}

func (s *Scheduler) runDNS(_ context.Context, t probe.Target, isFast bool) {
	seq := s.seq.Add(1)
	timeout := time.Duration(s.cfg.TimeoutsMS.DNS) * time.Millisecond
	queryName := s.registry.GetDNSQueryName()
	res := probe.ProbeDNS(t, queryName, timeout, seq)
	if isFast {
		res.Flags |= probe.FlagFastMode
	}
	s.sendResult(res)
}

func (s *Scheduler) runHTTP(_ context.Context, t probe.Target, isFast bool) {
	seq := s.seq.Add(1)
	timeout := time.Duration(s.cfg.TimeoutsMS.HTTP) * time.Millisecond
	res := probe.ProbeHTTP(t, timeout, seq, s.version)
	if isFast {
		res.Flags |= probe.FlagFastMode
	}
	s.sendResult(res)
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
