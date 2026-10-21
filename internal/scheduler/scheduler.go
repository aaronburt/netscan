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

func (s *Scheduler) Run(ctx context.Context) error {
	start := time.Now()
	tickCount := int64(0)
	lastWall := start

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		if s.paused.Load() {
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

		tickCount++
		nextDeadline := start.Add(time.Duration(tickCount) * interval)
		now := time.Now()

		wallDiff := now.Sub(lastWall)
		lastWall = now
		if wallDiff > interval+3*time.Second {
			if s.onGap != nil {
				s.onGap(wallDiff)
			}
			start = now
			tickCount = 0
			nextDeadline = start.Add(interval)
		} else if now.After(nextDeadline.Add(interval)) {
			missedTicks := int64(now.Sub(start) / interval)
			tickCount = missedTicks
			nextDeadline = start.Add(time.Duration(tickCount) * interval)
		}

		s.dispatchTick(ctx, isFast, interval, tickCount)

		sleepDur := time.Until(nextDeadline)
		if sleepDur > 0 {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(sleepDur):
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

	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(staggerStep):
		}

		allDNS := s.registry.GetDNS()
		if len(allDNS) > 0 {
			if isFast {
				s.launchBatch(ctx, allDNS, s.runDNS, isFast)
			} else {
				idx := s.dnsIdx % len(allDNS)
				s.dnsIdx++
				s.launchBatch(ctx, []probe.Target{allDNS[idx]}, s.runDNS, isFast)
			}
		}
	}()

	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * staggerStep):
		}

		allTCP := s.registry.GetWANTCP()
		if len(allTCP) > 0 {
			if isFast {
				s.launchBatch(ctx, allTCP, s.runTCP, isFast)
			} else {
				idx := s.tcpIdx % len(allTCP)
				s.tcpIdx++
				s.launchBatch(ctx, []probe.Target{allTCP[idx]}, s.runTCP, isFast)
			}
		}
	}()

	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(3 * staggerStep):
		}

		allHTTP := s.registry.GetHTTP()
		if len(allHTTP) > 0 {
			if isFast {
				if tickNum%2 == 0 {
					s.launchBatch(ctx, allHTTP, s.runHTTP, isFast)
				}
			} else {
				idx := s.httpIdx % len(allHTTP)
				s.httpIdx++
				s.launchBatch(ctx, []probe.Target{allHTTP[idx]}, s.runHTTP, isFast)
			}
		}
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
	}
}
