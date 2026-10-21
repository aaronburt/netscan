package detector

import (
	"math"
	"sort"
	"sync"
	"time"

	"github.com/aaronburt/netscan/internal/config"
)

type sampleRecord struct {
	ts    time.Time
	rttMS float64
}

type targetLatencyState struct {
	history      []sampleRecord
	longHistory  []sampleRecord
	last5Samples []float64
	baseline     float64
	mad          float64
	hasBaseline  bool
	shiftStart   time.Time
}

type LatencyTracker struct {
	lock    sync.Mutex
	cfg     config.LatencyConfig
	targets map[int]*targetLatencyState
}

func NewLatencyTracker(cfg config.LatencyConfig) *LatencyTracker {
	return &LatencyTracker{
		cfg:     cfg,
		targets: make(map[int]*targetLatencyState),
	}
}

func (lt *LatencyTracker) Reset() {
	lt.lock.Lock()
	defer lt.lock.Unlock()
	lt.targets = make(map[int]*targetLatencyState)
}

func (lt *LatencyTracker) Record(targetID int, rttUS int64, now time.Time) (bool, bool, bool) {
	lt.lock.Lock()
	defer lt.lock.Unlock()

	state, ok := lt.targets[targetID]
	if !ok {
		state = &targetLatencyState{}
		lt.targets[targetID] = state
	}

	rttMS := float64(rttUS) / 1000.0

	cutoff := now.Add(-time.Duration(lt.cfg.BaselineWindowS) * time.Second)
	valid := state.history[:0]
	for _, s := range state.history {
		if s.ts.After(cutoff) {
			valid = append(valid, s)
		}
	}
	state.history = valid

	longCutoff := now.Add(-time.Duration(lt.cfg.LongWindowS) * time.Second)
	longValid := state.longHistory[:0]
	for _, s := range state.longHistory {
		if s.ts.After(longCutoff) {
			longValid = append(longValid, s)
		}
	}
	state.longHistory = append(longValid, sampleRecord{ts: now, rttMS: rttMS})

	state.last5Samples = append(state.last5Samples, rttMS)
	if len(state.last5Samples) > lt.cfg.SustainOf {
		state.last5Samples = state.last5Samples[len(state.last5Samples)-lt.cfg.SustainOf:]
	}

	if len(state.history) < lt.cfg.WarmupSamples {
		state.history = append(state.history, sampleRecord{ts: now, rttMS: rttMS})
		lt.computeStats(state)
		return false, false, false
	}

	if !state.hasBaseline {
		lt.computeStats(state)
	}

	baseline := state.baseline
	mad := state.mad

	floorVal := math.Max(lt.cfg.FloorMS, baseline*(lt.cfg.FloorPct/100.0))
	spread := math.Max(lt.cfg.MADK*mad, floorVal)
	threshold := baseline + spread

	spikeLimit := math.Max(lt.cfg.SpikeMS, lt.cfg.SpikeX*baseline)
	isSpike := rttMS > spikeLimit

	hits := 0
	for _, val := range state.last5Samples {
		if val > threshold {
			hits++
		}
	}
	isSustained := hits >= lt.cfg.SustainHits

	isLatency := isSustained || isSpike

	if !isLatency {
		state.history = append(state.history, sampleRecord{ts: now, rttMS: rttMS})
		lt.computeStats(state)
		state.shiftStart = time.Time{}
	} else {
		if state.shiftStart.IsZero() {
			state.shiftStart = now
		}
	}

	rebaselined := false
	if !state.shiftStart.IsZero() && now.Sub(state.shiftStart) >= time.Duration(lt.cfg.LongWindowS)*time.Second {
		lt.computeLongStats(state)
		state.shiftStart = time.Time{}
		rebaselined = true
	}

	return isLatency, isSpike, rebaselined
}

func (lt *LatencyTracker) computeStats(state *targetLatencyState) {
	if len(state.history) == 0 {
		return
	}
	vals := make([]float64, len(state.history))
	for i, s := range state.history {
		vals[i] = s.rttMS
	}
	sort.Float64s(vals)
	med := median(vals)
	state.baseline = med
	state.hasBaseline = true

	devs := make([]float64, len(vals))
	for i, v := range vals {
		devs[i] = math.Abs(v - med)
	}
	sort.Float64s(devs)
	state.mad = median(devs)
}

func (lt *LatencyTracker) computeLongStats(state *targetLatencyState) {
	if len(state.longHistory) == 0 {
		return
	}
	vals := make([]float64, len(state.longHistory))
	for i, s := range state.longHistory {
		vals[i] = s.rttMS
	}
	sort.Float64s(vals)
	med := median(vals)
	state.baseline = med
	state.hasBaseline = true

	devs := make([]float64, len(vals))
	for i, v := range vals {
		devs[i] = math.Abs(v - med)
	}
	sort.Float64s(devs)
	state.mad = median(devs)
}

func median(sorted []float64) float64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	if n%2 == 1 {
		return sorted[n/2]
	}
	return (sorted[n/2-1] + sorted[n/2]) / 2.0
}
