package detector

import (
	"encoding/json"
	"math"
	"sync"
	"time"

	"github.com/aaronburt/netscan/internal/config"
	"github.com/aaronburt/netscan/internal/netenv"
	"github.com/aaronburt/netscan/internal/probe"
)

type Detector struct {
	lock           sync.Mutex
	cfg            config.Config
	clock          Clock
	latencyTracker *LatencyTracker

	state        State
	fastMode     bool
	fastHealthyS int
	outageS      int

	consecAllUP    int
	lastGoodSample map[probe.Layer]time.Time

	layerStatuses map[probe.Layer]LayerStatus
	latestResults map[int]probe.ProbeResult
	history120s   []probe.ProbeResult
	singleHist    map[int][]probe.ProbeResult

	openEvent    *Event
	openEventID  int64
	nextEventID  int64
	lastEvent    *Event
	activeLayers int

	firstFailInDegraded *probe.ProbeResult
	lastFailInDegraded  *probe.ProbeResult
	anyFailInDegraded   bool

	postResumeUntil time.Time
	isVPN           bool
	networkID       int64
	ssid            string
	gatewayIP       string
	ispHopIP        string

	onFastModeChange func(fast bool)
}

func NewDetector(cfg config.Config, clock Clock, onFastModeChange func(bool)) *Detector {
	if clock == nil {
		clock = RealClock{}
	}
	return &Detector{
		cfg:              cfg,
		clock:            clock,
		latencyTracker:   NewLatencyTracker(cfg.Latency),
		state:            StateHealthy,
		layerStatuses:    make(map[probe.Layer]LayerStatus),
		latestResults:    make(map[int]probe.ProbeResult),
		singleHist:       make(map[int][]probe.ProbeResult),
		lastGoodSample:   make(map[probe.Layer]time.Time),
		nextEventID:      1,
		onFastModeChange: onFastModeChange,
	}
}

func (d *Detector) SetNetworkContext(networkID int64, isVPN bool, gwIP, ispHop, ssid string) {
	d.lock.Lock()
	defer d.lock.Unlock()
	d.networkID = networkID
	d.isVPN = isVPN
	d.gatewayIP = gwIP
	d.ispHopIP = ispHop
	d.ssid = ssid
}

// SetNextEventID makes new events continue numbering after the ones already
// stored, so a restart doesn't overwrite earlier events that share an id.
func (d *Detector) SetNextEventID(next int64) {
	d.lock.Lock()
	defer d.lock.Unlock()
	if next > d.nextEventID {
		d.nextEventID = next
	}
}

// CloseForShutdown ends any open event as interrupted, so it isn't left
// without an end time when the app exits. It returns the closed event.
func (d *Detector) CloseForShutdown() *Event {
	d.lock.Lock()
	defer d.lock.Unlock()
	return d.closeOpenEvent(d.clock.Now(), true).Clone()
}

func (d *Detector) Reset() {
	d.lock.Lock()
	defer d.lock.Unlock()

	d.state = StateHealthy
	d.fastMode = false
	d.consecAllUP = 0
	d.openEvent = nil
	d.lastEvent = nil
	d.history120s = nil
	d.singleHist = make(map[int][]probe.ProbeResult)
	d.clearFailTracking()
	d.latencyTracker.Reset()
	if d.onFastModeChange != nil {
		d.onFastModeChange(false)
	}
}

func (d *Detector) ProcessSystemEvent(evt netenv.SystemEvent) (*Event, *Event) {
	d.lock.Lock()
	defer d.lock.Unlock()

	now := d.clock.Now()

	switch evt.Kind {
	case netenv.SysEventSuspend:
		d.state = StateSuspended
		if d.openEvent != nil {
			closed := d.closeOpenEvent(now, true)
			return nil, closed.Clone()
		}
	case netenv.SysEventResume:
		d.state = StateHealthy
		d.clearFailTracking()
		d.postResumeUntil = now.Add(time.Duration(d.cfg.PostResumeGraceS) * time.Second)
		d.history120s = nil
	case netenv.SysEventNetworkChange, netenv.SysEventGatewayChange:
		d.latencyTracker.Reset()
	}
	return nil, nil
}

func (d *Detector) ProcessProbe(res probe.ProbeResult) (probe.ProbeResult, *Event, *Event) {
	d.lock.Lock()
	defer d.lock.Unlock()

	now := d.clock.Now()

	isLatency, isSpike, rebaselined := false, false, false
	if res.Reached && res.OK {
		isLatency, isSpike, rebaselined = d.latencyTracker.Record(res.TargetID, res.RTTUS, now)
	}

	if isLatency {
		res.Flags |= probe.FlagLatency
	}
	if isSpike {
		res.Flags |= probe.FlagSpike
	}
	if now.Before(d.postResumeUntil) {
		res.Flags |= probe.FlagPostResume
	}
	if d.isVPN {
		res.Flags |= probe.FlagVPN
	}
	if d.fastMode {
		res.Flags |= probe.FlagFastMode
	}

	d.latestResults[res.TargetID] = res
	d.singleHist[res.TargetID] = append(d.singleHist[res.TargetID], res)
	if len(d.singleHist[res.TargetID]) > 3 {
		d.singleHist[res.TargetID] = d.singleHist[res.TargetID][len(d.singleHist[res.TargetID])-3:]
	}

	cutoff120s := now.Add(-120 * time.Second)
	valid120s := d.history120s[:0]
	for _, h := range d.history120s {
		if time.UnixMilli(h.SendTimeUTC).After(cutoff120s) {
			valid120s = append(valid120s, h)
		}
	}
	d.history120s = append(valid120s, res)

	if res.OK {
		d.lastGoodSample[res.Target.Layer] = now
	} else if res.Target.Layer != probe.LayerISPHop {
		if d.firstFailInDegraded == nil {
			d.firstFailInDegraded = &res
		}
		d.lastFailInDegraded = &res
		d.anyFailInDegraded = true
	}

	d.evaluateLayers(now)
	created, closed := d.transitionOnProbe(now, isLatency || rebaselined)

	return res, created.Clone(), closed.Clone()
}

func (d *Detector) Tick(now time.Time) (*Event, *Event) {
	d.lock.Lock()
	defer d.lock.Unlock()

	d.evaluateLayers(now)
	created, closed := d.transitionOnTick(now)
	return created.Clone(), closed.Clone()
}

func (d *Detector) evaluateLayers(now time.Time) {
	maxAge := 3 * time.Duration(d.cfg.Intervals.NormalMS) * time.Millisecond
	if d.fastMode {
		maxAge = 3 * time.Duration(d.cfg.Intervals.FastMS) * time.Millisecond
	}

	d.layerStatuses[probe.LayerGateway] = d.evalSingleTargetLayer(probe.GatewayTargetID, maxAge, now)
	d.layerStatuses[probe.LayerISPHop] = d.evalSingleTargetLayer(probe.ISPHopTargetID, maxAge, now)

	for _, layer := range []probe.Layer{probe.LayerWANICMP, probe.LayerWANTCP, probe.LayerDNS, probe.LayerHTTP} {
		d.layerStatuses[layer] = d.evalMultiTargetLayer(layer, maxAge, now)
	}
}

func (d *Detector) evalSingleTargetLayer(targetID int, maxAge time.Duration, now time.Time) LayerStatus {
	hist, ok := d.singleHist[targetID]
	if !ok || len(hist) == 0 {
		return LayerStatusUnknown
	}
	latest := hist[len(hist)-1]
	if now.Sub(time.UnixMilli(latest.SendTimeUTC)) > maxAge {
		return LayerStatusUnknown
	}

	if latest.OK {
		return LayerStatusUp
	}

	if len(hist) >= 2 && !hist[len(hist)-2].OK {
		return LayerStatusDown
	}

	return LayerStatusSuspect
}

// evalMultiTargetLayer looks at the latest result of every target in the
// layer, however many the config defines.
func (d *Detector) evalMultiTargetLayer(layer probe.Layer, maxAge time.Duration, now time.Time) LayerStatus {
	activeCount := 0
	failCount := 0

	for _, res := range d.latestResults {
		if res.Target.Layer != layer {
			continue
		}
		if now.Sub(time.UnixMilli(res.SendTimeUTC)) > maxAge {
			continue
		}
		activeCount++
		if !res.OK {
			failCount++
		}
	}

	if activeCount == 0 {
		return LayerStatusUnknown
	}

	if failCount > activeCount/2 {
		return LayerStatusDown
	}
	if failCount > 0 {
		return LayerStatusSuspect
	}
	return LayerStatusUp
}

func (d *Detector) isWANDown() bool {
	icmpDown := d.layerStatuses[probe.LayerWANICMP] == LayerStatusDown
	tcpDown := d.layerStatuses[probe.LayerWANTCP] == LayerStatusDown
	return icmpDown && tcpDown
}

func (d *Detector) isAnyLayerDown() bool {
	if d.layerStatuses[probe.LayerGateway] == LayerStatusDown {
		return true
	}
	if d.isWANDown() {
		return true
	}
	if d.layerStatuses[probe.LayerDNS] == LayerStatusDown {
		return true
	}
	if d.layerStatuses[probe.LayerHTTP] == LayerStatusDown {
		return true
	}
	return false
}

func (d *Detector) isAnyLayerSuspect() bool {
	for l, st := range d.layerStatuses {
		if l == probe.LayerISPHop {
			continue
		}
		if st == LayerStatusSuspect || st == LayerStatusDown {
			return true
		}
	}
	return false
}

func (d *Detector) isAllLayersUP() bool {
	for l, st := range d.layerStatuses {
		if l == probe.LayerISPHop {
			continue
		}
		if st != LayerStatusUp && st != LayerStatusUnknown {
			return false
		}
	}
	return true
}

func (d *Detector) transitionOnProbe(now time.Time, hasLatency bool) (*Event, *Event) {
	anyDown := d.isAnyLayerDown()
	anySuspect := d.isAnyLayerSuspect() || hasLatency

	switch d.state {
	case StateHealthy:
		if anyDown {
			d.switchFastMode(true)
			d.state = StateOutage
			d.consecAllUP = 0
			return d.openNewEvent(EventKindOutage, now), nil
		}
		if anySuspect {
			d.switchFastMode(true)
			d.state = StateDegraded
			d.consecAllUP = 0
			// Keep the failure that triggered this; the trackers were
			// cleared when we last became healthy.
		}
	case StateDegraded:
		if anyDown {
			d.state = StateOutage
			d.consecAllUP = 0
			return d.openNewEvent(EventKindOutage, now), nil
		}
	case StateOutage:
		d.updateActiveLayersBitmask()
		if !anyDown {
			d.state = StateRecovering
			d.consecAllUP = 0
		}
	case StateRecovering:
		d.updateActiveLayersBitmask()
		if anyDown {
			d.state = StateOutage
			d.consecAllUP = 0
		}
	case StateSuspended:
		if anyDown {
			d.switchFastMode(true)
			d.state = StateOutage
			d.consecAllUP = 0
			return d.openNewEvent(EventKindOutage, now), nil
		}
	}
	return nil, nil
}

func (d *Detector) transitionOnTick(now time.Time) (*Event, *Event) {
	allUP := d.isAllLayersUP()
	anyDown := d.isAnyLayerDown()

	if allUP {
		d.consecAllUP++
	} else {
		d.consecAllUP = 0
	}

	switch d.state {
	case StateDegraded:
		if anyDown {
			d.state = StateOutage
			d.consecAllUP = 0
			return d.openNewEvent(EventKindOutage, now), nil
		}
		if d.consecAllUP >= 3 {
			d.state = StateHealthy
			d.switchFastMode(false)
			var created *Event
			if d.anyFailInDegraded {
				created = d.createBlipEvent(now)
			}
			d.clearFailTracking()
			return created, nil
		}
	case StateOutage:
		d.updateActiveLayersBitmask()
		if !anyDown {
			d.state = StateRecovering
			d.consecAllUP = 0
		}
	case StateRecovering:
		d.updateActiveLayersBitmask()
		if anyDown {
			d.state = StateOutage
			d.consecAllUP = 0
		} else if d.consecAllUP >= 3 {
			d.state = StateHealthy
			d.switchFastMode(false)
			closed := d.closeOpenEvent(now, false)
			d.clearFailTracking()
			return nil, closed
		}
	case StateSuspended:
		if anyDown {
			d.switchFastMode(true)
			d.state = StateOutage
			d.consecAllUP = 0
			return d.openNewEvent(EventKindOutage, now), nil
		} else if d.consecAllUP >= 3 {
			d.state = StateHealthy
			d.switchFastMode(false)
			d.clearFailTracking()
		}
	}

	return nil, nil
}

// clearFailTracking forgets failures from the last episode so the next one
// starts fresh.
func (d *Detector) clearFailTracking() {
	d.firstFailInDegraded = nil
	d.lastFailInDegraded = nil
	d.anyFailInDegraded = false
}

func (d *Detector) switchFastMode(fast bool) {
	if d.fastMode != fast {
		d.fastMode = fast
		if d.onFastModeChange != nil {
			d.onFastModeChange(fast)
		}
	}
}

func (d *Detector) updateActiveLayersBitmask() {
	if d.layerStatuses[probe.LayerGateway] == LayerStatusDown {
		d.activeLayers |= LayerMaskGateway
	}
	if d.layerStatuses[probe.LayerISPHop] == LayerStatusDown {
		d.activeLayers |= LayerMaskISPEdge
	}
	if d.layerStatuses[probe.LayerWANICMP] == LayerStatusDown {
		d.activeLayers |= LayerMaskWANICMP
	}
	if d.layerStatuses[probe.LayerWANTCP] == LayerStatusDown {
		d.activeLayers |= LayerMaskWANTCP
	}
	if d.layerStatuses[probe.LayerDNS] == LayerStatusDown {
		d.activeLayers |= LayerMaskDNS
	}
	if d.layerStatuses[probe.LayerHTTP] == LayerStatusDown {
		d.activeLayers |= LayerMaskHTTP
	}
}

func (d *Detector) classify() Classification {
	if (d.activeLayers & LayerMaskLink) != 0 {
		return ClassLinkDown
	}
	if (d.activeLayers & LayerMaskGateway) != 0 {
		return ClassGateway
	}
	if (d.activeLayers&LayerMaskWANICMP) != 0 && (d.activeLayers&LayerMaskWANTCP) != 0 {
		if (d.activeLayers & LayerMaskISPEdge) != 0 {
			return ClassISPEdge
		}
		return ClassWAN
	}
	if (d.activeLayers&LayerMaskWANICMP) != 0 && (d.activeLayers&LayerMaskWANTCP) == 0 {
		return ClassICMPFiltered
	}
	if (d.activeLayers & LayerMaskDNS) != 0 {
		return ClassDNSAll
	}
	if (d.activeLayers & LayerMaskHTTP) != 0 {
		return ClassHTTP
	}
	return ClassWAN
}

func (d *Detector) openNewEvent(kind EventKind, now time.Time) *Event {
	id := d.nextEventID
	d.nextEventID++
	d.activeLayers = 0
	d.updateActiveLayersBitmask()

	startMS := now.UnixMilli()
	startUncertMS := int64(1000)

	if d.firstFailInDegraded != nil {
		startMS = d.firstFailInDegraded.SendTimeUTC
		goodTime, ok := d.lastGoodSample[d.firstFailInDegraded.Target.Layer]
		if ok && !goodTime.IsZero() {
			diff := startMS - goodTime.UnixMilli()
			if diff > 0 {
				startUncertMS = diff
			}
		}
	}

	flags := 0
	if now.Before(d.postResumeUntil) {
		flags |= EventFlagPostResume
	}
	if d.isVPN {
		flags |= EventFlagVPN
	}

	ctxMap := map[string]string{
		"gateway": d.gatewayIP,
		"isp_hop": d.ispHopIP,
		"ssid":    d.ssid,
	}
	ctxBytes, _ := json.Marshal(ctxMap)

	evt := &Event{
		ID:             id,
		Kind:           kind,
		Classification: d.classify(),
		NetworkID:      d.networkID,
		StartMS:        startMS,
		StartUncertMS:  startUncertMS,
		LayersDown:     d.activeLayers,
		Flags:          flags,
		ContextJSON:    string(ctxBytes),
	}

	d.openEvent = evt
	d.openEventID = id
	return evt
}

func (d *Detector) closeOpenEvent(now time.Time, interrupted bool) *Event {
	if d.openEvent == nil {
		return nil
	}

	evt := d.openEvent
	d.openEvent = nil

	endMS := now.UnixMilli()
	endUncertMS := int64(500)
	if d.lastFailInDegraded != nil {
		diff := endMS - d.lastFailInDegraded.SendTimeUTC
		if diff > 0 {
			endUncertMS = diff
		}
	}

	durationMS := endMS - evt.StartMS
	if durationMS < 0 {
		durationMS = 0
	}

	evt.EndMS = &endMS
	evt.EndUncertMS = &endUncertMS
	evt.DurationMS = &durationMS
	evt.Classification = d.classify()
	evt.LayersDown = d.activeLayers

	if interrupted {
		evt.Flags |= EventFlagInterrupted
	}

	d.computeEventReachability(evt)
	d.lastEvent = evt
	return evt
}

func (d *Detector) computeEventReachability(evt *Event) {
	gwTotal, gwOK := 0, 0
	ispTotal, ispOK := 0, 0

	for _, h := range d.history120s {
		if h.SendTimeUTC >= evt.StartMS && (evt.EndMS == nil || h.SendTimeUTC <= *evt.EndMS) {
			if h.Target.Layer == probe.LayerGateway {
				gwTotal++
				if h.OK {
					gwOK++
				}
			}
			if h.Target.Layer == probe.LayerISPHop {
				ispTotal++
				if h.OK {
					ispOK++
				}
			}
		}
	}

	if gwTotal > 0 {
		evt.GatewayOKPct = math.Round((float64(gwOK)/float64(gwTotal))*1000) / 10
	} else {
		evt.GatewayOKPct = 100.0
	}

	if ispTotal > 0 {
		evt.ISPHopOKPct = math.Round((float64(ispOK)/float64(ispTotal))*1000) / 10
	}
}

func (d *Detector) createBlipEvent(now time.Time) *Event {
	id := d.nextEventID
	d.nextEventID++

	startMS := now.UnixMilli()
	if d.firstFailInDegraded != nil {
		startMS = d.firstFailInDegraded.SendTimeUTC
	}
	endMS := now.UnixMilli()
	durationMS := endMS - startMS
	if durationMS < 0 {
		durationMS = 0
	}
	uncert := int64(1000)

	flags := 0
	if now.Before(d.postResumeUntil) {
		flags |= EventFlagPostResume
	}
	if d.isVPN {
		flags |= EventFlagVPN
	}

	evt := &Event{
		ID:             id,
		Kind:           EventKindBlip,
		Classification: ClassWAN,
		NetworkID:      d.networkID,
		StartMS:        startMS,
		StartUncertMS:  uncert,
		EndMS:          &endMS,
		EndUncertMS:    &uncert,
		DurationMS:     &durationMS,
		LayersDown:     0,
		Flags:          flags,
		GatewayOKPct:   100.0,
	}
	d.lastEvent = evt
	return evt
}

func (d *Detector) GetSnapshot() Snapshot {
	d.lock.Lock()
	defer d.lock.Unlock()

	layerStatusesCopy := make(map[probe.Layer]LayerStatus)
	for k, v := range d.layerStatuses {
		layerStatusesCopy[k] = v
	}

	rttCopy := make(map[int]int64)
	for k, v := range d.latestResults {
		if v.OK {
			rttCopy[k] = v.RTTUS
		}
	}

	return Snapshot{
		TimestampMS:   d.clock.Now().UnixMilli(),
		State:         d.state,
		StateString:   d.state.String(),
		FastMode:      d.fastMode,
		LayerStatuses: layerStatusesCopy,
		LatestRTTUS:   rttCopy,
		// Copies, so callers can marshal them while the detector keeps
		// updating its own.
		OpenEvent: d.openEvent.Clone(),
		LastEvent: d.lastEvent.Clone(),
	}
}
