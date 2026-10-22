package detector_test

import (
	"testing"
	"time"

	"github.com/aaronburt/netscan/internal/config"
	"github.com/aaronburt/netscan/internal/detector"
	"github.com/aaronburt/netscan/internal/netenv"
	"github.com/aaronburt/netscan/internal/probe"
)

type MockClock struct {
	curr time.Time
}

func (m *MockClock) Now() time.Time {
	return m.curr
}

func (m *MockClock) Advance(d time.Duration) {
	m.curr = m.curr.Add(d)
}

func setupDetector(clock *MockClock) (*detector.Detector, *bool) {
	cfg := config.DefaultConfig()
	cfg.Intervals.NormalMS = 1000
	cfg.Intervals.FastMS = 500

	fastMode := false
	d := detector.NewDetector(cfg, clock, func(fast bool) {
		fastMode = fast
	})
	d.SetNetworkContext(1, false, "192.168.1.1", "10.0.0.1", "HomeWiFi")
	return d, &fastMode
}

func makeProbe(targetID int, layer probe.Layer, ok bool, clock *MockClock) probe.ProbeResult {
	return probe.ProbeResult{
		TargetID:    targetID,
		Target:      probe.Target{ID: targetID, Layer: layer, Address: "target"},
		SendTimeUTC: clock.Now().UnixMilli(),
		SendMonoNS:  clock.Now().UnixNano(),
		Reached:     ok,
		OK:          ok,
		RTTUS:       15000,
	}
}

func sendTick(d *detector.Detector, clock *MockClock, wanICMPOK, wanTCPOK, gwOK bool) (*detector.Event, *detector.Event) {
	var lastCreated, lastClosed *detector.Event

	_, c, cl := d.ProcessProbe(makeProbe(1, probe.LayerGateway, gwOK, clock))
	if c != nil {
		lastCreated = c
	}
	if cl != nil {
		lastClosed = cl
	}

	for id := 10; id <= 12; id++ {
		_, c, cl := d.ProcessProbe(makeProbe(id, probe.LayerWANICMP, wanICMPOK, clock))
		if c != nil {
			lastCreated = c
		}
		if cl != nil {
			lastClosed = cl
		}
	}

	for id := 20; id <= 22; id++ {
		_, c, cl := d.ProcessProbe(makeProbe(id, probe.LayerWANTCP, wanTCPOK, clock))
		if c != nil {
			lastCreated = c
		}
		if cl != nil {
			lastClosed = cl
		}
	}

	for _, tgt := range []struct {
		id    int
		layer probe.Layer
	}{
		{30, probe.LayerDNS}, {31, probe.LayerDNS}, {32, probe.LayerDNS},
		{50, probe.LayerHTTP}, {51, probe.LayerHTTP}, {52, probe.LayerHTTP},
	} {
		_, c, cl := d.ProcessProbe(makeProbe(tgt.id, tgt.layer, wanTCPOK, clock))
		if c != nil {
			lastCreated = c
		}
		if cl != nil {
			lastClosed = cl
		}
	}

	cTick, clTick := d.Tick(clock.Now())
	if cTick != nil {
		lastCreated = cTick
	}
	if clTick != nil {
		lastClosed = clTick
	}

	return lastCreated, lastClosed
}

func Test1SecondBlip(t *testing.T) {
	clock := &MockClock{curr: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)}
	d, fastMode := setupDetector(clock)

	sendTick(d, clock, true, true, true)
	if *fastMode {
		t.Fatalf("expected healthy normal mode")
	}

	clock.Advance(1 * time.Second)
	_, _ = sendTick(d, clock, false, true, true)
	if !*fastMode {
		t.Fatalf("expected fast mode on suspect layer")
	}

	clock.Advance(500 * time.Millisecond)
	sendTick(d, clock, true, true, true)
	clock.Advance(500 * time.Millisecond)
	sendTick(d, clock, true, true, true)
	clock.Advance(500 * time.Millisecond)
	created, _ := sendTick(d, clock, true, true, true)

	if created == nil {
		t.Fatalf("expected BLIP event to be created after 1s blip")
	}
	if created.Kind != detector.EventKindBlip {
		t.Fatalf("expected event kind blip, got %s", created.Kind)
	}
	if *fastMode {
		t.Fatalf("expected fast mode to turn off after recovery")
	}
}

func TestWANOutage(t *testing.T) {
	clock := &MockClock{curr: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)}
	d, _ := setupDetector(clock)

	sendTick(d, clock, true, true, true)

	clock.Advance(1 * time.Second)
	created, _ := sendTick(d, clock, false, false, true)
	if created == nil {
		t.Fatalf("expected OUTAGE event to open on both WAN ICMP and TCP down")
	}
	if created.Kind != detector.EventKindOutage {
		t.Fatalf("expected outage kind, got %s", created.Kind)
	}

	for i := 0; i < 6; i++ {
		clock.Advance(500 * time.Millisecond)
		sendTick(d, clock, false, false, true)
	}

	clock.Advance(500 * time.Millisecond)
	sendTick(d, clock, true, true, true)
	clock.Advance(500 * time.Millisecond)
	sendTick(d, clock, true, true, true)
	clock.Advance(500 * time.Millisecond)
	_, closed := sendTick(d, clock, true, true, true)

	if closed == nil {
		t.Fatalf("expected event to close after 3 consecutive all-up ticks")
	}
	if closed.Classification != detector.ClassWAN {
		t.Fatalf("expected ClassWAN, got %s", closed.Classification)
	}
	if closed.GatewayOKPct < 99.0 {
		t.Fatalf("expected 100%% gateway ok, got %f", closed.GatewayOKPct)
	}
	if closed.DurationMS == nil || *closed.DurationMS < 3000 {
		t.Fatalf("expected duration >= 3000ms, got %v", closed.DurationMS)
	}
}

func TestICMPFilteredNoOutage(t *testing.T) {
	clock := &MockClock{curr: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)}
	d, _ := setupDetector(clock)

	sendTick(d, clock, true, true, true)

	clock.Advance(1 * time.Second)
	created, _ := sendTick(d, clock, false, true, true)
	if created != nil && created.Kind == detector.EventKindOutage {
		t.Fatalf("ICMP loss with TCP up should NOT open an outage event")
	}

	clock.Advance(500 * time.Millisecond)
	sendTick(d, clock, true, true, true)
	clock.Advance(500 * time.Millisecond)
	sendTick(d, clock, true, true, true)
	clock.Advance(500 * time.Millisecond)
	sendTick(d, clock, true, true, true)

	snap := d.GetSnapshot()
	if snap.State != detector.StateHealthy {
		t.Fatalf("expected healthy state, got %s", snap.State)
	}
}

func TestGatewayOutage(t *testing.T) {
	clock := &MockClock{curr: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)}
	d, _ := setupDetector(clock)

	sendTick(d, clock, true, true, true)

	clock.Advance(1 * time.Second)
	sendTick(d, clock, true, true, false)

	clock.Advance(500 * time.Millisecond)
	created, _ := sendTick(d, clock, true, true, false)
	if created == nil {
		t.Fatalf("expected outage to open after 2 consecutive gateway drops")
	}

	clock.Advance(500 * time.Millisecond)
	sendTick(d, clock, true, true, true)
	clock.Advance(500 * time.Millisecond)
	sendTick(d, clock, true, true, true)
	clock.Advance(500 * time.Millisecond)
	_, closed := sendTick(d, clock, true, true, true)

	if closed == nil {
		t.Fatalf("expected event to close")
	}
	if closed.Classification != detector.ClassGateway {
		t.Fatalf("expected ClassGateway, got %s", closed.Classification)
	}
}

func TestSuspendClosesEventAsInterrupted(t *testing.T) {
	clock := &MockClock{curr: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)}
	d, _ := setupDetector(clock)

	sendTick(d, clock, true, true, true)
	clock.Advance(1 * time.Second)
	sendTick(d, clock, false, false, true)

	snap := d.GetSnapshot()
	if snap.OpenEvent == nil {
		t.Fatalf("expected open event before suspend")
	}

	_, closed := d.ProcessSystemEvent(netenv.SystemEvent{
		Kind: netenv.SysEventSuspend,
	})

	if closed == nil {
		t.Fatalf("expected event to be closed on suspend")
	}
	if (closed.Flags & detector.EventFlagInterrupted) == 0 {
		t.Fatalf("expected EventFlagInterrupted to be set")
	}
}

// A single failed probe used to be dropped when the detector went from
// healthy to degraded, so a one-probe drop produced no blip event.
func TestSingleFailedProbeRecordsBlip(t *testing.T) {
	clock := &MockClock{curr: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)}
	d, _ := setupDetector(clock)
	sendTick(d, clock, true, true, true)

	clock.Advance(time.Second)
	failAt := clock.Now().UnixMilli()
	d.ProcessProbe(makeProbe(10, probe.LayerWANICMP, false, clock))
	if snap := d.GetSnapshot(); snap.State != detector.StateDegraded {
		t.Fatalf("state = %s, want degraded", snap.StateString)
	}

	var created *detector.Event
	for i := 0; i < 4 && created == nil; i++ {
		clock.Advance(500 * time.Millisecond)
		created, _ = sendTick(d, clock, true, true, true)
	}
	if created == nil || created.Kind != detector.EventKindBlip {
		t.Fatalf("expected a blip event, got %+v", created)
	}
	if created.StartMS != failAt {
		t.Fatalf("blip start = %d, want the failed probe's time %d", created.StartMS, failAt)
	}
}

// Layer status used to be computed from a fixed list of ids, so targets
// beyond the third in a layer were probed but ignored.
func TestExtraTargetsCountTowardsLayer(t *testing.T) {
	clock := &MockClock{curr: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)}
	d, _ := setupDetector(clock)

	d.ProcessProbe(makeProbe(1000, probe.LayerDNS, false, clock))
	d.ProcessProbe(makeProbe(1001, probe.LayerDNS, false, clock))
	snap := d.GetSnapshot()
	if got := snap.LayerStatuses[probe.LayerDNS]; got != detector.LayerStatusDown {
		t.Fatalf("DNS layer = %v, want down", got)
	}
}

// In normal mode only one target of a slow layer is probed at a time, so one
// failure alone is not enough to call the layer down. The scheduler follows
// it with a confirming probe of another target.
func TestSingleFailureNeedsConfirmation(t *testing.T) {
	clock := &MockClock{curr: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)}
	d, _ := setupDetector(clock)
	sendTick(d, clock, true, true, true)

	clock.Advance(time.Second)
	firstFail := clock.Now().UnixMilli()
	_, created, _ := d.ProcessProbe(makeProbe(30, probe.LayerDNS, false, clock))
	snap := d.GetSnapshot()
	if got := snap.LayerStatuses[probe.LayerDNS]; got != detector.LayerStatusSuspect {
		t.Fatalf("one failed DNS probe: layer = %v, want suspect", got)
	}
	if created != nil || snap.OpenEvent != nil {
		t.Fatal("one failed DNS probe must not open an outage")
	}

	// The confirming probe of another resolver fails as well. That takes the
	// DNS layer down, but one layer alone is not enough for an outage.
	clock.Advance(1200 * time.Millisecond)
	_, created, _ = d.ProcessProbe(makeProbe(31, probe.LayerDNS, false, clock))
	if got := d.GetSnapshot().LayerStatuses[probe.LayerDNS]; got != detector.LayerStatusDown {
		t.Fatalf("confirmed DNS failure: layer = %v, want down", got)
	}
	if created != nil {
		t.Fatalf("a single down layer must not open an outage, got %+v", created)
	}

	// A second layer going down completes the vote. The outage starts at the
	// first failed probe, not at the confirmation.
	clock.Advance(100 * time.Millisecond)
	d.ProcessProbe(makeProbe(20, probe.LayerWANTCP, false, clock))
	clock.Advance(100 * time.Millisecond)
	_, created, _ = d.ProcessProbe(makeProbe(21, probe.LayerWANTCP, false, clock))
	if created == nil || created.Kind != detector.EventKindOutage {
		t.Fatalf("two layers down should open an outage, got %+v", created)
	}
	if created.StartMS != firstFail {
		t.Fatalf("outage start = %d, want the first failure's time %d", created.StartMS, firstFail)
	}
}

func TestFailureWithPassingConfirmationIsNotAnOutage(t *testing.T) {
	clock := &MockClock{curr: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)}
	d, _ := setupDetector(clock)
	sendTick(d, clock, true, true, true)

	clock.Advance(time.Second)
	d.ProcessProbe(makeProbe(30, probe.LayerDNS, false, clock))
	clock.Advance(200 * time.Millisecond)
	_, created, _ := d.ProcessProbe(makeProbe(31, probe.LayerDNS, true, clock))
	snap := d.GetSnapshot()
	if created != nil || snap.OpenEvent != nil {
		t.Fatal("a failure confirmed OK by another resolver is not an outage")
	}
}

// A slow HTTP probe that fails by timing out is already as old as its
// timeout when it arrives. It still has to count, in normal and fast mode.
func TestHTTPTimeoutStillCounts(t *testing.T) {
	clock := &MockClock{curr: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)}
	d, _ := setupDetector(clock)
	sendTick(d, clock, true, true, true)

	sent := clock.Now()
	first := makeProbe(50, probe.LayerHTTP, false, clock)
	clock.Advance(2 * time.Second) // the probe times out
	d.ProcessProbe(first)

	second := makeProbe(51, probe.LayerHTTP, false, clock)
	clock.Advance(2 * time.Second) // so does the confirming probe
	d.ProcessProbe(second)
	if got := d.GetSnapshot().LayerStatuses[probe.LayerHTTP]; got != detector.LayerStatusDown {
		t.Fatalf("two HTTP timeouts 2s apart: layer = %v, want down (first sent at %v)", got, sent)
	}
}

// With a single configured target there's nobody to confirm against.
func TestSingleConfiguredTargetCanGoDown(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Targets.DNS = []string{"1.1.1.1:53"}
	clock := &MockClock{curr: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)}
	d := detector.NewDetector(cfg, clock, nil)

	d.ProcessProbe(makeProbe(30, probe.LayerDNS, false, clock))
	if got := d.GetSnapshot().LayerStatuses[probe.LayerDNS]; got != detector.LayerStatusDown {
		t.Fatalf("DNS layer = %v, want down", got)
	}
}

// Snapshots are marshalled on other goroutines, so they must not share the
// detector's live event.
func TestSnapshotEventsAreCopies(t *testing.T) {
	clock := &MockClock{curr: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)}
	d, _ := setupDetector(clock)
	sendTick(d, clock, true, true, true)
	for i := 0; i < 3; i++ {
		clock.Advance(500 * time.Millisecond)
		sendTick(d, clock, false, false, true)
	}
	snap := d.GetSnapshot()
	if snap.OpenEvent == nil {
		t.Fatal("expected an open outage")
	}

	for i := 0; i < 5; i++ {
		clock.Advance(500 * time.Millisecond)
		sendTick(d, clock, true, true, true)
	}
	if after := d.GetSnapshot(); after.OpenEvent != nil {
		t.Fatal("expected the outage to be closed")
	}
	if snap.OpenEvent.EndMS != nil {
		t.Fatal("closing the event changed an earlier snapshot")
	}
}

func TestSetNextEventID(t *testing.T) {
	clock := &MockClock{curr: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)}
	d, _ := setupDetector(clock)
	d.SetNextEventID(42)
	sendTick(d, clock, true, true, true)
	clock.Advance(time.Second)
	sendTick(d, clock, false, false, true)
	clock.Advance(500 * time.Millisecond)
	created, _ := sendTick(d, clock, false, false, true)
	if snap := d.GetSnapshot(); snap.OpenEvent != nil {
		created = snap.OpenEvent
	}
	if created == nil || created.ID != 42 {
		t.Fatalf("event = %+v, want id 42", created)
	}
}

func TestCloseForShutdownEndsOpenEvent(t *testing.T) {
	clock := &MockClock{curr: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)}
	d, _ := setupDetector(clock)
	if d.CloseForShutdown() != nil {
		t.Fatal("nothing open, expected nil")
	}
	sendTick(d, clock, true, true, true)
	for i := 0; i < 3; i++ {
		clock.Advance(500 * time.Millisecond)
		sendTick(d, clock, false, false, true)
	}
	evt := d.CloseForShutdown()
	if evt == nil || evt.EndMS == nil || evt.Flags&detector.EventFlagInterrupted == 0 {
		t.Fatalf("expected an interrupted, closed event, got %+v", evt)
	}
}

func TestSnapshotReportsLastProbePerLayer(t *testing.T) {
	clock := &MockClock{curr: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)}
	d, _ := setupDetector(clock)
	d.ProcessProbe(makeProbe(30, probe.LayerDNS, true, clock))
	first := clock.Now().UnixMilli()
	clock.Advance(3 * time.Second)
	d.ProcessProbe(makeProbe(1, probe.LayerGateway, true, clock))

	snap := d.GetSnapshot()
	if snap.LastProbeMS[probe.LayerDNS] != first {
		t.Fatalf("DNS last probe = %d, want %d", snap.LastProbeMS[probe.LayerDNS], first)
	}
	if snap.LastProbeMS[probe.LayerGateway] != clock.Now().UnixMilli() {
		t.Fatalf("gateway last probe = %d", snap.LastProbeMS[probe.LayerGateway])
	}
}

func TestOutageNeedsTwoOfThreeCheckTypes(t *testing.T) {
	cases := []struct {
		name       string
		failLayers map[probe.Layer]bool
		wantOutage bool
	}{
		{"icmp only", map[probe.Layer]bool{probe.LayerWANICMP: true}, false},
		{"dns only", map[probe.Layer]bool{probe.LayerDNS: true}, false},
		{"tcp only", map[probe.Layer]bool{probe.LayerWANTCP: true}, false},
		{"http only", map[probe.Layer]bool{probe.LayerHTTP: true}, false},
		{"icmp and dns", map[probe.Layer]bool{probe.LayerWANICMP: true, probe.LayerDNS: true}, false},
		{"tcp and dns", map[probe.Layer]bool{probe.LayerWANTCP: true, probe.LayerDNS: true}, true},
		{"dns and http", map[probe.Layer]bool{probe.LayerDNS: true, probe.LayerHTTP: true}, true},
		{"tcp and http", map[probe.Layer]bool{probe.LayerWANTCP: true, probe.LayerHTTP: true}, true},
	}

	targets := []struct {
		id    int
		layer probe.Layer
	}{
		{1, probe.LayerGateway},
		{10, probe.LayerWANICMP}, {11, probe.LayerWANICMP}, {12, probe.LayerWANICMP},
		{20, probe.LayerWANTCP}, {21, probe.LayerWANTCP}, {22, probe.LayerWANTCP},
		{30, probe.LayerDNS}, {31, probe.LayerDNS}, {32, probe.LayerDNS},
		{50, probe.LayerHTTP}, {51, probe.LayerHTTP}, {52, probe.LayerHTTP},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clock := &MockClock{curr: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)}
			d, _ := setupDetector(clock)

			for _, tgt := range targets {
				d.ProcessProbe(makeProbe(tgt.id, tgt.layer, true, clock))
			}
			d.Tick(clock.Now())

			clock.Advance(1 * time.Second)
			var created *detector.Event
			for _, tgt := range targets {
				_, c, _ := d.ProcessProbe(makeProbe(tgt.id, tgt.layer, !tc.failLayers[tgt.layer], clock))
				if c != nil {
					created = c
				}
			}
			if c, _ := d.Tick(clock.Now()); c != nil {
				created = c
			}

			gotOutage := created != nil && created.Kind == detector.EventKindOutage
			if gotOutage != tc.wantOutage {
				t.Fatalf("outage = %v, want %v", gotOutage, tc.wantOutage)
			}
		})
	}
}
