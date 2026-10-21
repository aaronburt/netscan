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
	snap := d.GetSnapshot()
	if got := snap.LayerStatuses[probe.LayerDNS]; got != detector.LayerStatusDown {
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
