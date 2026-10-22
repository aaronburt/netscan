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

func TestSingleProviderFailureDoesNotCauseOutage(t *testing.T) {
	clock := &MockClock{curr: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)}
	d, _ := setupDetector(clock)

	targets := []struct {
		id    int
		layer probe.Layer
	}{
		{1, probe.LayerGateway},
		{10, probe.LayerWANICMP},
		{11, probe.LayerWANICMP},
		{12, probe.LayerWANICMP},
		{20, probe.LayerWANTCP},
		{21, probe.LayerWANTCP},
		{22, probe.LayerWANTCP},
		{30, probe.LayerDNS},
		{31, probe.LayerDNS},
		{32, probe.LayerDNS},
		{50, probe.LayerHTTP},
		{51, probe.LayerHTTP},
		{52, probe.LayerHTTP},
	}

	for _, tgt := range targets {
		d.ProcessProbe(makeProbe(tgt.id, tgt.layer, true, clock))
	}
	d.Tick(clock.Now())

	clock.Advance(1 * time.Second)
	var lastCreated *detector.Event
	for _, tgt := range targets {
		isCloudflare := tgt.id == 10 || tgt.id == 20 || tgt.id == 30
		ok := !isCloudflare
		_, c, _ := d.ProcessProbe(makeProbe(tgt.id, tgt.layer, ok, clock))
		if c != nil {
			lastCreated = c
		}
	}
	cTick, _ := d.Tick(clock.Now())
	if cTick != nil {
		lastCreated = cTick
	}

	if lastCreated != nil && lastCreated.Kind == detector.EventKindOutage {
		t.Fatalf("single provider failure should not trigger an outage event")
	}

	snap := d.GetSnapshot()
	if snap.State == detector.StateOutage {
		t.Fatalf("state should not be Outage when other providers are responding, got %s", snap.State)
	}
}

func TestAllUpstreamEndpointsFailCausesOutage(t *testing.T) {
	clock := &MockClock{curr: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)}
	d, _ := setupDetector(clock)

	targets := []struct {
		id    int
		layer probe.Layer
	}{
		{1, probe.LayerGateway},
		{10, probe.LayerWANICMP},
		{11, probe.LayerWANICMP},
		{12, probe.LayerWANICMP},
		{20, probe.LayerWANTCP},
		{21, probe.LayerWANTCP},
		{22, probe.LayerWANTCP},
		{30, probe.LayerDNS},
		{31, probe.LayerDNS},
		{32, probe.LayerDNS},
		{50, probe.LayerHTTP},
		{51, probe.LayerHTTP},
		{52, probe.LayerHTTP},
	}

	for _, tgt := range targets {
		d.ProcessProbe(makeProbe(tgt.id, tgt.layer, true, clock))
	}
	d.Tick(clock.Now())

	clock.Advance(1 * time.Second)
	var lastCreated *detector.Event
	for _, tgt := range targets {
		ok := tgt.layer == probe.LayerGateway
		_, c, _ := d.ProcessProbe(makeProbe(tgt.id, tgt.layer, ok, clock))
		if c != nil {
			lastCreated = c
		}
	}
	cTick, _ := d.Tick(clock.Now())
	if cTick != nil {
		lastCreated = cTick
	}

	if lastCreated == nil || lastCreated.Kind != detector.EventKindOutage {
		t.Fatalf("expected outage event when all upstream endpoints fail, got %v", lastCreated)
	}

	snap := d.GetSnapshot()
	if snap.State != detector.StateOutage {
		t.Fatalf("expected StateOutage when all upstream endpoints fail, got %s", snap.State)
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
			if tc.wantOutage && d.GetSnapshot().State != detector.StateOutage {
				t.Fatalf("expected StateOutage, got %s", d.GetSnapshot().State)
			}
		})
	}
}
