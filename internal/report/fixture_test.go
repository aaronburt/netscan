package report

import (
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"sort"
	"time"

	"github.com/aaronburt/netscan/internal/config"
	"github.com/aaronburt/netscan/internal/detector"
	"github.com/aaronburt/netscan/internal/netenv"
	"github.com/aaronburt/netscan/internal/store"
)

// testZone is an hour ahead of UTC, so a mistake that mixes the two shows up.
var testZone = time.FixedZone("UTC+01:00", 3600)

// fixtureNow is a Friday at 04:12 local time.
var fixtureNow = time.Date(2026, time.October, 30, 4, 12, 0, 0, testZone)

const (
	lTCP  = detector.LayerMaskWANTCP
	lDNS  = detector.LayerMaskDNS
	lHTTP = detector.LayerMaskHTTP
	lPing = detector.LayerMaskWANICMP
	lGW   = detector.LayerMaskGateway
	lISP  = detector.LayerMaskISPEdge
)

// fixture is an in-memory Source holding days of invented history ending at
// fixtureNow. The same seed always gives the same history.
type fixture struct {
	events   []detector.Event
	rollups  []store.RollupRow
	profiles []store.ProfileRecord
	sys      []netenv.SystemEvent
	failOn   string // name of the call that should fail
}

func (f *fixture) QueryEvents(fl store.EventFilter) ([]detector.Event, error) {
	if f.failOn == "events" {
		return nil, fmt.Errorf("events broke")
	}
	var out []detector.Event
	for _, e := range f.events {
		if (fl.FromMS > 0 && e.StartMS < fl.FromMS) || (fl.ToMS > 0 && e.StartMS > fl.ToMS) {
			continue
		}
		out = append(out, e)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].StartMS > out[j].StartMS })
	if fl.Offset >= len(out) {
		return nil, nil
	}
	out = out[fl.Offset:]
	if fl.Limit > 0 && len(out) > fl.Limit {
		out = out[:fl.Limit]
	}
	return out, nil
}

func (f *fixture) ForEachRollup(fromMS, toMS int64, fn func(store.RollupRow)) error {
	if f.failOn == "rollups" {
		return fmt.Errorf("rollups broke")
	}
	for _, r := range f.rollups {
		if r.BucketMS >= fromMS && r.BucketMS <= toMS {
			fn(r)
		}
	}
	return nil
}

func (f *fixture) QueryProfiles(fromMS, toMS int64) ([]store.ProfileRecord, error) {
	if f.failOn == "profiles" {
		return nil, fmt.Errorf("profiles broke")
	}
	var out []store.ProfileRecord
	for _, p := range f.profiles {
		if p.StartMS <= toMS && (p.EndMS == nil || *p.EndMS >= fromMS) {
			out = append(out, p)
		}
	}
	return out, nil
}

func (f *fixture) QuerySystemEvents(fromMS, toMS int64) ([]netenv.SystemEvent, error) {
	if f.failOn == "system" {
		return nil, fmt.Errorf("system broke")
	}
	var out []netenv.SystemEvent
	for _, e := range f.sys {
		if e.Timestamp >= fromMS && e.Timestamp <= toMS {
			out = append(out, e)
		}
	}
	return out, nil
}

func ptr(v int64) *int64 { return &v }

func profileJSON(p config.Profile) string {
	b, err := json.Marshal(p)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// ago is a time that many hours before fixtureNow, in milliseconds.
func ago(hours float64) int64 {
	return fixtureNow.UnixMilli() - int64(hours*float64(time.Hour/time.Millisecond))
}

// outage makes a closed outage event.
func outage(id, startMS, durMS int64, mask int, flags int, routerPct float64, profile int64) detector.Event {
	class := detector.ClassWAN
	switch {
	case mask&lGW != 0:
		class = detector.ClassGateway
	case mask&lPing != 0 && mask&lTCP == 0:
		class = detector.ClassICMPFiltered
	case mask&lPing == 0 && mask&lDNS != 0:
		class = detector.ClassDNSAll
	case mask&lPing == 0 && mask&lHTTP != 0:
		class = detector.ClassHTTP
	}
	return detector.Event{
		ID: id, Kind: detector.EventKindOutage, Classification: class,
		StartMS: startMS, StartUncertMS: 1000, EndMS: ptr(startMS + durMS), EndUncertMS: ptr(500),
		DurationMS: ptr(durMS), LayersDown: mask, Flags: flags, GatewayOKPct: routerPct, ProfileID: profile,
	}
}

// newFixture builds days of history. Everything about it is invented but is
// shaped the way the database holds it.
func newFixture(days int) *fixture {
	f := &fixture{}
	rng := rand.New(rand.NewSource(20261030))
	end := fixtureNow.UnixMilli()
	start := end - int64(days)*int64(24*time.Hour/time.Millisecond)

	// Three stretches of profile history: Standard, then Aggressive, then Standard.
	std, agg := config.Standard(), config.Aggressive()
	t1 := start + (end-start)*6/10
	t2 := start + (end-start)*8/10
	f.profiles = []store.ProfileRecord{
		{ID: 1, StartMS: start - 3_600_000, EndMS: ptr(t1), Profile: std.ID, ProfileName: std.Name, SettingsHash: "std", SettingsJSON: profileJSON(std)},
		{ID: 2, StartMS: t1, EndMS: ptr(t2), Profile: agg.ID, ProfileName: agg.Name, SettingsHash: "agg", SettingsJSON: profileJSON(agg)},
		{ID: 3, StartMS: t2, Profile: std.ID, ProfileName: std.Name, SettingsHash: "std", SettingsJSON: profileJSON(std)},
	}
	profileAt := func(ms int64) int64 {
		switch {
		case ms < t1:
			return 1
		case ms < t2:
			return 2
		}
		return 3
	}

	// Sleep: two long gaps, written the way the scheduler writes them.
	asleep := [][2]int64{
		{start + (end-start)*2/10, start + (end-start)*2/10 + int64(5.5*float64(time.Hour/time.Millisecond))},
		{start + (end-start)*7/10, start + (end-start)*7/10 + int64(6*float64(time.Hour/time.Millisecond))},
	}
	inAsleep := func(a, b int64) bool {
		for _, g := range asleep {
			if a < g[1] && b > g[0] {
				return true
			}
		}
		return false
	}
	id := int64(1000)
	for _, g := range asleep {
		gap := time.Duration(g[1]-g[0]) * time.Millisecond
		f.sys = append(f.sys,
			netenv.SystemEvent{ID: id, Timestamp: g[1], Kind: netenv.SysEventSuspend, Detail: fmt.Sprintf("scheduler gap of %v", gap)},
			netenv.SystemEvent{ID: id + 1, Timestamp: g[1], Kind: netenv.SysEventResume, Detail: fmt.Sprintf("scheduler resumed after gap of %v", gap)})
		id += 2
	}
	f.sys = append(f.sys,
		netenv.SystemEvent{ID: id, Timestamp: start + (end-start)/2, Kind: netenv.SysEventISPHopChange, Detail: "isp hop discovered at 198.51.100.1 (ttl=2)"},
		netenv.SystemEvent{ID: id + 1, Timestamp: start + (end-start)*55/100, Kind: netenv.SysEventISPHopChange, Detail: "isp hop discovered at 198.51.100.9 (ttl=2)"},
		netenv.SystemEvent{ID: id + 2, Timestamp: start + (end-start)*9/10, Kind: netenv.SysEventISPHopChange, Detail: "isp hop discovered at 198.51.100.9 (ttl=2)"},
		netenv.SystemEvent{ID: id + 3, Timestamp: start + (end-start)*3/10, Kind: netenv.SysEventGatewayChange, Detail: "gateway changed from <nil> to 192.168.1.1"})

	// Events. A few scripted ones for the story, then everyday drops.
	nextID := int64(1201)
	add := func(e detector.Event) { f.events = append(f.events, e) }
	script := []struct {
		hoursAgo float64
		dur      int64
		mask     int
		flags    int
		router   float64
	}{
		{hoursAgo: float64(days)*24*0.55 + 2, dur: 860_000, mask: lISP | lPing | lTCP | lDNS | lHTTP, router: 100},
		{hoursAgo: float64(days)*24*0.40 + 1, dur: 365_000, mask: lPing | lTCP | lDNS | lHTTP, router: 100},
		{hoursAgo: float64(days)*24*0.30 + 3, dur: 221_000, mask: lDNS | lHTTP, router: 96.7},
		{hoursAgo: float64(days)*24*0.25 + 5, dur: 48_000, mask: lGW | lPing | lTCP | lDNS | lHTTP, router: 0},
		{hoursAgo: float64(days)*24*0.15 + 2, dur: 22_000, mask: lTCP | lDNS, flags: detector.EventFlagPostResume, router: 100},
		{hoursAgo: float64(days)*24*0.12 + 4, dur: 30_000, mask: lTCP | lHTTP, flags: detector.EventFlagVPN, router: 100},
		{hoursAgo: float64(days)*24*0.08 + 6, dur: 40_000, mask: lTCP | lDNS | lPing, router: 85.0},
	}
	for _, s := range script {
		st := ago(s.hoursAgo)
		if st < start || inAsleep(st-30_000, st+s.dur+30_000) {
			continue
		}
		fl := s.flags
		e := outage(nextID, st, s.dur, s.mask, fl, s.router, profileAt(st))
		add(e)
		nextID++
	}
	// One that straddles the switch to Aggressive.
	span := outage(nextID, t1-4_000, 9_000, lPing|lTCP|lDNS, detector.EventFlagProfileChanged, 100, 1)
	add(span)
	nextID++

	want := 6 * days
	for guard := 0; guard < 5000 && want > 0; guard++ {
		st := start + int64(rng.Float64()*float64(end-start-3_600_000))
		dur := int64(2+math.Round(math.Exp(1.9+0.75*rng.NormFloat64()))) * 1000
		if rng.Float64() < 0.12 {
			dur = int64(60+rng.Float64()*90) * 1000
		}
		dur = min(dur, 170_000)
		clash := inAsleep(st-30_000, st+dur+30_000)
		for _, e := range f.events {
			if st < e.StartMS+*e.DurationMS+90_000 && st+dur > e.StartMS-90_000 {
				clash = true
			}
		}
		if clash {
			continue
		}
		var mask int
		switch r := rng.Float64(); {
		case r < 0.40:
			mask = lTCP | lDNS | lHTTP
		case r < 0.65:
			mask = lTCP | lDNS
		case r < 0.77:
			mask = lTCP | lHTTP
		case r < 0.95:
			mask = lDNS | lHTTP
		default:
			mask = lISP | lPing | lTCP | lDNS | lHTTP
		}
		if rng.Float64() < 0.92 {
			mask |= lPing
		}
		router := 100.0
		if rng.Float64() > 0.7 {
			router = []float64{93.3, 95.0, 96.7, 97.5, 98.6}[rng.Intn(5)]
		}
		e := outage(nextID, st, dur, mask, 0, router, profileAt(st))
		e.StartUncertMS = []int64{500, 1000}[rng.Intn(2)]
		add(e)
		nextID++
		want--
	}

	// Brief failures: one check each, now and then a pair apart.
	blipMasks := []int{lPing, lTCP, lPing, lDNS, lPing, lHTTP, lGW, lTCP | lDNS}
	for i := 0; i < 3*days; i++ {
		st := start + int64(rng.Float64()*float64(end-start))
		if inAsleep(st-5_000, st+5_000) {
			continue
		}
		add(detector.Event{ID: nextID, Kind: detector.EventKindBlip, Classification: detector.ClassWAN, StartMS: st,
			StartUncertMS: 1000, EndMS: ptr(st + 1500), DurationMS: ptr(1500), LayersDown: blipMasks[i%len(blipMasks)],
			GatewayOKPct: 100, ProfileID: profileAt(st)})
		nextID++
	}
	// Slow spells.
	for i := 0; i < days; i++ {
		st := ago(float64(i)*24 + 7.5)
		class := detector.ClassLatencyWAN
		if i%4 == 3 {
			class = detector.ClassLatencyLocal
		}
		if st < start || inAsleep(st, st+300_000) {
			continue
		}
		add(detector.Event{ID: nextID, Kind: detector.EventKindLatency, Classification: class, StartMS: st,
			StartUncertMS: 1000, EndMS: ptr(st + 240_000), DurationMS: ptr(240_000), GatewayOKPct: 100, ProfileID: profileAt(st)})
		nextID++
	}

	// One-minute summaries for eight targets.
	type tgt struct {
		id      int
		layer   string
		address string
		label   string
		base    float64 // median microseconds
		sentMin int     // probes per minute
	}
	targets := []tgt{
		{1, "gateway", "192.168.1.1", "Gateway (192.168.1.1)", 1100, 60},
		{2, "isp_hop", "198.51.100.9", "ISP Hop (198.51.100.9)", 8100, 30},
		{10, "wan_icmp", "1.1.1.1", "WAN ICMP (1.1.1.1)", 13200, 60},
		{11, "wan_icmp", "8.8.8.8", "WAN ICMP (8.8.8.8)", 14000, 60},
		{20, "wan_tcp", "1.1.1.1:443", "WAN TCP (1.1.1.1:443)", 14100, 4},
		{30, "dns", "1.1.1.1", "DNS (1.1.1.1)", 15500, 4},
		{40, "dns", "192.168.1.1", "System DNS (192.168.1.1)", 4800, 4},
		{50, "http", "https://www.google.com/generate_204", "HTTP (https://www.google.com/gen...)", 78000, 2},
	}
	diurnal := []float64{0.92, 0.9, 0.88, 0.87, 0.87, 0.9, 0.95, 1.0, 1.02, 1.03, 1.04, 1.05, 1.06, 1.07, 1.08, 1.1, 1.14, 1.25, 1.5, 1.75, 1.8, 1.7, 1.4, 1.1}
	var outs []detector.Event
	for _, e := range f.events {
		if e.Kind == detector.EventKindOutage {
			outs = append(outs, e)
		}
	}
	for m := start / 60000 * 60000; m <= end; m += 60000 {
		if inAsleep(m, m+60000) {
			continue
		}
		hod := time.UnixMilli(m).In(testZone).Hour()
		for _, tg := range targets {
			sent := tg.sentMin
			ok := sent
			// An outage fails the checks it names.
			for _, e := range outs {
				if m+60000 <= e.StartMS || m >= e.StartMS+*e.DurationMS {
					continue
				}
				bit := map[string]int{"gateway": lGW, "isp_hop": lISP, "wan_icmp": lPing, "wan_tcp": lTCP, "dns": lDNS, "http": lHTTP}[tg.layer]
				if e.LayersDown&bit != 0 {
					ok = 0
				}
			}
			med := tg.base * diurnal[hod] * (1 + 0.03*rng.NormFloat64())
			row := store.RollupRow{
				RollupRecord: store.RollupRecord{
					BucketMS: m, TargetID: tg.id, Layer: tg.layer, TargetLabel: tg.label,
					Sent: sent, Reached: ok, OK: ok,
				},
				Address: tg.address,
			}
			if ok > 0 {
				row.MinUS = int64(med * 0.8)
				row.P50US = int64(med)
				row.P95US = int64(med * (1.9 + 0.3*rng.Float64()))
				row.MaxUS = int64(float64(row.P95US) * (1.2 + rng.Float64()))
				row.JitterUS = int64(med * 0.25)
			}
			f.rollups = append(f.rollups, row)
		}
	}
	return f
}

func fixtureOptions(p Period) Options {
	return Options{
		Period:   p,
		Now:      fixtureNow,
		Location: testZone,
		Version:  "0.9.8",
		Network:  Network{Interface: "Ethernet", ID: "9f3a7c21b04de68a", GatewayIP: "192.168.1.1", ISPHopIP: "198.51.100.9"},
	}
}
