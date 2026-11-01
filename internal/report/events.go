package report

import (
	"sort"
	"strings"

	"github.com/aaronburt/netscan/internal/config"
	"github.com/aaronburt/netscan/internal/detector"
	"github.com/aaronburt/netscan/internal/store"
)

// routerOKThreshold is how much of the router's own probing must have been
// answered for NetScan to point past the router. It is the dashboard's figure.
const routerOKThreshold = 90.0

// Cause is why an outage is labelled the way it is. The labels are the
// dashboard's, so the report and the dashboard never disagree.
type Cause int

const (
	CauseWAN Cause = iota
	CauseDNS
	CauseHTTP
	CauseLocal
	CauseWake
	CauseVPN
)

var causeStyles = [...]struct{ label, sev string }{
	CauseWAN:   {"ISP / WAN drop", "bad"},
	CauseDNS:   {"DNS timeout", "bad"},
	CauseHTTP:  {"HTTP timeout", "warn"},
	CauseLocal: {"Local Wi-Fi / gateway", "bad"},
	CauseWake:  {"Right after waking", "neutral"},
	CauseVPN:   {"While a VPN was active", "neutral"},
}

// Label is the cause as the dashboard words it.
func (c Cause) Label() string { return causeStyles[c].label }

// Severity is the pill style for the cause: bad, warn or neutral.
func (c Cause) Severity() string { return causeStyles[c].sev }

// Local says whether the cause keeps an outage out of the ISP-side figures.
func (c Cause) Local() bool { return c == CauseLocal || c == CauseWake || c == CauseVPN }

// causeOf follows the dashboard's mapClassification, with the two flags the
// dashboard does not show: an outage that began just after the PC woke, or
// while a VPN was up, says little about the ISP and is labelled as such.
func causeOf(class detector.Classification, flags int) Cause {
	if flags&detector.EventFlagPostResume != 0 {
		return CauseWake
	}
	if flags&detector.EventFlagVPN != 0 {
		return CauseVPN
	}
	c := strings.ToUpper(string(class))
	switch {
	case strings.Contains(c, "GATEWAY"), strings.Contains(c, "LINK_DOWN"):
		return CauseLocal
	case strings.Contains(c, "DNS"):
		return CauseDNS
	case strings.Contains(c, "HTTP"), strings.Contains(c, "CAPTIVE"):
		return CauseHTTP
	}
	return CauseWAN
}

// Outage is one outage as the report lists it.
type Outage struct {
	ID          int64
	StartMS     int64
	DurMS       int64
	Ongoing     bool // still open when the report was made; DurMS runs to the end of the period
	UncertMS    int64
	Mask        int
	Flags       int
	Class       detector.Classification
	Cause       Cause
	RouterPct   float64
	RouterKnown bool
	Profile     string
	ProfileRow  int64
	Spanned     bool // began under one profile and ended under another
}

// EndMS is when the outage ended, or the end of the period if it was still going.
func (o Outage) EndMS() int64 { return o.StartMS + o.DurMS }

// Failed says whether the layer bit was down in the outage.
func (o Outage) Failed(bit int) bool { return o.Mask&bit != 0 }

// Blip is a brief failure: one check failed and recovered by itself.
type Blip struct {
	ID         int64
	StartMS    int64
	Mask       int
	Flags      int
	ProfileRow int64
}

// SlowSpell is a stretch of latency well above NetScan's own baseline.
type SlowSpell struct {
	ID      int64
	StartMS int64
	DurMS   int64
	Where   string // Internet or Router
}

// lengthBands name the bands Report.Lengths counts outages in.
var lengthBands = [5]struct {
	label    string
	min, max int64 // milliseconds, max exclusive; 0 means no upper bound
}{
	{"Under 10 s", 0, 10_000},
	{"10 to 60 s", 10_000, 60_000},
	{"1 to 5 min", 60_000, 300_000},
	{"5 to 15 min", 300_000, 900_000},
	{"Over 15 min", 900_000, 0},
}

func lengthBand(ms int64) int {
	for i, b := range lengthBands {
		if ms >= b.min && (b.max == 0 || ms < b.max) {
			return i
		}
	}
	return len(lengthBands) - 1
}

// sortEvents sorts the period's events into outages, brief failures and slow
// spells, and works out the figures that come straight from the outages.
func (r *Report) sortEvents(events []detector.Event, profiles []store.ProfileRecord) {
	names := make(map[int64]string, len(profiles))
	for _, p := range profiles {
		names[p.ID] = p.ProfileName
	}
	profileName := func(id int64) string {
		if id == 0 {
			return config.Standard().Name
		}
		if n, ok := names[id]; ok {
			return n
		}
		return "Unknown"
	}
	toMS := r.To.UnixMilli()

	for _, e := range events {
		switch e.Kind {
		case detector.EventKindOutage:
			o := Outage{
				ID:          e.ID,
				StartMS:     e.StartMS,
				UncertMS:    e.StartUncertMS,
				Mask:        e.LayersDown,
				Flags:       e.Flags,
				Class:       e.Classification,
				RouterPct:   e.GatewayOKPct,
				RouterKnown: true,
				Profile:     profileName(e.ProfileID),
				ProfileRow:  e.ProfileID,
				Spanned:     e.Flags&detector.EventFlagProfileChanged != 0,
			}
			if e.DurationMS != nil {
				o.DurMS = max(*e.DurationMS, 0)
			} else {
				o.Ongoing = true
				o.RouterKnown = false
				o.DurMS = max(toMS-e.StartMS, 0)
			}
			o.Cause = causeOf(e.Classification, e.Flags)
			r.Outages = append(r.Outages, o)
		case detector.EventKindBlip:
			r.Blips = append(r.Blips, Blip{ID: e.ID, StartMS: e.StartMS, Mask: e.LayersDown, Flags: e.Flags, ProfileRow: e.ProfileID})
		case detector.EventKindLatency:
			s := SlowSpell{ID: e.ID, StartMS: e.StartMS, Where: "Internet"}
			if e.DurationMS != nil {
				s.DurMS = max(*e.DurationMS, 0)
			}
			if e.Classification == detector.ClassLatencyLocal {
				s.Where = "Router"
			}
			r.Slow = append(r.Slow, s)
		}
	}

	sort.SliceStable(r.Outages, func(i, j int) bool { return r.Outages[i].StartMS < r.Outages[j].StartMS })
	sort.SliceStable(r.Blips, func(i, j int) bool { return r.Blips[i].StartMS < r.Blips[j].StartMS })
	sort.SliceStable(r.Slow, func(i, j int) bool { return r.Slow[i].StartMS < r.Slow[j].StartMS })

	var lens []int64
	for i := range r.Outages {
		o := &r.Outages[i]
		r.OfflineMS += o.DurMS
		lens = append(lens, o.DurMS)
		r.Lengths[lengthBand(o.DurMS)]++
		if r.Longest == nil || o.DurMS > r.Longest.DurMS {
			r.Longest = o
		}
		switch {
		case o.Cause.Local():
			r.Local = append(r.Local, *o)
		case o.RouterKnown && o.RouterPct < routerOKThreshold:
			r.Unclear = append(r.Unclear, *o)
		default:
			r.Upstream = append(r.Upstream, *o)
			if o.RouterKnown {
				r.RouterOK++
			}
		}
		if o.Flags&detector.EventFlagInterrupted != 0 {
			r.Flags.Interrupted++
		}
		if o.Flags&detector.EventFlagPostResume != 0 {
			r.Flags.PostResume++
		}
		if o.Flags&detector.EventFlagVPN != 0 {
			r.Flags.VPN++
		}
		if o.Spanned {
			r.Flags.ProfileChange++
		}
	}
	if len(lens) > 0 {
		sort.Slice(lens, func(i, j int) bool { return lens[i] < lens[j] })
		r.MedianLenMS = medianInt64(lens)
	}
	r.buildCauses()
	r.buildRule()
}

func medianInt64(sorted []int64) int64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	if n%2 == 1 {
		return sorted[n/2]
	}
	return (sorted[n/2-1] + sorted[n/2]) / 2
}

// FlagCounts counts outages by the flags the detector put on them.
type FlagCounts struct {
	Interrupted   int // cut short because NetScan closed
	PostResume    int // began within the grace period after waking
	VPN           int // began while a VPN was active
	ProfileChange int // began under one profile and ended under another
}

// CauseRow is the outages that share one cause label.
type CauseRow struct {
	Cause       Cause
	Count       int
	TotalMS     int64
	LongestMS   int64
	RouterPct   float64 // average of the outages where the router's figure is known
	RouterKnown bool
}

func (r *Report) buildCauses() {
	rows := map[Cause]*CauseRow{}
	sums := map[Cause]float64{}
	known := map[Cause]int{}
	for _, o := range r.Outages {
		row := rows[o.Cause]
		if row == nil {
			row = &CauseRow{Cause: o.Cause}
			rows[o.Cause] = row
		}
		row.Count++
		row.TotalMS += o.DurMS
		row.LongestMS = max(row.LongestMS, o.DurMS)
		if o.RouterKnown {
			sums[o.Cause] += o.RouterPct
			known[o.Cause]++
		}
	}
	for _, c := range []Cause{CauseWAN, CauseDNS, CauseHTTP, CauseLocal, CauseWake, CauseVPN} {
		row := rows[c]
		if row == nil {
			continue
		}
		if known[c] > 0 {
			row.RouterKnown = true
			row.RouterPct = sums[c] / float64(known[c])
		}
		r.Causes = append(r.Causes, *row)
	}
}

// RuleRow is one line of the table that shows how an outage is decided: which
// checks failed, what that counts as, and how many times it happened.
type RuleRow struct {
	TCP, DNS, HTTP, Router bool
	Outage                 bool
	Count                  int
	Note                   string
}

// RuleCounts is the outage rule with what was recorded under each line of it.
type RuleCounts struct {
	Rows []RuleRow
}

const (
	maskVoters = detector.LayerMaskWANTCP | detector.LayerMaskDNS | detector.LayerMaskHTTP
	maskRouter = detector.LayerMaskGateway | detector.LayerMaskLink
)

func (r *Report) buildRule() {
	var single [3]int // brief failures where only TCP, DNS or HTTP failed
	var pingOnly, apart int
	var pairs [4]int // TCP+DNS, TCP+HTTP, DNS+HTTP, all three
	var router, other int

	for _, b := range r.Blips {
		switch v := b.Mask & maskVoters; v {
		case detector.LayerMaskWANTCP:
			single[0]++
		case detector.LayerMaskDNS:
			single[1]++
		case detector.LayerMaskHTTP:
			single[2]++
		case 0:
			pingOnly++
		default:
			apart++
		}
	}
	for _, o := range r.Outages {
		if o.Mask&maskRouter != 0 {
			router++
			continue
		}
		switch o.Mask & maskVoters {
		case detector.LayerMaskWANTCP | detector.LayerMaskDNS:
			pairs[0]++
		case detector.LayerMaskWANTCP | detector.LayerMaskHTTP:
			pairs[1]++
		case detector.LayerMaskDNS | detector.LayerMaskHTTP:
			pairs[2]++
		case maskVoters:
			pairs[3]++
		default:
			other++
		}
	}

	rows := []RuleRow{
		{TCP: true, Count: single[0]},
		{DNS: true, Count: single[1]},
		{HTTP: true, Count: single[2]},
		{Count: pingOnly, Note: "only ping, the router or the ISP hop failed"},
		{TCP: true, DNS: true, Outage: true, Count: pairs[0]},
		{TCP: true, HTTP: true, Outage: true, Count: pairs[1]},
		{DNS: true, HTTP: true, Outage: true, Count: pairs[2]},
		{TCP: true, DNS: true, HTTP: true, Outage: true, Count: pairs[3]},
		{Router: true, Outage: true, Count: router, Note: "router stopped answering, whatever else failed"},
	}
	if apart > 0 {
		rows = append(rows, RuleRow{Count: apart, Note: "TCP, DNS or HTTP failed, but never together"})
	}
	if other > 0 {
		rows = append(rows, RuleRow{Outage: true, Count: other, Note: "other combinations"})
	}
	r.Rule.Rows = rows
}
