package report

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/aaronburt/netscan/internal/config"
	"github.com/aaronburt/netscan/internal/netenv"
	"github.com/aaronburt/netscan/internal/store"
)

// minGap is the shortest stall of the scheduler that the report calls a gap in
// monitoring. The scheduler notes anything over three seconds; a minute is long
// enough to be a sleep and not a busy moment.
const minGap = time.Minute

// maxSysRows is how many system events the report lists before it sums up.
const maxSysRows = 8

// Tally is the outage time and counts in one stretch of the period: a day, or
// an hour when the whole report is 36 hours or less.
type Tally struct {
	Start          time.Time
	Label, Sub     string
	OfflineMS      int64
	Outages, Blips int
}

// Gap is a stretch when NetScan's probing clock stopped, normally because the
// PC was asleep.
type Gap struct{ StartMS, EndMS int64 }

// SysRow is a line of the table of gaps and changes the app recorded.
type SysRow struct {
	AtMS         int64
	What, Detail string
}

// ProfileSeg is a stretch of the period under one monitoring profile.
type ProfileSeg struct {
	FromMS, ToMS int64
	ID, Name     string
	Style        int // which fill the charts use
}

// UsageRow is how much of the period one profile covered and what it found.
type UsageRow struct {
	Name        string
	SharePct    float64
	Known       bool // the share and load figures are from the profile log
	Probes      float64
	Remote      float64
	MinOutageMS int
	Outages     int
	Blips       int
	id          string
}

var gapRE = regexp.MustCompile(`gap of (\S+)`)

func dayStart(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
}

func (r *Report) buildTimeline(sys []netenv.SystemEvent, profiles []store.ProfileRecord) {
	fromMS, toMS := r.From.UnixMilli(), r.To.UnixMilli()

	for d := dayStart(r.From); d.Before(r.To); d = d.AddDate(0, 0, 1) {
		r.Dates = append(r.Dates, d)
	}

	// Bars: one per day, or one per hour for a report of 36 hours or less.
	if r.To.Sub(r.From) <= 36*time.Hour {
		r.Hours = true
		h := time.Date(r.From.Year(), r.From.Month(), r.From.Day(), r.From.Hour(), 0, 0, 0, r.Loc)
		for ; h.Before(r.To); h = h.Add(time.Hour) {
			r.Tally = append(r.Tally, Tally{Start: h, Label: h.Format("15")})
		}
	} else {
		for _, d := range r.Dates {
			r.Tally = append(r.Tally, Tally{Start: d, Label: d.Format("Mon"), Sub: d.Format("2 Jan")})
		}
	}
	tallyEnd := func(i int) int64 {
		if i+1 < len(r.Tally) {
			return r.Tally[i+1].Start.UnixMilli()
		}
		return toMS
	}
	for _, o := range r.Outages {
		for i := range r.Tally {
			a, z := max(r.Tally[i].Start.UnixMilli(), fromMS), tallyEnd(i)
			if o.EndMS() <= a || o.StartMS >= z {
				continue
			}
			r.Tally[i].OfflineMS += min(o.EndMS(), z) - max(o.StartMS, a)
			if o.StartMS >= a && o.StartMS < z {
				r.Tally[i].Outages++
			}
		}
	}
	for _, b := range r.Blips {
		for i := range r.Tally {
			if b.StartMS >= max(r.Tally[i].Start.UnixMilli(), fromMS) && b.StartMS < tallyEnd(i) {
				r.Tally[i].Blips++
				break
			}
		}
	}

	r.buildGaps(sys)
	r.buildProfiles(profiles)
}

// buildGaps turns the scheduler's sleep notes into gaps, and lists them with
// the other system events. The scheduler writes a SUSPEND and a RESUME at the
// moment it notices, with the length of the gap in the text, so the gap runs
// back from there.
func (r *Report) buildGaps(sys []netenv.SystemEvent) {
	fromMS, toMS := r.From.UnixMilli(), r.To.UnixMilli()

	for _, e := range sys {
		if e.Kind != netenv.SysEventSuspend {
			continue
		}
		m := gapRE.FindStringSubmatch(e.Detail)
		if m == nil {
			continue
		}
		d, err := time.ParseDuration(m[1])
		if err != nil || d < minGap {
			continue
		}
		g := Gap{StartMS: max(e.Timestamp-d.Milliseconds(), fromMS), EndMS: min(e.Timestamp, toMS)}
		if g.EndMS > g.StartMS {
			r.Gaps = append(r.Gaps, g)
		}
	}
	sort.Slice(r.Gaps, func(i, j int) bool { return r.Gaps[i].StartMS < r.Gaps[j].StartMS })
	merged := r.Gaps[:0]
	for _, g := range r.Gaps {
		if n := len(merged); n > 0 && g.StartMS <= merged[n-1].EndMS {
			merged[n-1].EndMS = max(merged[n-1].EndMS, g.EndMS)
			continue
		}
		merged = append(merged, g)
	}
	r.Gaps = merged
	for _, g := range r.Gaps {
		r.GapTotal += time.Duration(g.EndMS-g.StartMS) * time.Millisecond
	}

	var rows []SysRow
	for _, g := range r.Gaps {
		back := time.UnixMilli(g.EndMS).In(r.Loc)
		rows = append(rows, SysRow{
			AtMS:   g.StartMS,
			What:   "Monitoring gap",
			Detail: fmt.Sprintf("%s, back at %s", fmtDur(g.EndMS-g.StartMS), back.Format("15:04")),
		})
	}
	lastHop := ""
	for _, e := range sys {
		switch e.Kind {
		case netenv.SysEventSuspend, netenv.SysEventResume:
			// Already shown as a gap, or too short to be one.
		case netenv.SysEventGatewayChange:
			rows = append(rows, SysRow{AtMS: e.Timestamp, What: "Router changed", Detail: gatewayChange(e.Detail)})
		case netenv.SysEventISPHopChange:
			addr := hopAddress(e.Detail)
			if addr == "" || addr == lastHop {
				continue
			}
			what := "ISP hop changed"
			detail := "now " + addr
			if lastHop == "" {
				what, detail = "ISP first hop", "found at "+addr
			}
			lastHop = addr
			rows = append(rows, SysRow{AtMS: e.Timestamp, What: what, Detail: detail})
		default:
			rows = append(rows, SysRow{AtMS: e.Timestamp, What: kindWords(string(e.Kind)), Detail: truncate(e.Detail, 60)})
		}
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].AtMS < rows[j].AtMS })
	if len(rows) > maxSysRows {
		r.SysMore = len(rows) - maxSysRows
		rows = rows[:maxSysRows]
	}
	r.Sys = rows
}

var hopRE = regexp.MustCompile(`at ([0-9A-Fa-f:.]+)`)

func hopAddress(detail string) string {
	if m := hopRE.FindStringSubmatch(detail); m != nil {
		return m[1]
	}
	return ""
}

// gatewayChange turns "gateway changed from A to B" into "A to B".
func gatewayChange(detail string) string {
	s := strings.TrimPrefix(detail, "gateway changed from ")
	s = strings.ReplaceAll(s, "<nil>", "none")
	return truncate(s, 60)
}

// kindWords turns a stored kind such as DISK_PRESSURE into "Disk pressure".
func kindWords(kind string) string {
	s := strings.ToLower(strings.ReplaceAll(kind, "_", " "))
	if s == "" {
		return "Event"
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// profileStyle picks the fill the charts use for a profile. The three built-in
// profiles keep their own, so they look the same in every report.
func profileStyle(id string) int {
	switch id {
	case "standard":
		return 0
	case "aggressive":
		return 1
	case "lax":
		return 2
	}
	return 3
}

func (r *Report) buildProfiles(profiles []store.ProfileRecord) {
	fromMS, toMS := r.From.UnixMilli(), r.To.UnixMilli()

	hashOf := make(map[int64]string, len(profiles))
	for _, p := range profiles {
		hashOf[p.ID] = p.SettingsHash
		end := toMS
		if p.EndMS != nil {
			end = min(*p.EndMS, toMS)
		}
		seg := ProfileSeg{FromMS: max(p.StartMS, fromMS), ToMS: end, ID: p.Profile, Name: p.ProfileName, Style: profileStyle(p.Profile)}
		if seg.ToMS > seg.FromMS {
			r.Profiles = append(r.Profiles, seg)
		}
	}

	index := map[string]int{}
	for _, u := range store.SummarizeProfiles(profiles, fromMS, toMS) {
		index[u.SettingsHash] = len(r.Usage)
		r.Usage = append(r.Usage, UsageRow{
			Name:        u.Name,
			SharePct:    u.SharePct,
			Known:       true,
			Probes:      u.Estimate.ProbesPerSec,
			Remote:      u.Estimate.RemoteProbesPerSec,
			MinOutageMS: u.Estimate.MinDetectableOutageMS,
			id:          u.ID,
		})
	}
	// Events from before profile history have no profile and read as Standard.
	unrecorded := -1
	rowOf := func(profileRow int64) int {
		if profileRow != 0 {
			if i, ok := index[hashOf[profileRow]]; ok {
				return i
			}
			return -1
		}
		for i, u := range r.Usage {
			if u.id == config.ProfileStandard {
				return i
			}
		}
		if unrecorded < 0 {
			unrecorded = len(r.Usage)
			r.Usage = append(r.Usage, UsageRow{Name: "Standard (before profile history)"})
		}
		return unrecorded
	}
	for _, o := range r.Outages {
		if i := rowOf(o.ProfileRow); i >= 0 {
			r.Usage[i].Outages++
		}
	}
	for _, b := range r.Blips {
		if i := rowOf(b.ProfileRow); i >= 0 {
			r.Usage[i].Blips++
		}
	}
}

// ProfilesText is the profiles used and their share of the period, for the
// summary page.
func (r *Report) ProfilesText() string {
	var parts []string
	for _, u := range r.Usage {
		if u.Known {
			parts = append(parts, fmt.Sprintf("%s %d%%", u.Name, int(u.SharePct+0.5)))
		}
	}
	if len(parts) == 0 {
		return "Not recorded"
	}
	return strings.Join(parts, " · ")
}

// truncate shortens s to n characters, ending in an ellipsis when it cuts.
func truncate(s string, n int) string {
	rs := []rune(s)
	if len(rs) <= n {
		return s
	}
	return string(rs[:n-1]) + "…"
}
