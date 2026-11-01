package report

import (
	"fmt"
	"strings"
	"time"
)

// NoData says the database holds nothing for the period.
func (r *Report) NoData() bool {
	return r.DataFrom.IsZero() && len(r.Outages) == 0 && len(r.Blips) == 0
}

// buildFigures works out the headline numbers that need the whole period.
func (r *Report) buildFigures() {
	start := r.From
	// Time before NetScan had any data is not time it measured as up.
	if !r.DataFrom.IsZero() && r.DataFrom.After(r.From.Add(time.Hour)) {
		start = r.DataFrom
	}
	r.Monitored = r.To.Sub(start)
	r.UptimePct = 100
	if ms := r.Monitored.Milliseconds(); ms > 0 {
		r.UptimePct = 100 * (1 - float64(r.OfflineMS)/float64(ms))
		r.UptimePct = max(0, min(100, r.UptimePct))
	}
}

// StartsLate says monitoring data begins well after the start of the period.
func (r *Report) StartsLate() bool {
	return !r.DataFrom.IsZero() && r.DataFrom.After(r.From.Add(time.Hour))
}

// Headline is the one sentence the summary page opens with.
func (r *Report) Headline() string {
	words := r.Period.Words()
	switch {
	case r.NoData():
		return "No monitoring data in the last " + words + "."
	case len(r.Outages) == 0:
		return "No outages in the last " + words + "."
	}
	return fmt.Sprintf("%s in %s, %s offline.", plural(len(r.Outages), "outage", "outages"), words, fmtDur(r.OfflineMS))
}

// Summary is the sentence under the headline: where the outages happened.
func (r *Report) Summary() string {
	n, a, l, u := len(r.Outages), r.RouterOK, len(r.Local), len(r.Unclear)
	switch {
	case r.NoData():
		return "NetScan recorded nothing for this period. It may not have been running."
	case n == 0:
		if len(r.Blips) == 0 {
			return "Every check kept answering, and NetScan recorded no brief failures either."
		}
		return fmt.Sprintf("Every check kept answering. %s recorded, none lasting long enough to count as an outage.",
			plural(len(r.Blips), "brief failure was", "brief failures were"))
	}

	var s []string
	switch {
	case a == n:
		s = append(s, "The router kept answering during all of them, so the breaks happened beyond your router, on the line or at the ISP.")
	case a > 0:
		s = append(s, fmt.Sprintf("The router kept answering during %d of them, so those breaks happened beyond your router, on the line or at the ISP.", a))
	default:
		s = append(s, "None of them can be placed beyond the router.")
	}
	if u > 0 {
		s = append(s, fmt.Sprintf("On %d the router also missed replies, so they may not be the ISP's.", u))
	}
	if l > 0 {
		s = append(s, fmt.Sprintf("%s local or system %s.", plural(l, "was a", "were"), pluralNoun(l, "event", "events")))
	}
	return strings.Join(s, " ")
}

// pluralNoun picks the noun form without a count in front of it.
func pluralNoun(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// OutageSub is the line under the outage count.
func (r *Report) OutageSub() string {
	s := fmt.Sprintf("%d beyond router · %d local", r.RouterOK, len(r.Local))
	if u := len(r.Unclear); u > 0 {
		s = fmt.Sprintf("%d beyond router · %d unclear · %d local", r.RouterOK, u, len(r.Local))
	}
	if ongoing := r.OngoingCount(); ongoing > 0 {
		s += " · " + plural(ongoing, "still going", "still going")
	}
	return s
}

// OngoingCount counts outages that were still open when the report was made.
func (r *Report) OngoingCount() int {
	n := 0
	for _, o := range r.Outages {
		if o.Ongoing {
			n++
		}
	}
	return n
}

// OfflinePct is the share of the monitored time spent in an outage.
func (r *Report) OfflinePct() float64 { return 100 - r.UptimePct }

// SlowCounts counts slow spells on the internet side and on the router.
func (r *Report) SlowCounts() (internet, router int) {
	for _, s := range r.Slow {
		if s.Where == "Router" {
			router++
		} else {
			internet++
		}
	}
	return
}

// at writes a time of day in the report's zone.
func (r *Report) at(ms int64) time.Time { return time.UnixMilli(ms).In(r.Loc) }

// tallyName names a day, or an hour, for the findings.
func (r *Report) tallyName(t Tally) string {
	if r.Hours {
		return t.Start.Format("15:04") + " to " + t.Start.Add(time.Hour).Format("15:04")
	}
	return t.Start.Format("Mon 2 Jan")
}

var dayParts = [4]struct{ name, from, to string }{
	{"Overnight", "00:00", "06:00"},
	{"Mornings", "06:00", "12:00"},
	{"Afternoons", "12:00", "18:00"},
	{"Evenings", "18:00", "24:00"},
}

// buildFindings writes the few sentences under "What stands out". Each one is
// there only when the data supports it, and says only what was counted.
func (r *Report) buildFindings() {
	var out []string

	for _, o := range r.Outages {
		if o.Ongoing {
			out = append(out, fmt.Sprintf("<b>An outage was still going</b> when this report was made. It began %s at %s.",
				r.at(o.StartMS).Format("Mon 2 Jan"), r.at(o.StartMS).Format("15:04")))
			break
		}
	}

	if n := len(r.Outages); n >= 2 && len(r.Tally) >= 2 {
		busiest := 0
		for i, t := range r.Tally {
			if t.Outages > r.Tally[busiest].Outages {
				busiest = i
			}
		}
		if t := r.Tally[busiest]; t.Outages >= 2 {
			s := fmt.Sprintf("<b>%s had the most outages:</b> %d, adding up to %s.", r.tallyName(t), t.Outages, fmtDur(t.OfflineMS))
			if name := r.profileChangeDuring(t); name != "" {
				s += " The monitoring profile changed to " + esc(name) + " then."
			}
			out = append(out, s)
		}
	}

	if r.Longest != nil && r.OfflineMS > 0 && len(r.Tally) >= 2 {
		worst := 0
		for i, t := range r.Tally {
			if t.OfflineMS > r.Tally[worst].OfflineMS {
				worst = i
			}
		}
		t := r.Tally[worst]
		s := fmt.Sprintf("<b>%s had the most time offline:</b> %s", r.tallyName(t), fmtDur(t.OfflineMS))
		l := r.Longest
		if st := r.at(l.StartMS); !st.Before(t.Start) && st.Before(t.Start.Add(dayOrHour(r.Hours))) && l.DurMS < t.OfflineMS {
			s += fmt.Sprintf(", of which %s was a single outage from %s.", fmtDur(l.DurMS), st.Format("15:04"))
			s += routerSentence(*l)
		} else {
			s += "."
		}
		out = append(out, s)
	}

	if !r.Hours {
		if s := r.timeOfDayFinding(); s != "" {
			out = append(out, s)
		}
	}

	if len(r.Outages) >= 4 {
		out = append(out, fmt.Sprintf("<b>Typical length:</b> half of all outages ended within %s.", fmtDur(r.MedianLenMS)))
	}

	if len(out) > 4 {
		out = out[:4]
	}
	r.Findings = out
}

func dayOrHour(hours bool) time.Duration {
	if hours {
		return time.Hour
	}
	return 25 * time.Hour
}

func routerSentence(o Outage) string {
	switch {
	case o.Cause.Local():
		return " It was a local event."
	case !o.RouterKnown:
		return ""
	case o.RouterPct >= 99.95:
		return " The router answered throughout."
	case o.RouterPct >= routerOKThreshold:
		return fmt.Sprintf(" The router answered %s of the time.", fmtPct(o.RouterPct))
	}
	return " The router missed replies too."
}

// profileChangeDuring names the profile that was switched to during a tally.
func (r *Report) profileChangeDuring(t Tally) string {
	from := t.Start.UnixMilli()
	to := t.Start.Add(dayOrHour(r.Hours)).UnixMilli()
	for i, p := range r.Profiles {
		if i > 0 && p.FromMS >= from && p.FromMS < to {
			return p.Name
		}
	}
	return ""
}

// timeOfDayFinding says when in the day the outages that were not local began,
// if most of them fall in one part of it.
func (r *Report) timeOfDayFinding() string {
	var counts [4]int
	total := 0
	for _, list := range [][]Outage{r.Upstream, r.Unclear} {
		for _, o := range list {
			counts[r.at(o.StartMS).Hour()/6]++
			total++
		}
	}
	if total < 4 {
		return ""
	}
	top := 0
	for i, c := range counts {
		if c > counts[top] {
			top = i
		}
	}
	if counts[top]*2 < total {
		return ""
	}
	p := dayParts[top]
	return fmt.Sprintf("<b>%s:</b> %d of %d outages that were not local began between %s and %s.", p.name, counts[top], total, p.from, p.to)
}
