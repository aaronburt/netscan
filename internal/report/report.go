// Package report builds the connection stability report: one self-contained
// HTML document of A4 sheets, with inline SVG charts and print styles, that a
// browser saves as a PDF. It reads what NetScan has recorded and states only
// that. Where the database holds no figure, as with coverage, the report says
// "Not recorded" rather than printing a number.
package report

import (
	"errors"
	"fmt"
	"time"

	"github.com/aaronburt/netscan/internal/detector"
	"github.com/aaronburt/netscan/internal/netenv"
	"github.com/aaronburt/netscan/internal/store"
)

// Period is how far back a report looks, ending now.
type Period string

const (
	Period24h Period = "24h"
	Period7d  Period = "7d"
	Period30d Period = "30d"
)

// ParsePeriod reads a period name from a request. An empty name is the default,
// seven days.
func ParsePeriod(s string) (Period, bool) {
	switch Period(s) {
	case "":
		return Period7d, true
	case Period24h, Period7d, Period30d:
		return Period(s), true
	}
	return "", false
}

// Duration is the length of the period.
func (p Period) Duration() time.Duration {
	switch p {
	case Period24h:
		return 24 * time.Hour
	case Period30d:
		return 30 * 24 * time.Hour
	}
	return 7 * 24 * time.Hour
}

// Words says the length of the period in running text.
func (p Period) Words() string {
	switch p {
	case Period24h:
		return "24 hours"
	case Period30d:
		return "30 days"
	}
	return "7 days"
}

// Source is what the report reads. *store.StoreReader is the real one.
type Source interface {
	QueryEvents(store.EventFilter) ([]detector.Event, error)
	ForEachRollup(fromMS, toMS int64, fn func(store.RollupRow)) error
	QueryProfiles(fromMS, toMS int64) ([]store.ProfileRecord, error)
	QuerySystemEvents(fromMS, toMS int64) ([]netenv.SystemEvent, error)
}

// Network describes the network NetScan is on now. Any field may be empty.
type Network struct {
	Interface string
	ID        string // the network fingerprint
	GatewayIP string
	ISPHopIP  string
	VPN       bool
}

// Options say what to report on.
type Options struct {
	Period   Period         // empty means seven days
	Now      time.Time      // the end of the period; zero means the current time
	Location *time.Location // where days start and hours fall; nil means the local zone
	Version  string
	Network  Network
}

// maxEvents caps how many events one report reads, so a runaway database
// cannot make the page take minutes to build. The report says when it hit it.
const maxEvents = 20000

// Report is everything the HTML is drawn from.
type Report struct {
	Period  Period
	Version string
	Network Network
	Loc     *time.Location

	Generated time.Time
	From, To  time.Time

	// DataFrom is when monitoring data starts: the first one-minute summary in
	// the period. It is zero when there is none. Uptime is measured from here,
	// so a period that began before NetScan was installed is not counted as up.
	DataFrom  time.Time
	Monitored time.Duration

	Outages  []Outage // every outage, oldest first
	Upstream []Outage // not local, and the router answered 90% or more
	Unclear  []Outage // not local, but the router missed replies
	Local    []Outage // right after waking, VPN, link or router
	Blips    []Blip
	Slow     []SlowSpell

	// Truncated is set when the period held more events than maxEvents.
	Truncated bool

	OfflineMS   int64
	UptimePct   float64
	Longest     *Outage
	MedianLenMS int64
	Lengths     [5]int // outages by length band, see lengthBands

	Causes   []CauseRow
	Rule     RuleCounts
	Flags    FlagCounts
	RouterOK int // outages not local where the router answered 90% or more

	Dates []time.Time // the local days the period touches, oldest first
	Tally []Tally     // time offline and counts per day (or per hour for 24h)
	Hours bool        // Tally is per hour, not per day

	Gaps     []Gap
	GapTotal time.Duration
	Sys      []SysRow
	SysMore  int // system rows left out of Sys

	Profiles []ProfileSeg
	Usage    []UsageRow

	Checks     []CheckRow
	ChecksMore int // targets left out of Checks

	Sent, Failed int64 // probes sent and not answered, ISP first hop left out
	LossPct      float64

	Latency   LatencyStats
	LatSeries []LatPoint
	LatStepMS int64
	HOD       [24]HodPoint

	Findings []string // sentences with <b> markup, safe by construction

	Log LogPlan
}

// Build reads the period from src and works out every figure the report shows.
func Build(src Source, opts Options) (*Report, error) {
	if src == nil {
		return nil, errors.New("report: no source")
	}
	period, ok := ParsePeriod(string(opts.Period))
	if !ok {
		return nil, fmt.Errorf("report: unknown period %q", opts.Period)
	}
	loc := opts.Location
	if loc == nil {
		loc = time.Local
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	// Whole milliseconds, so every figure agrees with the database.
	now = time.UnixMilli(now.UnixMilli()).In(loc)

	r := &Report{
		Period:    period,
		Version:   opts.Version,
		Network:   opts.Network,
		Loc:       loc,
		Generated: now,
		To:        now,
		From:      now.Add(-period.Duration()),
	}
	fromMS, toMS := r.From.UnixMilli(), r.To.UnixMilli()

	events, truncated, err := loadEvents(src, fromMS, toMS)
	if err != nil {
		return nil, fmt.Errorf("read events: %w", err)
	}
	r.Truncated = truncated

	profiles, err := src.QueryProfiles(fromMS, toMS)
	if err != nil {
		return nil, fmt.Errorf("read profile history: %w", err)
	}
	sys, err := src.QuerySystemEvents(fromMS, toMS)
	if err != nil {
		return nil, fmt.Errorf("read system events: %w", err)
	}

	agg := newAggregator(r)
	if err := src.ForEachRollup(fromMS, toMS, agg.add); err != nil {
		return nil, fmt.Errorf("read rollups: %w", err)
	}

	r.sortEvents(events, profiles)
	r.buildTimeline(sys, profiles)
	agg.finish(r)
	r.buildFigures()
	r.buildFindings()
	r.planLog()
	return r, nil
}

// loadEvents reads every event in the period, a page at a time, up to maxEvents.
func loadEvents(src Source, fromMS, toMS int64) ([]detector.Event, bool, error) {
	const page = 1000
	var all []detector.Event
	for offset := 0; ; offset += page {
		got, err := src.QueryEvents(store.EventFilter{FromMS: fromMS, ToMS: toMS, Limit: page, Offset: offset})
		if err != nil {
			return nil, false, err
		}
		all = append(all, got...)
		if len(got) < page {
			return all, false, nil
		}
		if len(all) >= maxEvents {
			return all[:maxEvents], true, nil
		}
	}
}
