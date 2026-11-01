package report

import (
	"math"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/aaronburt/netscan/internal/probe"
	"github.com/aaronburt/netscan/internal/store"
)

// maxChecks is how many targets the per-check table lists before it sums up
// the rest.
const maxChecks = 18

// minuteDist is what a one-minute summary says about the probes answered in
// that minute: how many, and four points of their round-trip times in
// microseconds.
type minuteDist struct {
	n                  uint32
	min, p50, p95, max uint32
}

func distOf(row store.RollupRow) (minuteDist, bool) {
	if row.OK <= 0 || row.P50US <= 0 {
		return minuteDist{}, false
	}
	clamp := func(v int64) uint32 {
		if v < 0 {
			return 0
		}
		if v > math.MaxUint32 {
			return math.MaxUint32
		}
		return uint32(v)
	}
	d := minuteDist{n: clamp(int64(row.OK)), min: clamp(row.MinUS), p50: clamp(row.P50US), p95: clamp(row.P95US), max: clamp(row.MaxUS)}
	// A summary should be in order; tolerate one that is not.
	d.min = min(d.min, d.p50)
	d.p95 = max(d.p95, d.p50)
	d.max = max(d.max, d.p95)
	return d, true
}

// cdf is the share of the minute's answered probes that took x microseconds or
// less, taking the four stored points to be joined by straight lines.
func (d minuteDist) cdf(x float64) float64 {
	pts := [4][2]float64{{float64(d.min), 0}, {float64(d.p50), 0.5}, {float64(d.p95), 0.95}, {float64(d.max), 1}}
	if x < pts[0][0] {
		return 0
	}
	if x >= pts[3][0] {
		return 1
	}
	for i := 1; i < len(pts); i++ {
		x0, y0, x1, y1 := pts[i-1][0], pts[i-1][1], pts[i][0], pts[i][1]
		if x < x1 {
			return y0 + (y1-y0)*(x-x0)/(x1-x0)
		}
	}
	return 1
}

// pooledQuantile estimates the q-th quantile (0 to 1) of every probe behind a
// set of one-minute summaries, in microseconds. It treats each minute as the
// distribution its stored points describe and mixes them by how many probes
// each held. The result is close to, not exactly, what the raw probes would
// give: the report says so.
func pooledQuantile(ds []minuteDist, q float64) float64 {
	var total float64
	lo, hi := math.MaxFloat64, 0.0
	for _, d := range ds {
		total += float64(d.n)
		lo = math.Min(lo, float64(d.min))
		hi = math.Max(hi, float64(d.max))
	}
	if total == 0 {
		return 0
	}
	for i := 0; i < 60 && hi-lo > 1; i++ {
		mid := (lo + hi) / 2
		var f float64
		for _, d := range ds {
			f += float64(d.n) * d.cdf(mid)
		}
		if f/total >= q {
			hi = mid
		} else {
			lo = mid
		}
	}
	return hi
}

// targetAgg is everything the period holds for one probe target.
type targetAgg struct {
	id                      int
	layer, address, label   string
	sent, reached, ok       int64
	mins                    []minuteDist
	maxUS                   uint32
	jitterSum, jitterWeight float64
}

// aggregator folds the one-minute summaries into totals as they stream past.
type aggregator struct {
	origin, step int64
	loc          *time.Location
	to           int64

	targets  map[int]*targetAgg
	first    int64
	internet [][]minuteDist // per time bucket, pings to the internet
	router   [][]minuteDist
	all      []minuteDist
	hod      [24][]minuteDist
}

func newAggregator(r *Report) *aggregator {
	span := r.To.Sub(r.From)
	step := int64(time.Hour / time.Millisecond)
	switch {
	case span <= 36*time.Hour:
		step = int64(15 * time.Minute / time.Millisecond)
	case span > 9*24*time.Hour:
		step = int64(4 * time.Hour / time.Millisecond)
	}
	r.LatStepMS = step
	origin := r.From.UnixMilli() / step * step
	n := int((r.To.UnixMilli()-origin)/step) + 1
	return &aggregator{
		origin:   origin,
		step:     step,
		loc:      r.Loc,
		to:       r.To.UnixMilli(),
		targets:  map[int]*targetAgg{},
		internet: make([][]minuteDist, n),
		router:   make([][]minuteDist, n),
	}
}

func (a *aggregator) add(row store.RollupRow) {
	if a.first == 0 || row.BucketMS < a.first {
		a.first = row.BucketMS
	}
	t := a.targets[row.TargetID]
	if t == nil {
		t = &targetAgg{id: row.TargetID, layer: row.Layer, address: row.Address, label: row.TargetLabel}
		a.targets[row.TargetID] = t
	}
	t.sent += int64(row.Sent)
	t.reached += int64(row.Reached)
	t.ok += int64(row.OK)

	d, ok := distOf(row)
	if !ok {
		return
	}
	t.mins = append(t.mins, d)
	t.maxUS = max(t.maxUS, d.max)
	if row.OK >= 2 && row.JitterUS > 0 {
		t.jitterSum += float64(row.JitterUS) * float64(d.n)
		t.jitterWeight += float64(d.n)
	}

	idx := int((row.BucketMS - a.origin) / a.step)
	if idx < 0 || idx >= len(a.internet) {
		return
	}
	switch probe.Layer(row.Layer) {
	case probe.LayerWANICMP:
		a.internet[idx] = append(a.internet[idx], d)
		a.all = append(a.all, d)
		h := time.UnixMilli(row.BucketMS).In(a.loc).Hour()
		a.hod[h] = append(a.hod[h], d)
	case probe.LayerGateway:
		a.router[idx] = append(a.router[idx], d)
	}
}

// LatencyStats is the internet round-trip time over the whole period.
type LatencyStats struct {
	Have     bool
	MedianMS float64
	P95MS    float64
}

// LatPoint is one time bucket of the round-trip chart.
type LatPoint struct {
	TMS              int64
	HaveInt, HaveRtr bool
	IntMed, IntP95   float64
	RtrMed           float64
}

// HodPoint is the internet round-trip time at one hour of the day, over every
// day of the period.
type HodPoint struct {
	Have     bool
	Med, P95 float64
}

// CheckRow is one probe target in the per-check table.
type CheckRow struct {
	Check, Target string
	Layer         probe.Layer
	Probes        int64
	OKPct         float64
	Have          bool // there are round-trip figures
	MedianMS      float64
	P95MS         float64
	MaxMS         float64
	JitterMS      float64
}

func ms(us float64) float64 { return us / 1000 }

var layerOrder = map[probe.Layer]int{
	probe.LayerGateway: 0, probe.LayerISPHop: 1, probe.LayerWANICMP: 2,
	probe.LayerWANTCP: 3, probe.LayerDNS: 4, probe.LayerHTTP: 5,
}

func (a *aggregator) finish(r *Report) {
	if a.first > 0 {
		r.DataFrom = time.UnixMilli(a.first).In(r.Loc)
	}

	if len(a.all) > 0 {
		r.Latency = LatencyStats{Have: true, MedianMS: ms(pooledQuantile(a.all, 0.5)), P95MS: ms(pooledQuantile(a.all, 0.95))}
	}

	for i := range a.internet {
		p := LatPoint{TMS: a.origin + int64(i)*a.step}
		if len(a.internet[i]) > 0 {
			p.HaveInt = true
			p.IntMed = ms(pooledQuantile(a.internet[i], 0.5))
			p.IntP95 = ms(pooledQuantile(a.internet[i], 0.95))
		}
		if len(a.router[i]) > 0 {
			p.HaveRtr = true
			p.RtrMed = ms(pooledQuantile(a.router[i], 0.5))
		}
		r.LatSeries = append(r.LatSeries, p)
	}

	for h := range a.hod {
		if len(a.hod[h]) == 0 {
			continue
		}
		r.HOD[h] = HodPoint{Have: true, Med: ms(pooledQuantile(a.hod[h], 0.5)), P95: ms(pooledQuantile(a.hod[h], 0.95))}
	}

	rows := make([]*targetAgg, 0, len(a.targets))
	for _, t := range a.targets {
		rows = append(rows, t)
		// The ISP first hop often ignores probes that expire in transit, so it
		// stays out of the headline loss figure. It is still in the table.
		if probe.Layer(t.layer) != probe.LayerISPHop {
			r.Sent += t.sent
			r.Failed += t.sent - t.ok
		}
	}
	if r.Sent > 0 {
		r.LossPct = float64(r.Failed) / float64(r.Sent) * 100
	}

	sort.Slice(rows, func(i, j int) bool {
		li, lj := layerOrder[probe.Layer(rows[i].layer)], layerOrder[probe.Layer(rows[j].layer)]
		if li != lj {
			return li < lj
		}
		if rows[i].address != rows[j].address {
			return rows[i].address < rows[j].address
		}
		return rows[i].id < rows[j].id
	})
	for i, t := range rows {
		if i >= maxChecks {
			r.ChecksMore = len(rows) - maxChecks
			break
		}
		r.Checks = append(r.Checks, t.row())
	}
}

func (t *targetAgg) row() CheckRow {
	c := CheckRow{Layer: probe.Layer(t.layer), Probes: t.sent}
	c.Check, c.Target = checkNames(t.layer, t.address, t.label)
	if t.sent > 0 {
		c.OKPct = float64(t.ok) / float64(t.sent) * 100
	}
	if len(t.mins) > 0 {
		c.Have = true
		c.MedianMS = ms(pooledQuantile(t.mins, 0.5))
		c.P95MS = ms(pooledQuantile(t.mins, 0.95))
		c.MaxMS = ms(float64(t.maxUS))
		if t.jitterWeight > 0 {
			c.JitterMS = ms(t.jitterSum / t.jitterWeight)
		}
	}
	return c
}

// checkNames words a target the way the report's table does: what kind of
// check it is, and where it points.
func checkNames(layer, address, label string) (check, target string) {
	switch probe.Layer(layer) {
	case probe.LayerGateway:
		return "Router", address
	case probe.LayerISPHop:
		return "ISP first hop", address
	case probe.LayerWANICMP:
		return "Ping", address
	case probe.LayerWANTCP:
		if host, port, err := net.SplitHostPort(address); err == nil {
			return "TCP :" + port, host
		}
		return "TCP", address
	case probe.LayerDNS:
		if strings.HasPrefix(label, "System DNS") {
			return "DNS", "System resolver " + address
		}
		return "DNS", address
	case probe.LayerHTTP:
		u := address
		if i := strings.Index(u, "://"); i >= 0 {
			u = u[i+3:]
		}
		u = strings.TrimSuffix(u, "/")
		return "HTTP", truncate(u, 38)
	}
	if layer == "" {
		return "Unknown", address
	}
	return layer, address
}
