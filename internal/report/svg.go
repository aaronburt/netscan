package report

import (
	"fmt"
	"html/template"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The charts are SVG written straight into the page. Their colours are literal,
// not CSS variables, because a sheet is printed in these colours whatever
// theme the viewer's screen is using.
const (
	colInk     = "#0F1720"
	colInk2    = "#3B4654"
	colInk3    = "#586474"
	colLine    = "#CDD3DC"
	colLine2   = "#E5E9EF"
	colTrack   = "#F6F8FA"
	colBad     = "#B42318"
	colRouter  = "#2F6FD0"
	colPing    = "#B83F86"
	colNeutral = "#5B6778"
	colHatch   = "#9AA4B2"
)

// The sequential ramp for the heatmap, lightest first.
var seqRamp = [5]string{"#E8ECF2", "#BDD1F6", "#80A7EC", "#3F72D8", "#1B3F9C"}

// Fills for the profile lanes, by ProfileSeg.Style.
var profileFills = [4]string{"#DCE2E9", "url(#hatch-profile)", "#B8C2CF", "#EEF1F5"}

const (
	fullW = 688 // width of a full-width chart; the sheet's content is 688 px wide
	halfW = 335 // width of a chart that shares a row
)

func n1(v float64) string {
	s := strconv.FormatFloat(v, 'f', 1, 64)
	if s == "-0.0" {
		return "0.0"
	}
	return s
}

func svgWrap(w, h int, label, inner string) template.HTML {
	return template.HTML(fmt.Sprintf(`<svg class="chart" viewBox="0 0 %d %d" width="%d" height="%d" role="img" aria-label="%s">%s</svg>`,
		w, h, w, h, esc(label), inner))
}

func hatchLight(id string) string {
	return fmt.Sprintf(`<pattern id="%s" width="5" height="5" patternUnits="userSpaceOnUse" patternTransform="rotate(45)"><rect width="5" height="5" fill="#fff"/><line x1="0" y1="0" x2="0" y2="5" stroke="%s" stroke-width="1.3"/></pattern>`, id, colHatch)
}

func hatchDark(id string) string {
	return fmt.Sprintf(`<pattern id="%s" width="5" height="5" patternUnits="userSpaceOnUse" patternTransform="rotate(135)"><rect width="5" height="5" fill="%s"/><line x1="0" y1="0" x2="0" y2="5" stroke="#8F9AAB" stroke-width="1.2"/></pattern>`, id, colNeutral)
}

// linePath joins the points that have a value, lifting the pen over gaps.
func linePath(have []bool, vals []float64, X func(int) float64, Y func(float64) float64) string {
	var b strings.Builder
	pen := false
	for i, v := range vals {
		if !have[i] {
			pen = false
			continue
		}
		c := "L"
		if !pen {
			c = "M"
		}
		fmt.Fprintf(&b, "%s%s %s", c, n1(X(i)), n1(Y(v)))
		pen = true
	}
	return b.String()
}

// bandPath fills between two series, one closed shape for each run of points.
func bandPath(have []bool, lo, hi []float64, X func(int) float64, Y func(float64) float64) string {
	var b strings.Builder
	n := len(lo)
	for i := 0; i < n; {
		if !have[i] {
			i++
			continue
		}
		j := i
		for j < n && have[j] {
			j++
		}
		for k := i; k < j; k++ {
			c := "L"
			if k == i {
				c = "M"
			}
			fmt.Fprintf(&b, "%s%s %s", c, n1(X(k)), n1(Y(hi[k])))
		}
		for k := j - 1; k >= i; k-- {
			fmt.Fprintf(&b, "L%s %s", n1(X(k)), n1(Y(lo[k])))
		}
		b.WriteString("Z")
		i = j
	}
	return b.String()
}

// barUp is a bar standing on a baseline with its top corners rounded.
func barUp(x, y, w, h, r float64) string {
	r = math.Min(r, math.Min(w/2, h))
	b := y + h
	return fmt.Sprintf("M%s %sV%sQ%s %s %s %sH%sQ%s %s %s %sV%sZ",
		n1(x), n1(b), n1(y+r), n1(x), n1(y), n1(x+r), n1(y), n1(x+w-r), n1(x+w), n1(y), n1(x+w), n1(y+r), n1(b))
}

// barRight is a bar running right from a baseline with its far corners rounded.
func barRight(x, y, w, h, r float64) string {
	r = math.Min(r, math.Min(h/2, w))
	return fmt.Sprintf("M%s %sH%sQ%s %s %s %sV%sQ%s %s %s %sH%sZ",
		n1(x), n1(y), n1(x+w-r), n1(x+w), n1(y), n1(x+w), n1(y+r), n1(y+h-r), n1(x+w), n1(y+h), n1(x+w-r), n1(y+h), n1(x))
}

func niceMax(v, step float64) float64 { return math.Max(step, math.Ceil(v/step)*step) }

// pickStep chooses a gridline step so a chart has about four to six lines.
func pickStep(maxV float64) float64 {
	for _, s := range []float64{1, 2, 5, 10, 20, 25, 30, 50, 100, 200, 250, 500, 1000, 2000, 5000} {
		if maxV/s <= 5 {
			return s
		}
	}
	return 10000
}

// mark is a gridline on a time axis, with the label drawn beside it.
type mark struct {
	ms    int64
	label string
}

// axisMarks picks gridlines for the time axis of a chart: every three hours for
// a day, every midnight for up to nine days, and every Monday beyond that.
func axisMarks(from, to time.Time) []mark {
	var out []mark
	switch span := to.Sub(from); {
	case span <= 36*time.Hour:
		h := time.Date(from.Year(), from.Month(), from.Day(), from.Hour(), 0, 0, 0, from.Location())
		if h.Before(from) {
			h = h.Add(time.Hour)
		}
		for ; h.Before(to); h = h.Add(time.Hour) {
			if h.Hour()%3 != 0 {
				continue
			}
			label := h.Format("15:04")
			if h.Hour() == 0 {
				label = h.Format("Mon 2 Jan")
			}
			out = append(out, mark{h.UnixMilli(), label})
		}
	case span <= 9*24*time.Hour:
		for d := dayStart(from); d.Before(to); d = d.AddDate(0, 0, 1) {
			if d.Before(from) {
				// The first day is partial. Label it from the left edge if
				// there is room to.
				if d.AddDate(0, 0, 1).Sub(from) >= 10*time.Hour {
					out = append(out, mark{from.UnixMilli(), d.Format("Mon 2 Jan")})
				}
				continue
			}
			out = append(out, mark{d.UnixMilli(), d.Format("Mon 2 Jan")})
		}
	default:
		for d := dayStart(from); d.Before(to); d = d.AddDate(0, 0, 1) {
			if d.Weekday() == time.Monday && !d.Before(from) {
				out = append(out, mark{d.UnixMilli(), d.Format("Mon 2 Jan")})
			}
		}
	}
	return out
}

// timeAxis maps times in the period to x positions.
type timeAxis struct {
	x0, x1       float64
	fromMS, toMS int64
}

func (r *Report) axis(x0, x1 float64) timeAxis {
	return timeAxis{x0: x0, x1: x1, fromMS: r.From.UnixMilli(), toMS: r.To.UnixMilli()}
}

func (a timeAxis) x(ms int64) float64 {
	return a.x0 + float64(ms-a.fromMS)/float64(a.toMS-a.fromMS)*(a.x1-a.x0)
}

// grid writes the vertical gridlines and their labels, from yTop down to yBot,
// with the labels on the baseline labelY.
func (a timeAxis) grid(r *Report, yTop, yBot, labelY float64) string {
	var b strings.Builder
	for _, m := range axisMarks(r.From, r.To) {
		x := a.x(m.ms)
		fmt.Fprintf(&b, `<line class="grid" x1="%s" x2="%s" y1="%s" y2="%s"/>`, n1(x), n1(x), n1(yTop), n1(yBot))
		// A label that would run past the right edge is left off.
		if x+4+float64(len([]rune(m.label)))*6.4 > fullW-4 {
			continue
		}
		fmt.Fprintf(&b, `<text x="%s" y="%s">%s</text>`, n1(x+4), n1(labelY), esc(m.label))
	}
	return b.String()
}

// spikeHeight is the height of an outage tick on a log scale: two seconds is
// the shortest, fifteen minutes or more is the tallest.
func spikeHeight(ms int64) float64 {
	sec := math.Max(float64(ms)/1000, 2)
	return 6 + 52*math.Min(1, math.Log(sec/2)/math.Log(450))
}

func laneLabel(x float64, y0, y1 float64, text string) string {
	return fmt.Sprintf(`<text class="strong" x="%s" y="%s" text-anchor="end">%s</text>`, n1(x), n1((y0+y1)/2+3.4), esc(text))
}

// segmentFill writes a profile segment as a rounded rectangle with its name.
func profileSegments(ax timeAxis, segs []ProfileSeg, y, h float64, nameY float64) string {
	var b strings.Builder
	for _, p := range segs {
		xa := ax.x(p.FromMS) + 0.75
		w := ax.x(p.ToMS) - ax.x(p.FromMS) - 1.5
		if w < 0.5 {
			continue
		}
		fmt.Fprintf(&b, `<rect x="%s" y="%s" width="%s" height="%s" rx="2" fill="%s"/>`, n1(xa), n1(y), n1(w), n1(h), profileFills[p.Style])
		if w > 54 {
			style := fmt.Sprintf("fill:%s;font-weight:600", colInk2)
			if p.Style == 1 {
				style = fmt.Sprintf("fill:#fff;font-weight:600;paint-order:stroke;stroke:%s;stroke-width:3px", colNeutral)
			}
			fmt.Fprintf(&b, `<text x="%s" y="%s" text-anchor="middle" style="%s">%s</text>`, n1(xa+w/2), n1(nameY), style, esc(truncate(p.Name, int(w/6.2))))
		}
	}
	return b.String()
}

func gapRects(ax timeAxis, gaps []Gap, y, h float64) string {
	var b strings.Builder
	for _, g := range gaps {
		w := ax.x(g.EndMS) - ax.x(g.StartMS)
		fmt.Fprintf(&b, `<rect x="%s" y="%s" width="%s" height="%s" fill="url(#hatch-gap)" stroke="%s" stroke-width=".8"/>`,
			n1(ax.x(g.StartMS)), n1(y), n1(math.Max(w, 1)), n1(h), colHatch)
	}
	return b.String()
}

// TimelineSVG draws the whole period on one strip: outages as ticks whose
// height shows how long each lasted, local events, the profile, and the gaps.
func (r *Report) TimelineSVG() template.HTML {
	const x0, x1 = 80.0, 684.0
	ax := r.axis(x0, x1)
	out, loc, prof, gap := [2]float64{30, 94}, [2]float64{104, 118}, [2]float64{126, 146}, [2]float64{154, 170}
	base := out[1]

	var b strings.Builder
	b.WriteString("<defs>" + hatchLight("hatch-gap") + hatchDark("hatch-profile") + "</defs>")
	for _, l := range [][2]float64{out, loc, prof, gap} {
		fmt.Fprintf(&b, `<rect x="%s" y="%s" width="%s" height="%s" fill="%s"/>`, n1(x0), n1(l[0]), n1(x1-x0), n1(l[1]-l[0]), colTrack)
	}
	b.WriteString(ax.grid(r, 16, gap[1], 11))
	b.WriteString(laneLabel(x0-8, out[0], out[1], "Outages") + laneLabel(x0-8, loc[0], loc[1], "Local events") +
		laneLabel(x0-8, prof[0], prof[1], "Profile") + laneLabel(x0-8, gap[0], gap[1], "Gaps"))

	for _, ref := range []struct {
		ms int64
		t  string
	}{{60_000, "1 min"}, {600_000, "10 min"}} {
		y := base - spikeHeight(ref.ms)
		fmt.Fprintf(&b, `<line x1="%s" x2="%s" y1="%s" y2="%s" stroke="#B9C1CC" stroke-dasharray="2 3"/>`, n1(x0), n1(x1), n1(y), n1(y))
		fmt.Fprintf(&b, `<text class="halo" x="%s" y="%s" text-anchor="end">%s</text>`, n1(x1-3), n1(y-3), ref.t)
	}

	var remote []Outage
	remote = append(remote, r.Upstream...)
	remote = append(remote, r.Unclear...)
	for _, o := range remote {
		h := spikeHeight(o.DurMS)
		fmt.Fprintf(&b, `<rect x="%s" y="%s" width="2.4" height="%s" rx="1" fill="%s"/>`, n1(ax.x(o.StartMS)-1.1), n1(base-h), n1(h), colBad)
	}
	fmt.Fprintf(&b, `<line class="axis" x1="%s" x2="%s" y1="%s" y2="%s"/>`, n1(x0), n1(x1), n1(base), n1(base))

	// Name the longest few, keeping the labels apart.
	longest := append([]Outage(nil), remote...)
	sort.SliceStable(longest, func(i, j int) bool { return longest[i].DurMS > longest[j].DurMS })
	var placed []float64
	for _, o := range longest {
		if len(placed) == 3 {
			break
		}
		x := ax.x(o.StartMS)
		near := false
		for _, p := range placed {
			if math.Abs(p-x) < 50 {
				near = true
			}
		}
		if near || x < x0+22 || x > x1-22 {
			continue
		}
		placed = append(placed, x)
		fmt.Fprintf(&b, `<text class="strong halo" x="%s" y="%s" text-anchor="middle">%s</text>`, n1(x), n1(base-spikeHeight(o.DurMS)-5), esc(fmtDur(o.DurMS)))
	}

	for _, o := range r.Local {
		fmt.Fprintf(&b, `<rect x="%s" y="%s" width="2.4" height="%s" rx="1" fill="%s"/>`, n1(ax.x(o.StartMS)-1.1), n1(loc[0]+2), n1(loc[1]-loc[0]-4), colInk2)
	}
	if len(r.Profiles) == 0 {
		fmt.Fprintf(&b, `<text x="%s" y="%s" text-anchor="middle">Not recorded</text>`, n1((x0+x1)/2), n1(prof[0]+13.2))
	}
	b.WriteString(profileSegments(ax, r.Profiles, prof[0], prof[1]-prof[0], prof[0]+13.2))
	b.WriteString(gapRects(ax, r.Gaps, gap[0], gap[1]-gap[0]))

	return svgWrap(fullW, 174, "Timeline of the period: outages as ticks whose height shows how long each lasted, local events, which profile was running and the gaps in monitoring", b.String())
}

// heatLevel bands the seconds of outage in a 15-minute block.
func heatLevel(sec float64) int {
	switch {
	case sec <= 0:
		return 0
	case sec < 5:
		return 1
	case sec < 30:
		return 2
	case sec < 180:
		return 3
	}
	return 4
}

// HeatmapSVG draws outage time in every 15-minute block of the period, one row
// for each day.
func (r *Report) HeatmapSVG() template.HTML {
	const hl, hr, cols = 80.0, 2.0, 96
	cell := (fullW - hl - hr) / cols
	n := len(r.Dates)
	rowH, rowG, every := 18.0, 3.0, 1
	switch {
	case n > 24:
		rowH, rowG, every = 4, 1, 5
	case n > 16:
		rowH, rowG, every = 5, 1, 5
	case n > 9:
		rowH, rowG, every = 12, 2, 1
	}
	const top = 20.0
	H := top + float64(n)*(rowH+rowG) - rowG + 4

	// Seconds of outage and share of asleep time, by 15-minute block.
	block := int64(15 * time.Minute / time.Millisecond)
	secs := map[int64]float64{}
	spread := func(startMS, endMS int64, add func(blockMS int64, overlapMS int64)) {
		for t := startMS / block * block; t < endMS; t += block {
			ov := min(endMS, t+block) - max(startMS, t)
			if ov > 0 {
				add(t, ov)
			}
		}
	}
	for _, o := range r.Outages {
		spread(o.StartMS, max(o.EndMS(), o.StartMS+1), func(t, ov int64) { secs[t] += float64(ov) / 1000 })
	}
	asleep := map[int64]float64{}
	for _, g := range r.Gaps {
		spread(g.StartMS, g.EndMS, func(t, ov int64) { asleep[t] += float64(ov) / float64(block) })
	}

	var b strings.Builder
	b.WriteString("<defs>" + hatchLight("hatch-heat") + "</defs>")
	for _, h := range []int{0, 6, 12, 18, 24} {
		anchor := "middle"
		if h == 0 {
			anchor = "start"
		} else if h == 24 {
			anchor = "end"
		}
		fmt.Fprintf(&b, `<text x="%s" y="11" text-anchor="%s">%02d:00</text>`, n1(hl+float64(h)*4*cell), anchor, h%24)
	}

	fromMS, toMS := r.From.UnixMilli(), r.To.UnixMilli()
	for i, day := range r.Dates {
		y := top + float64(i)*(rowH+rowG)
		next := day.AddDate(0, 0, 1)
		if every == 1 || i%every == 0 || day.Weekday() == time.Monday || i == n-1 {
			if every == 1 || day.Weekday() == time.Monday || i == 0 {
				fmt.Fprintf(&b, `<text class="strong" x="%s" y="%s" text-anchor="end">%s</text>`, n1(hl-8), n1(y+math.Min(rowH, 13)-0.6+0.4), esc(day.Format("Mon 2 Jan")))
			}
		}
		// The part of the day inside the period is the track.
		a, z := max(day.UnixMilli(), fromMS), min(next.UnixMilli(), toMS)
		xa := hl + float64(r.at(a).Hour()*60+r.at(a).Minute())/1440*cols*cell
		xz := hl + float64(r.at(z).Hour()*60+r.at(z).Minute())/1440*cols*cell
		if next.UnixMilli() <= toMS {
			xz = hl + cols*cell
		}
		fmt.Fprintf(&b, `<rect x="%s" y="%s" width="%s" height="%s" fill="%s"/>`, n1(xa), n1(y), n1(math.Max(xz-xa, 0)), n1(rowH), seqRamp[0])

		for t := day.UnixMilli() / block * block; t < next.UnixMilli(); t += block {
			if t+block <= a || t >= z {
				continue
			}
			wall := r.at(t)
			col := (wall.Hour()*60 + wall.Minute()) / 15
			if col < 0 || col >= cols {
				continue
			}
			x := hl + float64(col)*cell
			switch {
			case asleep[t] >= 0.5:
				fmt.Fprintf(&b, `<rect x="%s" y="%s" width="%s" height="%s" fill="url(#hatch-heat)"/>`, n1(x+0.4), n1(y), n1(cell-0.8), n1(rowH))
			case secs[t] > 0:
				fmt.Fprintf(&b, `<rect x="%s" y="%s" width="%s" height="%s" fill="%s"/>`, n1(x+0.4), n1(y), n1(cell-0.8), n1(rowH), seqRamp[heatLevel(secs[t])])
			}
		}
	}

	// Local events get a marker above their row.
	for _, o := range r.Local {
		t := r.at(o.StartMS)
		i := sort.Search(len(r.Dates), func(i int) bool { return r.Dates[i].After(t) }) - 1
		if i < 0 {
			continue
		}
		x := hl + float64(t.Hour()*60+t.Minute())/1440*cols*cell
		y := top + float64(i)*(rowH+rowG)
		if rowH >= 12 {
			fmt.Fprintf(&b, `<path d="M%s %sh8l-4 6z" fill="%s"/>`, n1(x-4), n1(y-4), colInk)
		} else {
			fmt.Fprintf(&b, `<rect x="%s" y="%s" width="1.6" height="%s" fill="%s"/>`, n1(x-0.8), n1(y), n1(rowH), colInk)
		}
	}
	return svgWrap(fullW, int(math.Ceil(H)), "Outage time in each 15-minute block of the period, one row per day", b.String())
}

// DailySVG draws the time offline in each day, or each hour for a short report,
// with the number of outages and brief failures under each full-size bar.
func (r *Report) DailySVG() template.HTML {
	const W, H, x0, x1, top, base = halfW, 196, 74.0, 333.0, 20.0, 118.0
	n := len(r.Tally)
	var maxMS int64
	for _, t := range r.Tally {
		maxMS = max(maxMS, t.OfflineMS)
	}
	maxMin := float64(maxMS) / 60000
	step := pickStep(math.Max(maxMin, 1))
	ymax := niceMax(math.Max(maxMin, 0.1), step)
	Y := func(m float64) float64 { return base - m/ymax*(base-top) }
	compact := n > 9
	slot := (x1 - x0) / float64(max(n, 1))
	bw := math.Min(20, slot*0.7)

	var b strings.Builder
	b.WriteString(`<text x="0" y="10">Minutes offline</text>`)
	for v := 0.0; v <= ymax+1e-9; v += step {
		cls := "grid"
		if v == 0 {
			cls = "axis"
		}
		fmt.Fprintf(&b, `<line class="%s" x1="%s" x2="%s" y1="%s" y2="%s"/><text x="%s" y="%s" text-anchor="end">%s</text>`,
			cls, n1(x0), n1(x1), n1(Y(v)), n1(Y(v)), n1(x0-7), n1(Y(v)+3.3), strconv.FormatFloat(v, 'f', -1, 64))
	}
	tallest := 0
	for i, t := range r.Tally {
		if t.OfflineMS > r.Tally[tallest].OfflineMS {
			tallest = i
		}
	}
	for i, t := range r.Tally {
		cx := x0 + slot*(float64(i)+0.5)
		h := 0.0
		if t.OfflineMS > 0 {
			h = math.Max(2, float64(t.OfflineMS)/60000/ymax*(base-top))
			fmt.Fprintf(&b, `<path d="%s" fill="%s"/>`, barUp(cx-bw/2, base-h, bw, h, math.Min(4, bw/2)), colBad)
		}
		if !compact {
			if t.OfflineMS > 0 {
				fmt.Fprintf(&b, `<text class="val halo" x="%s" y="%s" text-anchor="middle">%s</text>`, n1(cx), n1(base-h-5), esc(strings.TrimSuffix(fmtMinutes(t.OfflineMS), " min")))
			}
			fmt.Fprintf(&b, `<text class="strong" x="%s" y="%d" text-anchor="middle">%s</text><text x="%s" y="%d" text-anchor="middle">%s</text>`, n1(cx), int(base)+14, esc(t.Label), n1(cx), int(base)+25, esc(t.Sub))
			fmt.Fprintf(&b, `<text class="val mono" x="%s" y="%d" text-anchor="middle">%d</text><text class="mono" x="%s" y="%d" text-anchor="middle" style="fill:%s">%d</text>`,
				n1(cx), int(base)+50, t.Outages, n1(cx), int(base)+66, colInk3, t.Blips)
			continue
		}
		if i == tallest && t.OfflineMS > 0 {
			fmt.Fprintf(&b, `<text class="val halo" x="%s" y="%s" text-anchor="middle">%s</text>`, n1(cx), n1(base-h-5), esc(fmtMinutes(t.OfflineMS)))
		}
		// Compact labels: every fifth bar, and the first.
		if i == 0 || i%5 == 0 || (r.Hours && i%3 == 0) {
			label := t.Start.Format("2")
			if r.Hours {
				label = t.Label
			}
			fmt.Fprintf(&b, `<text x="%s" y="%d" text-anchor="middle">%s</text>`, n1(cx), int(base)+14, esc(label))
		}
	}
	if !compact {
		fmt.Fprintf(&b, `<line class="grid" x1="0" x2="%s" y1="%d" y2="%d"/>`, n1(x1), int(base)+36, int(base)+36)
		fmt.Fprintf(&b, `<text class="strong" x="%s" y="%d" text-anchor="end">Outages</text><text x="%s" y="%d" text-anchor="end">Brief failures</text>`, n1(x0-7), int(base)+50, n1(x0-7), int(base)+66)
	} else {
		unit := "Day of the month"
		if r.Hours {
			unit = "Hour of the day"
		}
		fmt.Fprintf(&b, `<text x="%s" y="%d" text-anchor="end">%s</text>`, n1(x1), int(base)+36, unit)
	}
	return svgWrap(W, H, "Minutes offline in each "+map[bool]string{true: "hour", false: "day"}[r.Hours]+" of the period", b.String())
}

// LengthSVG draws how many outages fell in each band of length.
func (r *Report) LengthSVG() template.HTML {
	const W, H = halfW, 196
	maxN := 0
	for _, n := range r.Lengths {
		maxN = max(maxN, n)
	}
	const x0, maxW, rowH, gap, top = 82.0, 200.0, 22.0, 8.0, 22.0

	var b strings.Builder
	head := "Number of outages by length."
	if len(r.Outages) >= 2 {
		head = "Number of outages by length. Half ended within " + fmtDur(r.MedianLenMS) + "."
	}
	fmt.Fprintf(&b, `<text x="0" y="10">%s</text>`, esc(head))
	for i, band := range lengthBands {
		y := top + float64(i)*(rowH+gap)
		n := r.Lengths[i]
		w := 0.0
		if maxN > 0 {
			w = math.Max(map[bool]float64{true: 3, false: 0}[n > 0], float64(n)/float64(maxN)*maxW)
		}
		fmt.Fprintf(&b, `<text class="strong" x="0" y="%s">%s</text>`, n1(y+14.8), esc(band.label))
		if n > 0 {
			fmt.Fprintf(&b, `<path d="%s" fill="%s"/>`, barRight(x0, y+2, w, rowH-4, 4), colNeutral)
		}
		fmt.Fprintf(&b, `<text class="val" x="%s" y="%s">%d</text>`, n1(x0+w+6), n1(y+14.8), n)
	}
	fmt.Fprintf(&b, `<line class="axis" x1="%s" x2="%s" y1="%s" y2="%s"/>`, n1(x0), n1(x0), n1(top-2), n1(top+5*(rowH+gap)-gap))
	return svgWrap(W, H, "Number of outages in each length band", b.String())
}

// LatencySVG draws the round-trip time to the internet and to the router over
// the period, with the slowest 5% of the internet's shaded, and a strip of
// outage ticks underneath.
func (r *Report) LatencySVG() template.HTML {
	const x0, x1, top, base = 44.0, 628.0, 22.0, 146.0
	const H = int(base) + 44
	ax := r.axis(x0, x1)

	var maxV float64
	have := make([]bool, len(r.LatSeries))
	intMed, intP95, rtrMed := make([]float64, len(have)), make([]float64, len(have)), make([]float64, len(have))
	haveRtr := make([]bool, len(have))
	any := false
	for i, p := range r.LatSeries {
		have[i], haveRtr[i] = p.HaveInt, p.HaveRtr
		intMed[i], intP95[i], rtrMed[i] = p.IntMed, p.IntP95, p.RtrMed
		if p.HaveInt {
			maxV = math.Max(maxV, p.IntP95)
			any = true
		}
		if p.HaveRtr {
			maxV = math.Max(maxV, p.RtrMed)
		}
	}
	label := "Round-trip time to the router and to the internet over the period, with the slowest 5 percent shaded"
	if !any {
		return svgWrap(fullW, 90, label, fmt.Sprintf(`<rect x="0" y="0" width="%d" height="90" fill="%s"/><text class="strong" x="%d" y="48" text-anchor="middle">No round-trip times were recorded in this period.</text>`, fullW, colTrack, fullW/2))
	}
	step := pickStep(maxV)
	ymax := niceMax(maxV, step)
	Y := func(v float64) float64 { return base - v/ymax*(base-top) }
	mid := r.LatStepMS / 2
	X := func(i int) float64 { return ax.x(r.LatSeries[i].TMS + mid) }
	clampX := func(i int) float64 { return math.Max(x0, math.Min(x1, X(i))) }

	var b strings.Builder
	b.WriteString("<defs>" + hatchLight("hatch-lat") + "</defs>")
	for v := 0.0; v <= ymax+1e-9; v += step {
		cls := "grid"
		if v == 0 {
			cls = "axis"
		}
		t := strconv.FormatFloat(v, 'f', -1, 64)
		if v+step > ymax+1e-9 {
			t += " ms"
		}
		fmt.Fprintf(&b, `<line class="%s" x1="%s" x2="%s" y1="%s" y2="%s"/><text x="%s" y="%s" text-anchor="end">%s</text>`, cls, n1(x0), n1(x1), n1(Y(v)), n1(Y(v)), n1(x0-7), n1(Y(v)+3.3), t)
	}
	for _, m := range axisMarks(r.From, r.To) {
		x := ax.x(m.ms)
		fmt.Fprintf(&b, `<line class="grid" x1="%s" x2="%s" y1="%s" y2="%s"/><text class="strong" x="%s" y="%d">%s</text>`, n1(x), n1(x), n1(top), n1(base+4), n1(x+4), int(base)+17, esc(m.label))
	}
	for _, g := range r.Gaps {
		fmt.Fprintf(&b, `<rect x="%s" y="%s" width="%s" height="%s" fill="url(#hatch-lat)" opacity=".7"/>`, n1(ax.x(g.StartMS)), n1(top), n1(math.Max(ax.x(g.EndMS)-ax.x(g.StartMS), 1)), n1(base-top))
	}
	fmt.Fprintf(&b, `<path d="%s" fill="%s" opacity=".13"/>`, bandPath(have, intMed, intP95, clampX, Y), colPing)
	fmt.Fprintf(&b, `<path d="%s" fill="none" stroke="%s" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>`, linePath(haveRtr, rtrMed, clampX, Y), colRouter)
	fmt.Fprintf(&b, `<path d="%s" fill="none" stroke="%s" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>`, linePath(have, intMed, clampX, Y), colPing)

	// Outage ticks in a strip under the plot.
	ty := base + 26
	fmt.Fprintf(&b, `<rect x="%s" y="%s" width="%s" height="12" fill="%s"/><text class="strong" x="%s" y="%s" text-anchor="end">Outages</text>`, n1(x0), n1(ty), n1(x1-x0), colTrack, n1(x0-7), n1(ty+9.4))
	for _, o := range r.Outages {
		col := colBad
		if o.Cause.Local() {
			col = colInk2
		}
		fmt.Fprintf(&b, `<rect x="%s" y="%s" width="2" height="10" fill="%s"/>`, n1(ax.x(o.StartMS)-1), n1(ty+1), col)
	}

	// Mark the slowest bucket.
	worst, found := 0, false
	for i, p := range r.LatSeries {
		if p.HaveInt && (!found || p.IntP95 > r.LatSeries[worst].IntP95) {
			worst, found = i, true
		}
	}
	if found {
		p := r.LatSeries[worst]
		wx, wy := clampX(worst), Y(p.IntP95)
		anchor := "middle"
		if wx > x1-150 {
			anchor = "end"
		} else if wx < x0+150 {
			anchor = "start"
		}
		fmt.Fprintf(&b, `<circle cx="%s" cy="%s" r="3.5" fill="%s" stroke="#fff" stroke-width="2"/>`, n1(wx), n1(wy), colPing)
		fmt.Fprintf(&b, `<line x1="%s" x2="%s" y1="%s" y2="%s" stroke="%s" stroke-width="1"/>`, n1(wx), n1(wx), n1(top-7), n1(wy-5), colInk3)
		when := r.at(p.TMS + mid).Format("Mon 2 Jan 15:04")
		fmt.Fprintf(&b, `<text class="strong" x="%s" y="%s" text-anchor="%s">%s</text>`, n1(wx), n1(top-10), anchor, esc(fmt.Sprintf("Slowest 5%% reached %s ms, %s", fmtMS(p.IntP95), when)))
	}

	// Name the lines where they end.
	lastY := func(have []bool, vals []float64) (float64, bool) {
		for i := len(vals) - 1; i >= 0; i-- {
			if have[i] {
				return Y(vals[i]), true
			}
		}
		return 0, false
	}
	iy, okI := lastY(have, intMed)
	ry, okR := lastY(haveRtr, rtrMed)
	if okI {
		fmt.Fprintf(&b, `<text class="strong" x="%s" y="%s">Internet</text>`, n1(x1+8), n1(iy+3.4))
	}
	if okR {
		off := 3.4
		if okI && math.Abs(ry-iy) < 12 {
			off = 3.4 + 12 - math.Abs(ry-iy)
		}
		fmt.Fprintf(&b, `<text class="strong" x="%s" y="%s">Router</text>`, n1(x1+8), n1(ry+off))
	}
	return svgWrap(fullW, H, label, b.String())
}

// HourSVG draws the internet's round-trip time by hour of the day, over every
// day of the period.
func (r *Report) HourSVG() template.HTML {
	const W, H, x0, x1, top, base = halfW, 142, 40.0, 333.0, 14.0, 112.0
	label := "Internet round-trip time by hour of the day, median and slowest 5 percent"
	have := make([]bool, 24)
	med, hi := make([]float64, 24), make([]float64, 24)
	var maxV float64
	count := 0
	for h, p := range r.HOD {
		have[h], med[h], hi[h] = p.Have, p.Med, p.P95
		if p.Have {
			maxV = math.Max(maxV, p.P95)
			count++
		}
	}
	if count < 2 {
		return svgWrap(W, 90, label, fmt.Sprintf(`<rect x="0" y="0" width="%d" height="90" fill="%s"/><text class="strong" x="%d" y="48" text-anchor="middle">Not enough round-trip times for this chart.</text>`, W, colTrack, W/2))
	}
	step := pickStep(maxV)
	ymax := niceMax(maxV, step)
	Y := func(v float64) float64 { return base - v/ymax*(base-top) }
	X := func(i int) float64 { return x0 + (float64(i)+0.5)/24*(x1-x0) }

	var b strings.Builder
	for v := 0.0; v <= ymax+1e-9; v += step {
		cls := "grid"
		if v == 0 {
			cls = "axis"
		}
		t := strconv.FormatFloat(v, 'f', -1, 64)
		if v+step > ymax+1e-9 {
			t += " ms"
		}
		fmt.Fprintf(&b, `<line class="%s" x1="%s" x2="%s" y1="%s" y2="%s"/><text x="%s" y="%s" text-anchor="end">%s</text>`, cls, n1(x0), n1(x1), n1(Y(v)), n1(Y(v)), n1(x0-6), n1(Y(v)+3.3), t)
	}
	for _, h := range []int{0, 6, 12, 18, 24} {
		anchor := "middle"
		if h == 0 {
			anchor = "start"
		} else if h == 24 {
			anchor = "end"
		}
		fmt.Fprintf(&b, `<text x="%s" y="%d" text-anchor="%s">%02d:00</text>`, n1(x0+float64(h)/24*(x1-x0)), int(base)+15, anchor, h%24)
	}
	fmt.Fprintf(&b, `<path d="%s" fill="%s" opacity=".13"/>`, bandPath(have, med, hi, X, Y), colPing)
	fmt.Fprintf(&b, `<path d="%s" fill="none" stroke="%s" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>`, linePath(have, med, X, Y), colPing)

	peak, _ := r.hourPeak()
	fmt.Fprintf(&b, `<circle cx="%s" cy="%s" r="3.5" fill="%s" stroke="#fff" stroke-width="2"/>`, n1(X(peak)), n1(Y(med[peak])), colPing)
	anchor, dx := "end", -9.0
	if X(peak) < x0+120 {
		anchor, dx = "start", 9
	}
	fmt.Fprintf(&b, `<text class="strong halo" x="%s" y="%s" text-anchor="%s">%02d:00, median %s ms</text>`, n1(X(peak)+dx), n1(Y(med[peak])-9), anchor, peak, fmtMS(med[peak]))
	return svgWrap(W, H, label, b.String())
}

// hourPeak is the hour of the day with the highest median round-trip time.
func (r *Report) hourPeak() (int, bool) {
	peak, found := 0, false
	for h, p := range r.HOD {
		if p.Have && (!found || p.Med > r.HOD[peak].Med) {
			peak, found = h, true
		}
	}
	return peak, found
}

// HourNote says how much slower the busiest hour is than the quietest night
// hours, when the data supports saying so.
func (r *Report) HourNote() string {
	peak, found := r.hourPeak()
	if !found {
		return ""
	}
	var sum float64
	n := 0
	for h := 2; h < 6; h++ {
		if r.HOD[h].Have {
			sum += r.HOD[h].Med
			n++
		}
	}
	if n < 2 || sum <= 0 {
		return ""
	}
	night := sum / float64(n)
	ratio := r.HOD[peak].Med / night
	if ratio < 1.3 || peak >= 2 && peak < 6 {
		return ""
	}
	return fmt.Sprintf("The median at %02d:00 is about %.1f times the overnight figure (%s ms between 02:00 and 06:00).", peak, ratio, fmtMS(night))
}

// ProfileLaneSVG draws which profile ran when, and the gaps, with a note at
// each switch.
func (r *Report) ProfileLaneSVG() template.HTML {
	const x0, x1 = 80.0, 684.0
	ax := r.axis(x0, x1)
	var b strings.Builder
	b.WriteString("<defs>" + hatchLight("hatch-gap") + hatchDark("hatch-profile") + "</defs>")
	fmt.Fprintf(&b, `<rect x="%s" y="22" width="%s" height="26" fill="%s"/><rect x="%s" y="76" width="%s" height="14" fill="%s"/>`, n1(x0), n1(x1-x0), colTrack, n1(x0), n1(x1-x0), colTrack)
	b.WriteString(ax.grid(r, 15, 90, 10))
	b.WriteString(`<text class="strong" x="72" y="39.5" text-anchor="end">Profile</text><text class="strong" x="72" y="86.5" text-anchor="end">Gaps</text>`)
	if len(r.Profiles) == 0 {
		fmt.Fprintf(&b, `<text x="%s" y="39.4" text-anchor="middle">Not recorded</text>`, n1((x0+x1)/2))
	}
	b.WriteString(profileSegments(ax, r.Profiles, 22, 26, 39.4))

	// A mark and a note at each switch, as far as there is room for the notes.
	lastEnd := -1000.0
	for i, p := range r.Profiles {
		if i == 0 {
			continue
		}
		x := ax.x(p.FromMS)
		fmt.Fprintf(&b, `<path d="M%s 51l-4.5 7.5h9z" fill="%s"/>`, n1(x), colInk)
		note := fmt.Sprintf("To %s, %s", p.Name, r.at(p.FromMS).Format("Mon 2 15:04"))
		w := float64(len([]rune(note))) * 5.4
		left, anchor := x+6, "start"
		if left+w > x1 {
			left, anchor = x-6, "end"
		}
		span0 := left
		if anchor == "end" {
			span0 = left - w
		}
		if span0 < lastEnd+8 || span0 < x0-70 {
			continue
		}
		lastEnd = span0 + w
		fmt.Fprintf(&b, `<text class="strong" x="%s" y="66" text-anchor="%s">%s</text>`, n1(left), anchor, esc(note))
	}
	b.WriteString(gapRects(ax, r.Gaps, 76, 14))
	return svgWrap(fullW, 96, "Which monitoring profile was running across the period, and the gaps in monitoring", b.String())
}
