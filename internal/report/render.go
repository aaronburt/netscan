package report

import (
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aaronburt/netscan/internal/detector"
)

//go:embed report.gohtml
var pageSource string

//go:embed style.css
var styleSource string

var pageTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"dur":        fmtDur,
	"big":        fmtBig,
	"pct":        fmtPct,
	"ms":         fmtMS,
	"count":      fmtCount,
	"uptime":     fmtUptime,
	"plural":     plural,
	"thousands":  thousands,
	"seconds":    func(ms int) float64 { return float64(ms) / 1000 },
	"markup":     func(s string) template.HTML { return template.HTML(s) },
	"logo":       logo,
	"dot":        dotCell,
	"pillText":   pillText,
	"causePill":  func(c Cause) template.HTML { return pillText(c.Label(), c.Severity()) },
	"checks":     checkCells,
	"lasted":     lasted,
	"routerCell": routerCell,
	"uncert":     func(o Outage) string { return fmt.Sprintf("%.1f s", float64(o.UncertMS)/1000) },
	"profileSwatch": func(l LegendItem) template.HTML {
		return template.HTML(`<i class="sw" style="` + l.Style() + `"></i>`)
	},
	"pg": func(r *Report, n int, where string, mast bool) pageCtx {
		return pageCtx{R: r, N: n, Where: where, Mast: mast}
	},
	"lpg": func(r *Report, n int, where string) pageCtx {
		return pageCtx{R: r, N: n, Where: where}
	},
	"tbl": func(r *Report, rows []Outage, caption string) tableCtx {
		return tableCtx{R: r, Rows: rows, Caption: caption}
	},
	"logCtx": func(r *Report, i int, p LogPage) logCtx {
		return logCtx{R: r, N: fixedPages + 1 + i, Page: p}
	},
}).Parse(pageSource))

type pageCtx struct {
	R     *Report
	N     int
	Where string
	Mast  bool
}

type tableCtx struct {
	R       *Report
	Rows    []Outage
	Caption string
}

type logCtx struct {
	R    *Report
	N    int
	Page LogPage
}

type periodLink struct {
	Value, Label string
	Current      bool
}

// Render writes the report as a complete HTML document.
func Render(w io.Writer, r *Report) error {
	var periods []periodLink
	for _, p := range []struct {
		v Period
		l string
	}{{Period24h, "24 hours"}, {Period7d, "7 days"}, {Period30d, "30 days"}} {
		periods = append(periods, periodLink{Value: string(p.v), Label: p.l, Current: p.v == r.Period})
	}
	return pageTemplate.ExecuteTemplate(w, "doc", struct {
		R       *Report
		CSS     template.CSS
		Periods []periodLink
	}{R: r, CSS: template.CSS(styleSource), Periods: periods})
}

// Generate builds the report for a period and writes it.
func Generate(w io.Writer, src Source, opts Options) error {
	r, err := Build(src, opts)
	if err != nil {
		return err
	}
	return Render(w, r)
}

// --- text for the page -------------------------------------------------------

// ShortPeriod names the period by its dates: "Fri 23 Oct to Fri 30 Oct 2026".
func (r *Report) ShortPeriod() string {
	return r.From.Format("Mon 2 Jan") + " to " + r.To.Format("Mon 2 Jan 2006")
}

// PeriodText is the period with its times, for the title of the first page.
func (r *Report) PeriodText() string {
	return r.From.Format("Mon 2 Jan 15:04") + " to " + r.To.Format("Mon 2 Jan 2006 15:04") + " · " + r.Period.Words()
}

// GeneratedText says when the report was made.
func (r *Report) GeneratedText() string { return r.Generated.Format("Mon 2 Jan 2006, 15:04") }

// GeneratedShort is the time of generation for the foot of a page.
func (r *Report) GeneratedShort() string { return r.Generated.Format("Mon 2 Jan 15:04") }

// Zone names the time zone the report's times are in.
func (r *Report) Zone() string { return fmtZone(r.To) }

// VersionText is the app version as the report prints it.
func (r *Report) VersionText() string {
	v := strings.TrimSpace(r.Version)
	if v == "" {
		return ""
	}
	if v[0] >= '0' && v[0] <= '9' {
		return "v" + v
	}
	return v
}

// DayShort writes a day as "Fri 23".
func (r *Report) DayShort(ms int64) string { return r.at(ms).Format("Mon 2") }

// HM writes a time of day as "04:12".
func (r *Report) HM(ms int64) string { return r.at(ms).Format("15:04") }

// DataFromText says when monitoring data begins, for the note under the summary.
func (r *Report) DataFromText() string { return r.DataFrom.Format("Mon 2 Jan 15:04") }

// SlowSub is the line under the slow-spell count.
func (r *Report) SlowSub() string {
	i, rt := r.SlowCounts()
	return fmt.Sprintf("%d internet · %d router", i, rt)
}

// GapText is the total time in gaps, to the minute.
func (r *Report) GapText() string {
	if r.GapTotal <= 0 {
		return "None"
	}
	ms := r.GapTotal.Milliseconds()
	if ms >= 600_000 {
		ms = ms / 60_000 * 60_000
	}
	return fmtDur(ms)
}

// LatStepText says how finely the round-trip chart is cut.
func (r *Report) LatStepText() string {
	switch d := time.Duration(r.LatStepMS) * time.Millisecond; {
	case d >= time.Hour:
		return fmt.Sprintf("%d-hour figures", int(d/time.Hour))
	default:
		return fmt.Sprintf("%d-minute figures", int(d/time.Minute))
	}
}

// maxSlowShown is how many slow spells the speed page lists.
const maxSlowShown = 8

// SlowShown is the slow spells the speed page lists.
func (r *Report) SlowShown() []SlowSpell {
	return r.Slow[:min(len(r.Slow), maxSlowShown)]
}

// SlowMore is how many slow spells the speed page leaves out.
func (r *Report) SlowMore() int { return max(0, len(r.Slow)-maxSlowShown) }

// topCount is how many of the longest outages page 2 lists. A month of
// heatmap rows leaves room for fewer.
func (r *Report) topCount() int {
	if len(r.Dates) > 16 {
		return 3
	}
	return 5
}

// TopTitle is the heading over the longest outages.
func (r *Report) TopTitle() string {
	if r.topCount() == 3 {
		return "The three longest"
	}
	return "The five longest"
}

// TopFive is the longest outages, in the order they happened.
func (r *Report) TopFive() []Outage {
	top := append([]Outage(nil), r.Outages...)
	// Longest first; the sort is stable, so equal lengths keep their order.
	sort.SliceStable(top, func(i, j int) bool { return top[i].DurMS > top[j].DurMS })
	if n := r.topCount(); len(top) > n {
		top = top[:n]
	}
	sort.SliceStable(top, func(i, j int) bool { return top[i].StartMS < top[j].StartMS })
	return top
}

// LegendItem is a profile in the key under the timeline.
type LegendItem struct {
	Name  string
	style int
}

// Style is the CSS for the key's swatch.
func (l LegendItem) Style() string {
	switch l.style {
	case 0:
		return "background:#DCE2E9"
	case 1:
		return "background:repeating-linear-gradient(135deg,#5B6778 0 2px,#8F9AAB 2px 3px);border:1px solid #5B6778"
	case 2:
		return "background:#B8C2CF"
	}
	return "background:#EEF1F5;border:1px solid #CDD3DC"
}

// ProfileLegend lists each profile that ran in the period once.
func (r *Report) ProfileLegend() []LegendItem {
	var out []LegendItem
	seen := map[string]bool{}
	for _, p := range r.Profiles {
		if seen[p.Name] {
			continue
		}
		seen[p.Name] = true
		out = append(out, LegendItem{Name: p.Name, style: p.Style})
	}
	return out
}

// --- table cells -------------------------------------------------------------

func thousands(n int64) string {
	s := strconv.FormatInt(n, 10)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	if neg {
		s = "-" + s
	}
	return s
}

func logo(n int) template.HTML {
	return template.HTML(fmt.Sprintf(`<svg width="%d" height="%d" viewBox="0 0 32 32" aria-hidden="true"><rect width="32" height="32" rx="7" fill="#0F1720"/><path d="M5 17h5l3-8 5 15 3-9 2 2h4" fill="none" stroke="#F3F5F8" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg>`, n, n))
}

const (
	iconBad     = `<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M4 4l8 8M12 4l-8 8" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/></svg>`
	iconWarn    = `<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 2l6.5 11.5h-13z" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/><path d="M8 6.5v3M8 11.3v.4" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></svg>`
	iconNeutral = `<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M3 3.5h6.5L3 12.5h10" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"/></svg>`
)

// pillText is a rounded label with an icon, so its meaning never rests on
// colour alone.
func pillText(label, sev string) template.HTML {
	icon := iconNeutral
	switch sev {
	case "bad":
		icon = iconBad
	case "warn":
		icon = iconWarn
	default:
		sev = "neutral"
	}
	return template.HTML(`<span class="pill ` + sev + `">` + icon + esc(label) + `</span>`)
}

// dotCell is a filled dot where a check failed, and an empty ring where not.
func dotCell(on bool, kind string) template.HTML {
	if on {
		return template.HTML(`<i class="dot k-` + esc(kind) + `"></i>`)
	}
	return template.HTML(`<i class="dot off"></i>`)
}

// checkCells writes the dots of an outage-log row, one cell per check. The
// local table also has the link and router columns.
func checkCells(o Outage, local bool) template.HTML {
	cols := []struct {
		bit  int
		kind string
	}{
		{detector.LayerMaskISPEdge, "isp"}, {detector.LayerMaskWANICMP, "icmp"}, {detector.LayerMaskWANTCP, "tcp"}, {detector.LayerMaskDNS, "dns"}, {detector.LayerMaskHTTP, "http"},
	}
	if local {
		cols = append([]struct {
			bit  int
			kind string
		}{{detector.LayerMaskLink, "link"}, {detector.LayerMaskGateway, "gw"}}, cols...)
	}
	var b strings.Builder
	for _, c := range cols {
		b.WriteString(`<td class="c dc">` + string(dotCell(o.Failed(c.bit), c.kind)) + `</td>`)
	}
	return template.HTML(b.String())
}

// lasted is the length cell, with a note on an outage that had not ended.
func lasted(o Outage) template.HTML {
	s := esc(fmtDur(o.DurMS))
	if o.Ongoing {
		s += ` <span class="dag">ongoing</span>`
	}
	return template.HTML(s)
}

// routerCell is the cell that says how much of the router's probing was
// answered. Under the threshold it is marked, because the outage may not be
// the ISP's.
func routerCell(o Outage) template.HTML {
	if !o.RouterKnown {
		return `<td class="r dim">n/a</td>`
	}
	class := "r"
	if o.RouterPct < routerOKThreshold {
		class += " low"
	}
	return template.HTML(`<td class="` + class + `">` + esc(fmtPct(float64(int(o.RouterPct*10+0.5))/10)) + `</td>`)
}

// WhenCell writes a start time as a day above-left of the time of day.
func (r *Report) WhenCell(ms int64) template.HTML {
	t := r.at(ms)
	return template.HTML(`<span class="when"><small>` + esc(t.Format("Mon 2 Jan")) + `</small><b>` + esc(t.Format("15:04:05")) + `</b></span>`)
}

// ProfCell names the profile an outage began under.
func (r *Report) ProfCell(o Outage) template.HTML {
	s := `<span class="prof">` + esc(truncate(o.Profile, 12))
	if o.Spanned {
		s += `<sup class="dag" title="Began under one profile and ended under another">&dagger;</sup>`
	}
	return template.HTML(s + `</span>`)
}

// Why says, in a few words, why an outage counts as local.
func (o Outage) Why() string {
	var parts []string
	if o.Flags&detector.EventFlagPostResume != 0 {
		parts = append(parts, "Right after the PC woke")
	}
	if o.Flags&detector.EventFlagVPN != 0 {
		parts = append(parts, "A VPN was active")
	}
	if o.Mask&detector.LayerMaskLink != 0 {
		parts = append(parts, "Network link went down")
	} else if o.Mask&detector.LayerMaskGateway != 0 {
		parts = append(parts, "Router stopped answering")
	}
	if len(parts) == 0 {
		return "Local network"
	}
	for i := 1; i < len(parts); i++ {
		parts[i] = strings.ToLower(parts[i][:1]) + parts[i][1:]
	}
	return strings.Join(parts, "; ")
}
