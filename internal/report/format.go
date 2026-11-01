package report

import (
	"fmt"
	"html"
	"html/template"
	"math"
	"strings"
	"time"
)

// durParts splits a length of time into value and unit pairs: "3.2 s",
// "14 min 20 s", "1 h 05 min". Under ten seconds keeps a decimal, because a
// two second outage and a nine second one are different things.
func durParts(ms int64) [][2]string {
	if ms < 0 {
		ms = 0
	}
	if ms < 10_000 {
		return [][2]string{{fmt.Sprintf("%.1f", float64(ms)/1000), "s"}}
	}
	s := (ms + 500) / 1000
	if s < 60 {
		return [][2]string{{fmt.Sprint(s), "s"}}
	}
	m, r := s/60, s%60
	if m < 60 {
		if r == 0 {
			return [][2]string{{fmt.Sprint(m), "min"}}
		}
		return [][2]string{{fmt.Sprint(m), "min"}, {fmt.Sprintf("%02d", r), "s"}}
	}
	h, mm := m/60, m%60
	if mm == 0 {
		return [][2]string{{fmt.Sprint(h), "h"}}
	}
	return [][2]string{{fmt.Sprint(h), "h"}, {fmt.Sprintf("%02d", mm), "min"}}
}

// fmtDur writes a length of time in words and numbers: "14 min 20 s".
func fmtDur(ms int64) string {
	parts := durParts(ms)
	out := make([]string, len(parts))
	for i, p := range parts {
		out[i] = p[0] + " " + p[1]
	}
	return strings.Join(out, " ")
}

// fmtBig writes a length of time for a headline figure, with the units small.
func fmtBig(ms int64) template.HTML {
	var b strings.Builder
	for i, p := range durParts(ms) {
		if i > 0 {
			b.WriteString(" ")
		}
		b.WriteString(html.EscapeString(p[0]))
		b.WriteString("<small> " + p[1] + "</small>")
	}
	return template.HTML(b.String())
}

// fmtMinutes is a bar label: seconds under a minute, then minutes.
func fmtMinutes(ms int64) string {
	if ms < 60_000 {
		return fmt.Sprintf("%d s", (ms+500)/1000)
	}
	if ms < 600_000 {
		return fmt.Sprintf("%.1f min", float64(ms)/60000)
	}
	return fmt.Sprintf("%d min", (ms+30_000)/60_000)
}

// fmtPct writes a percentage with a decimal only when it needs one.
func fmtPct(p float64) string {
	if p == math.Trunc(p) {
		return fmt.Sprintf("%d%%", int(p))
	}
	return fmt.Sprintf("%.1f%%", p)
}

// fmtUptime writes the uptime to two places without rounding up to 100 while
// there was any time offline.
func fmtUptime(p float64, offlineMS int64) string {
	if offlineMS > 0 {
		p = math.Floor(p*100) / 100
		if p >= 100 {
			p = 99.99
		}
	}
	return fmt.Sprintf("%.2f", p)
}

// fmtCount writes a large count in words: "412 thousand", "1.2 million".
func fmtCount(n int64) string {
	switch {
	case n >= 1_000_000:
		return fmt.Sprintf("%.1f million", float64(n)/1e6)
	case n >= 10_000:
		return fmt.Sprintf("%d thousand", (n+500)/1000)
	}
	s := fmt.Sprint(n)
	if len(s) > 3 {
		s = s[:len(s)-3] + "," + s[len(s)-3:]
	}
	return s
}

// fmtMS writes a round-trip time in milliseconds to a sensible precision.
func fmtMS(v float64) string {
	switch {
	case v >= 100:
		return fmt.Sprintf("%.0f", v)
	case v >= 10:
		return fmt.Sprintf("%.1f", v)
	}
	return fmt.Sprintf("%.2f", v)
}

// fmtZone writes a time zone as an offset from UTC: "UTC+01:00".
func fmtZone(t time.Time) string {
	_, off := t.Zone()
	sign := "+"
	if off < 0 {
		sign, off = "-", -off
	}
	return fmt.Sprintf("UTC%s%02d:%02d", sign, off/3600, off%3600/60)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

func esc(s string) string { return html.EscapeString(s) }
