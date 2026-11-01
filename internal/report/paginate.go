package report

import (
	"fmt"
)

// The summary, outages, speed and method pages are one sheet each. The outage
// log that follows runs over as many sheets as it needs, and every sheet is
// laid out here rather than left to the browser, so the page breaks and the
// "Page n of N" are the same in every browser.
//
// Heights are in CSS pixels at 96 to the inch. A sheet has about 1016 px of
// room inside its margins. The budget is a little under that, because fonts
// differ and the page must never be tall enough to spill.
const (
	fixedPages = 4

	pageBudget  = 940.0
	runHeadH    = 44.0  // the running header and its gap
	introH      = 150.0 // title, key and note at the top of the log
	secHeadH    = 36.0  // a section heading and its gap
	tableHeadH  = 50.0  // the two-line table heading
	logRowH     = 22.0  // one row of the outage tables
	localRowH   = 30.0  // one row of the local events table, which can wrap
	emptyRowH   = 40.0  // the line that says a section is empty
	blockGap    = 12.0
	minTableRow = 3 // a table is not started unless this many rows fit
)

// Tail blocks, in the order they close the log, and their heights.
var logTail = []struct {
	name string
	h    float64
}{
	{"notinlog", 84},
	{"data", 178},
	{"terms", 208},
	{"end", 36},
}

// LogPlan is the outage log laid out over sheets.
type LogPlan struct {
	Pages []LogPage
}

// LogPage is one sheet of the outage log.
type LogPage struct {
	Intro    bool // the first sheet carries the title and the key
	Sections []LogSection
	Tail     []string // closing blocks that fall on this sheet
}

// LogSection is a table, or part of one, on a sheet.
type LogSection struct {
	Kind      string // upstream, unclear or local
	Title     string
	Note      string
	Rows      []Outage
	Continued bool
	Empty     bool
}

// TotalPages is how many sheets the report has.
func (r *Report) TotalPages() int { return fixedPages + len(r.Log.Pages) }

// LogRange says which sheets hold the outage log: "5" or "5–7".
func (r *Report) LogRange() string {
	first, last := fixedPages+1, r.TotalPages()
	if first == last {
		return fmt.Sprint(first)
	}
	return fmt.Sprintf("%d–%d", first, last)
}

func (r *Report) planLog() {
	type section struct {
		kind, title, note string
		rows              []Outage
	}
	note := func(rows []Outage, extra string) string {
		var total int64
		for _, o := range rows {
			total += o.DurMS
		}
		if len(rows) == 0 {
			return extra
		}
		return fmt.Sprintf("%s · %s", plural(len(rows), "outage", "outages"), fmtDur(total))
	}
	sections := []section{{"upstream", "Outages beyond the router", note(r.Upstream, ""), r.Upstream}}
	if len(r.Unclear) > 0 {
		sections = append(sections, section{"unclear", "Outages where the router also missed replies", note(r.Unclear, ""), r.Unclear})
	}
	sections = append(sections, section{"local", "Local and system events", "left out of the ISP-side figures", r.Local})

	var pages []LogPage
	cur := &LogPage{Intro: true}
	used := runHeadH + introH
	next := func() {
		pages = append(pages, *cur)
		cur = &LogPage{}
		used = runHeadH
	}

	for _, s := range sections {
		if len(s.rows) == 0 {
			need := secHeadH + emptyRowH + blockGap
			if used+need > pageBudget {
				next()
			}
			cur.Sections = append(cur.Sections, LogSection{Kind: s.kind, Title: s.title, Note: s.note, Empty: true})
			used += need
			continue
		}

		rowH := logRowH
		if s.kind == "local" {
			rowH = localRowH
		}
		rows := s.rows
		for first := true; len(rows) > 0; first = false {
			head := secHeadH + tableHeadH
			if used+head+float64(min(len(rows), minTableRow))*rowH > pageBudget {
				next()
			}
			k := min(len(rows), int((pageBudget-used-head)/rowH))
			cur.Sections = append(cur.Sections, LogSection{Kind: s.kind, Title: s.title, Note: s.note, Rows: rows[:k], Continued: !first})
			used += head + float64(k)*rowH + blockGap
			rows = rows[k:]
			if len(rows) > 0 {
				next()
			}
		}
	}

	for _, t := range logTail {
		if used+t.h > pageBudget {
			next()
		}
		cur.Tail = append(cur.Tail, t.name)
		used += t.h + blockGap
	}
	pages = append(pages, *cur)
	r.Log = LogPlan{Pages: pages}
}
