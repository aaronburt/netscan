package report

import (
	"bytes"
	"encoding/xml"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aaronburt/netscan/internal/detector"
	"github.com/aaronburt/netscan/internal/netenv"
	"github.com/aaronburt/netscan/internal/store"
)

// TestRenderToDir writes sample reports to the folder named by
// NETSCAN_REPORT_DIR, so a maintainer can open them in a browser or print them
// to PDF while working on the layout. It does nothing otherwise.
func TestRenderToDir(t *testing.T) {
	dir := os.Getenv("NETSCAN_REPORT_DIR")
	if dir == "" {
		t.Skip("set NETSCAN_REPORT_DIR to write sample reports")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]Period{"24h": Period24h, "7d": Period7d, "30d": Period30d} {
		days := map[Period]int{Period24h: 3, Period7d: 8, Period30d: 31}[p]
		var buf bytes.Buffer
		if err := Generate(&buf, newFixture(days), fixtureOptions(p)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(dir, "report-"+name+".html"), buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var buf bytes.Buffer
	if err := Generate(&buf, &fixture{}, fixtureOptions(Period7d)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "report-empty.html"), buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func render(t *testing.T, src Source, opts Options) string {
	t.Helper()
	var buf bytes.Buffer
	if err := Generate(&buf, src, opts); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

var svgRE = regexp.MustCompile(`(?s)<svg\b.*?</svg>`)

// checkPage fails on the faults a broken template or a bad number would leave.
func checkPage(t *testing.T, name, page string, r *Report) {
	t.Helper()
	for _, bad := range []string{"NaN", "Inf", "%!", "<nil>", "{{", "}}", "<no value>"} {
		if strings.Contains(page, bad) {
			i := strings.Index(page, bad)
			t.Errorf("%s: page contains %q near %q", name, bad, page[max(0, i-60):min(len(page), i+60)])
		}
	}
	for _, svg := range svgRE.FindAllString(page, -1) {
		dec := xml.NewDecoder(strings.NewReader(svg))
		for {
			_, err := dec.Token()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Errorf("%s: SVG is not well formed: %v\n%.200s", name, err, svg)
				break
			}
		}
	}
	for _, tag := range []string{"table", "section", "div", "svg", "tbody", "thead"} {
		open := strings.Count(page, "<"+tag+" ") + strings.Count(page, "<"+tag+">")
		if closed := strings.Count(page, "</"+tag+">"); open != closed {
			t.Errorf("%s: %d <%s> opened, %d closed", name, open, tag, closed)
		}
	}
	if got := strings.Count(page, `<section class="sheet"`); r != nil && got != r.TotalPages() {
		t.Errorf("%s: %d sheets drawn, TotalPages says %d", name, got, r.TotalPages())
	}
}

func TestParsePeriod(t *testing.T) {
	for in, want := range map[string]Period{"": Period7d, "24h": Period24h, "7d": Period7d, "30d": Period30d} {
		got, ok := ParsePeriod(in)
		if !ok || got != want {
			t.Errorf("ParsePeriod(%q) = %q, %v", in, got, ok)
		}
	}
	for _, in := range []string{"1y", "7D", "../x", "24h "} {
		if _, ok := ParsePeriod(in); ok {
			t.Errorf("ParsePeriod(%q) accepted", in)
		}
	}
	if Period24h.Duration() != 24*time.Hour || Period30d.Duration() != 720*time.Hour || Period7d.Duration() != 168*time.Hour {
		t.Error("period durations are wrong")
	}
}

func TestReportsRender(t *testing.T) {
	for _, tc := range []struct {
		p    Period
		days int
	}{{Period24h, 3}, {Period7d, 8}, {Period30d, 31}} {
		src := newFixture(tc.days)
		r, err := Build(src, fixtureOptions(tc.p))
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		if err := Render(&buf, r); err != nil {
			t.Fatal(err)
		}
		page := buf.String()
		checkPage(t, string(tc.p), page, r)

		if len(r.Outages) == 0 {
			t.Fatalf("%s: fixture gave no outages", tc.p)
		}
		if got := len(r.Upstream) + len(r.Unclear) + len(r.Local); got != len(r.Outages) {
			t.Errorf("%s: buckets hold %d outages, there are %d", tc.p, got, len(r.Outages))
		}
		var rows int
		for _, pg := range r.Log.Pages {
			for _, s := range pg.Sections {
				rows += len(s.Rows)
			}
		}
		if rows != len(r.Outages) {
			t.Errorf("%s: the log lists %d outages, there are %d", tc.p, rows, len(r.Outages))
		}
		var inBands int
		for _, n := range r.Lengths {
			inBands += n
		}
		if inBands != len(r.Outages) {
			t.Errorf("%s: length bands hold %d, there are %d", tc.p, inBands, len(r.Outages))
		}
		var causeSum int
		for _, c := range r.Causes {
			causeSum += c.Count
		}
		if causeSum != len(r.Outages) {
			t.Errorf("%s: causes add to %d, there are %d outages", tc.p, causeSum, len(r.Outages))
		}
		if r.UptimePct <= 0 || r.UptimePct >= 100 {
			t.Errorf("%s: uptime %v with %d ms offline", tc.p, r.UptimePct, r.OfflineMS)
		}
		if !strings.Contains(page, "Not recorded") {
			t.Errorf("%s: coverage should read Not recorded", tc.p)
		}
		if !strings.Contains(page, "0.9.8") || !strings.Contains(page, "UTC&#43;01:00") {
			t.Errorf("%s: version or zone missing from the footer", tc.p)
		}
	}
}

func TestEmptyReport(t *testing.T) {
	r, err := Build(&fixture{}, fixtureOptions(Period7d))
	if err != nil {
		t.Fatal(err)
	}
	if !r.NoData() {
		t.Error("an empty source should report no data")
	}
	var buf bytes.Buffer
	if err := Render(&buf, r); err != nil {
		t.Fatal(err)
	}
	checkPage(t, "empty", buf.String(), r)
}

func TestSourceErrorsAreReturned(t *testing.T) {
	for _, call := range []string{"events", "rollups", "profiles", "system"} {
		_, err := Build(&fixture{failOn: call}, fixtureOptions(Period7d))
		if err == nil {
			t.Errorf("a failing %s query was ignored", call)
		}
	}
	if _, err := Build(nil, fixtureOptions(Period7d)); err == nil {
		t.Error("nil source accepted")
	}
	o := fixtureOptions(Period("1y"))
	if _, err := Build(&fixture{}, o); err == nil {
		t.Error("unknown period accepted")
	}
}

func TestHostileTextIsEscaped(t *testing.T) {
	f := newFixture(8)
	f.sys = append(f.sys, netenv.SystemEvent{ID: 9999, Timestamp: ago(30), Kind: netenv.SysEventNetworkChange, Detail: `<script>alert(1)</script>"><img src=x onerror=alert(2)>`})
	for i := range f.rollups {
		f.rollups[i].Address = `https://evil.example/<script>alert(3)</script>`
	}
	o := fixtureOptions(Period7d)
	o.Version = `<b>9</b>`
	o.Network.Interface = `"><svg onload=alert(4)>`
	page := render(t, f, o)
	// The page has one script of its own, and no tag from the hostile text.
	if n := strings.Count(page, "<script"); n != 1 {
		t.Errorf("page has %d script tags, want its own one", n)
	}
	for _, bad := range []string{"<img src=x", "<svg onload", "<b>9</b>", "alert(3)</script>"} {
		if strings.Contains(page, bad) {
			t.Errorf("unescaped text %q reached the page", bad)
		}
	}
}

func TestPooledQuantile(t *testing.T) {
	// One minute: the quantiles of the stored points come back.
	d := minuteDist{n: 10, min: 10_000, p50: 20_000, p95: 40_000, max: 80_000}
	for q, want := range map[float64]float64{0.5: 20_000, 0.95: 40_000} {
		if got := pooledQuantile([]minuteDist{d}, q); math.Abs(got-want) > 100 {
			t.Errorf("q%.2f = %v, want about %v", q, got, want)
		}
	}
	// A slow minute with many probes pulls the pooled median up, a quiet one
	// with few does not.
	fast := minuteDist{n: 1, min: 5_000, p50: 5_000, p95: 6_000, max: 7_000}
	slow := minuteDist{n: 100, min: 50_000, p50: 60_000, p95: 70_000, max: 90_000}
	if got := pooledQuantile([]minuteDist{fast, slow}, 0.5); got < 50_000 {
		t.Errorf("median %v ignored the weight of the slow minute", got)
	}
	if got := pooledQuantile(nil, 0.5); got != 0 {
		t.Errorf("no minutes gave %v", got)
	}
	// Out-of-order stored points are tolerated.
	got, ok := distOf(store.RollupRow{RollupRecord: store.RollupRecord{OK: 3, MinUS: 9000, P50US: 5000, P95US: 4000, MaxUS: 3000}})
	if !ok || got.min > got.p50 || got.p95 < got.p50 || got.max < got.p95 {
		t.Errorf("distOf left points out of order: %+v", got)
	}
	if _, ok := distOf(store.RollupRow{}); ok {
		t.Error("a minute with no answers has a distribution")
	}
}

func TestCauseOf(t *testing.T) {
	cases := []struct {
		class detector.Classification
		flags int
		want  Cause
	}{
		{detector.ClassWAN, 0, CauseWAN},
		{detector.ClassGateway, 0, CauseLocal},
		{detector.ClassDNSAll, 0, CauseDNS},
		{detector.ClassHTTP, 0, CauseHTTP},
		{detector.ClassWAN, detector.EventFlagPostResume, CauseWake},
		{detector.ClassWAN, detector.EventFlagVPN, CauseVPN},
		{detector.ClassWAN, detector.EventFlagPostResume | detector.EventFlagVPN, CauseWake},
	}
	for _, c := range cases {
		if got := causeOf(c.class, c.flags); got != c.want {
			t.Errorf("causeOf(%q, %d) = %v, want %v", c.class, c.flags, got, c.want)
		}
	}
	if CauseWAN.Local() || !CauseWake.Local() || !CauseVPN.Local() || !CauseLocal.Local() {
		t.Error("Local() is wrong")
	}
	if CauseWAN.Label() != "ISP / WAN drop" {
		t.Errorf("label = %q", CauseWAN.Label())
	}
}

func TestOutageBuckets(t *testing.T) {
	f := &fixture{}
	mk := func(id int64, mask, flags int, router float64) detector.Event {
		return outage(id, ago(40-float64(id)), 30_000, mask, flags, router, 0)
	}
	f.events = []detector.Event{
		mk(1, lTCP|lDNS, 0, 100),                            // upstream
		mk(2, lTCP|lDNS, 0, 60),                             // unclear
		mk(3, lTCP|lDNS, detector.EventFlagPostResume, 100), // local, woke
		mk(4, lGW, 0, 0),                                    // local, router
	}
	r, err := Build(f, fixtureOptions(Period7d))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Upstream) != 1 || len(r.Unclear) != 1 || len(r.Local) != 2 {
		t.Fatalf("buckets: upstream %d unclear %d local %d", len(r.Upstream), len(r.Unclear), len(r.Local))
	}
	if r.RouterOK != 1 {
		t.Errorf("RouterOK = %d, want 1", r.RouterOK)
	}
	if r.OfflineMS != 4*30_000 {
		t.Errorf("offline = %d ms", r.OfflineMS)
	}
	checkPage(t, "buckets", render(t, f, fixtureOptions(Period7d)), r)
}

func TestSleepGapsAreReadFromSystemEvents(t *testing.T) {
	f := &fixture{}
	f.sys = []netenv.SystemEvent{
		{ID: 1, Timestamp: ago(10), Kind: netenv.SysEventSuspend, Detail: "gap of 2h30m0s detected"},
		{ID: 2, Timestamp: ago(30), Kind: netenv.SysEventSuspend, Detail: "gap of 5s detected"},   // too short
		{ID: 3, Timestamp: ago(20), Kind: netenv.SysEventSuspend, Detail: "no length given here"}, // unreadable
	}
	r, err := Build(f, fixtureOptions(Period7d))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Gaps) != 1 {
		t.Fatalf("got %d gaps, want 1: %+v", len(r.Gaps), r.Gaps)
	}
	if r.GapTotal != 150*time.Minute {
		t.Errorf("gap total %v, want 2h30m", r.GapTotal)
	}
}

func TestLongLogPaginates(t *testing.T) {
	f := &fixture{}
	for i := int64(1); i <= 400; i++ {
		f.events = append(f.events, outage(i, ago(float64(i)/3), 8_000, lTCP|lDNS, 0, 100, 0))
	}
	f.events = append(f.events, outage(900, ago(2), 20_000, lGW, 0, 0, 0))
	r, err := Build(f, fixtureOptions(Period7d))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Log.Pages) < 5 {
		t.Fatalf("400 outages fit on %d log pages", len(r.Log.Pages))
	}
	seen := map[int64]int{}
	for i, pg := range r.Log.Pages {
		if (i == 0) != pg.Intro {
			t.Errorf("page %d: intro = %v", i, pg.Intro)
		}
		for _, s := range pg.Sections {
			for _, o := range s.Rows {
				seen[o.ID]++
			}
		}
	}
	if len(seen) != 401 {
		t.Errorf("log lists %d distinct outages, want 401", len(seen))
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("outage %d listed %d times", id, n)
		}
	}
	var tail int
	for _, pg := range r.Log.Pages {
		tail += len(pg.Tail)
	}
	if tail != len(logTail) {
		t.Errorf("%d closing blocks placed, want %d", tail, len(logTail))
	}
	checkPage(t, "long", render(t, f, fixtureOptions(Period7d)), r)
}

func TestEventCapIsReported(t *testing.T) {
	f := &fixture{}
	for i := int64(1); i <= maxEvents+50; i++ {
		f.events = append(f.events, detector.Event{ID: i, Kind: detector.EventKindBlip, Classification: detector.ClassWAN, StartMS: ago(float64(i) / 200), DurationMS: ptr(1000), EndMS: ptr(ago(float64(i)/200) + 1000), LayersDown: lTCP})
	}
	r, err := Build(f, fixtureOptions(Period7d))
	if err != nil {
		t.Fatal(err)
	}
	if !r.Truncated {
		t.Error("hitting the event cap was not reported")
	}
}

func TestFormatters(t *testing.T) {
	for in, want := range map[int64]string{500: "0.5 s", 9_000: "9.0 s", 10_000: "10 s", 65_000: "1 min 05 s", 3_660_000: "1 h 01 min"} {
		if got := fmtDur(in); got != want {
			t.Errorf("fmtDur(%d) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[int64]string{20_000: "20 s", 72_000: "1.2 min", 1_200_000: "20 min"} {
		if got := fmtMinutes(in); got != want {
			t.Errorf("fmtMinutes(%d) = %q, want %q", in, got, want)
		}
	}
	if got := fmtUptime(99.999, 1000); got != "99.99" {
		t.Errorf("uptime rounded up to %q while offline", got)
	}
	if got := fmtUptime(100, 0); got != "100.00" {
		t.Errorf("uptime = %q", got)
	}
	if fmtPct(100) != "100%" || fmtPct(96.66) != "96.7%" {
		t.Errorf("fmtPct: %q %q", fmtPct(100), fmtPct(96.66))
	}
	if got := truncate("日本語のとても長い名前", 5); !strings.HasPrefix(got, "日本語の") || strings.ContainsRune(got, '�') {
		t.Errorf("truncate cut a character: %q", got)
	}
	if esc(`<a href="x">&`) != "&lt;a href=&#34;x&#34;&gt;&amp;" {
		t.Errorf("esc = %q", esc(`<a href="x">&`))
	}
}

func TestCheckNames(t *testing.T) {
	cases := []struct{ layer, addr, label, check, target string }{
		{"gateway", "192.168.1.1", "", "Router", "192.168.1.1"},
		{"wan_tcp", "1.1.1.1:443", "", "TCP :443", "1.1.1.1"},
		{"wan_icmp", "9.9.9.9", "", "Ping", "9.9.9.9"},
	}
	for _, c := range cases {
		check, target := checkNames(c.layer, c.addr, c.label)
		if check != c.check || target != c.target {
			t.Errorf("checkNames(%q, %q) = %q, %q; want %q, %q", c.layer, c.addr, check, target, c.check, c.target)
		}
	}
}

func TestUnspecifiedISPHopIsNotListed(t *testing.T) {
	f := &fixture{}
	f.sys = []netenv.SystemEvent{
		{ID: 1, Timestamp: ago(30), Kind: netenv.SysEventISPHopChange, Detail: "isp hop discovered at 0.0.0.0 (ttl=3)"},
		{ID: 2, Timestamp: ago(20), Kind: netenv.SysEventISPHopChange, Detail: "isp hop discovered at 198.51.100.9 (ttl=3)"},
	}
	r, err := Build(f, fixtureOptions(Period7d))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Sys) != 1 || r.Sys[0].Detail != "found at 198.51.100.9" {
		t.Fatalf("system rows = %+v, want only the real hop", r.Sys)
	}
}
