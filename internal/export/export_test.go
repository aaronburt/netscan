package export_test

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aaronburt/netscan/internal/detector"
	"github.com/aaronburt/netscan/internal/export"
	"github.com/aaronburt/netscan/internal/store"
)

func sampleEvents() []detector.Event {
	end := int64(1_700_000_004_000)
	dur := int64(4000)
	uncert := int64(1000)
	return []detector.Event{
		{ID: 1, Kind: detector.EventKindOutage, Classification: detector.ClassWAN, StartMS: 1_700_000_000_000, StartUncertMS: 1000, EndMS: &end, EndUncertMS: &uncert, DurationMS: &dur, GatewayOKPct: 100},
		{ID: 2, Kind: detector.EventKindBlip, Classification: detector.ClassWAN, StartMS: 1_700_000_100_000, StartUncertMS: 1000},
	}
}

func readCSV(t *testing.T, buf *bytes.Buffer) [][]string {
	t.Helper()
	rows, err := csv.NewReader(buf).ReadAll()
	if err != nil {
		t.Fatalf("invalid csv: %v", err)
	}
	return rows
}

func TestExportEventsCSV(t *testing.T) {
	var buf bytes.Buffer
	if err := export.ExportEventsCSV(&buf, sampleEvents(), nil); err != nil {
		t.Fatal(err)
	}
	rows := readCSV(t, &buf)
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want header + 2", len(rows))
	}
	if !strings.Contains(strings.Join(rows[1], ","), "outage") {
		t.Fatalf("first event row missing kind: %v", rows[1])
	}
}

func TestExportSamplesCSV(t *testing.T) {
	var buf bytes.Buffer
	samples := []store.SampleRecord{
		{TimestampMS: 1_700_000_000_000, TargetID: 10, Layer: "wan_icmp", Reached: true, OK: true, RTTUS: 20000},
		{TimestampMS: 1_700_000_001_000, TargetID: 20, Layer: "wan_tcp", ErrCode: 1, ErrText: "timeout"},
	}
	if err := export.ExportSamplesCSV(&buf, samples); err != nil {
		t.Fatal(err)
	}
	if rows := readCSV(t, &buf); len(rows) != 3 {
		t.Fatalf("rows = %d, want header + 2", len(rows))
	}
}

func TestExportRollupsCSV(t *testing.T) {
	var buf bytes.Buffer
	rollups := []store.RollupRecord{{BucketMS: 1_700_000_000_000, TargetID: 10, Layer: "wan_icmp", Sent: 60, Reached: 60, OK: 60, P50US: 20000}}
	if err := export.ExportRollupsCSV(&buf, rollups); err != nil {
		t.Fatal(err)
	}
	if rows := readCSV(t, &buf); len(rows) != 2 {
		t.Fatalf("rows = %d, want header + 1", len(rows))
	}
}

func TestExportJSONAndJSONL(t *testing.T) {
	rows := []store.RollupRecord{{TargetID: 10, Sent: 1}, {TargetID: 11, Sent: 2}}

	var buf bytes.Buffer
	meta := export.ExportMeta{FromMS: 1, ToMS: 2, AppVersion: "test"}
	if err := export.ExportJSON(&buf, meta, rows); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Meta export.ExportMeta    `json:"meta"`
		Rows []store.RollupRecord `json:"rows"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, buf.String())
	}

	buf.Reset()
	if err := export.ExportJSONL(&buf, rows); err != nil {
		t.Fatal(err)
	}
	if lines := strings.Split(strings.TrimSpace(buf.String()), "\n"); len(lines) != 2 {
		t.Fatalf("jsonl lines = %d, want 2", len(lines))
	}
}

func TestGenerateISPReport(t *testing.T) {
	var buf bytes.Buffer
	stats := store.StatsSummary{Outages24H: 1, Outages7D: 2, Blips7D: 3, CoveragePct: 99.5}
	meta := export.ExportMeta{FromMS: 1_700_000_000_000, ToMS: 1_700_600_000_000, AppVersion: "1.2.3", NetworkLabel: "home"}
	if err := export.GenerateISPReport(&buf, meta, sampleEvents(), stats, nil, "192.168.1.1", "10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"ISP EVIDENCE REPORT", "1.2.3", "192.168.1.1", "10.0.0.1", "99.5"} {
		if !strings.Contains(out, want) {
			t.Fatalf("report missing %q", want)
		}
	}

	buf.Reset()
	if err := export.GenerateISPReport(&buf, meta, nil, store.StatsSummary{}, nil, "N/A", "N/A"); err != nil {
		t.Fatal(err)
	}
}

func TestISPReportKeepsBlipsOutOfISPIncidents(t *testing.T) {
	var buf bytes.Buffer
	dur := int64(0)
	events := []detector.Event{{
		ID: 1, Kind: detector.EventKindBlip, Classification: detector.ClassICMPFiltered,
		StartMS: 1_700_000_100_000, LayersDown: detector.LayerMaskWANICMP, DurationMS: &dur, GatewayOKPct: 100,
	}}
	meta := export.ExportMeta{FromMS: 1_700_000_000_000, ToMS: 1_700_600_000_000}
	if err := export.GenerateISPReport(&buf, meta, events, store.StatsSummary{Blips7D: 1}, nil, "gw", "hop"); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "No upstream ISP-attributable outages recorded") {
		t.Fatalf("blip was listed as an ISP incident:\n%s", out)
	}
	if !strings.Contains(out, "BRIEF PROBE FAILURES") || !strings.Contains(out, "ICMP") {
		t.Fatalf("blip section missing:\n%s", out)
	}
}
