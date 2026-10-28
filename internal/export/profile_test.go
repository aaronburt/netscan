package export_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/aaronburt/netscan/internal/config"
	"github.com/aaronburt/netscan/internal/detector"
	"github.com/aaronburt/netscan/internal/export"
	"github.com/aaronburt/netscan/internal/store"
)

func TestEventsCSVNamesTheProfileEachEventStartedUnder(t *testing.T) {
	events := []detector.Event{
		{ID: 1, Kind: detector.EventKindOutage, StartMS: 1_700_000_000_000},
		{ID: 2, Kind: detector.EventKindOutage, StartMS: 1_700_000_100_000, ProfileID: 5},
		{ID: 3, Kind: detector.EventKindBlip, StartMS: 1_700_000_200_000, ProfileID: 9},
	}
	profiles := []store.ProfileRecord{{ID: 5, ProfileName: "Office Wi-Fi"}}

	var buf bytes.Buffer
	if err := export.ExportEventsCSV(&buf, events, profiles); err != nil {
		t.Fatal(err)
	}
	rows := readCSV(t, &buf)
	col := len(rows[0]) - 1
	if rows[0][col] != "profile" {
		t.Fatalf("last header = %q, want profile", rows[0][col])
	}
	// No profile recorded reads as Standard. An id with no row in the period is unknown.
	want := []string{config.Standard().Name, "Office Wi-Fi", "unknown"}
	for i, name := range want {
		if got := rows[i+1][col]; got != name {
			t.Errorf("event %d profile = %q, want %q", i+1, got, name)
		}
	}
}

func TestISPReportListsTheMonitoringProfiles(t *testing.T) {
	meta := export.ExportMeta{FromMS: 1_700_000_000_000, ToMS: 1_700_600_000_000, AppVersion: "test"}
	standard := config.Standard().Estimate()
	lax := config.Lax().Estimate()

	var buf bytes.Buffer
	usage := []store.ProfileUse{{ID: "standard", Name: "Standard", SharePct: 100, Estimate: standard}}
	if err := export.GenerateISPReport(&buf, meta, sampleEvents(), store.StatsSummary{}, usage, "gw", "hop"); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"3. MONITORING PROFILE", "100.0%"} {
		if !strings.Contains(out, want) {
			t.Fatalf("report missing %q", want)
		}
	}
	if strings.Contains(out, "depend on the monitoring profile") {
		t.Fatal("a Standard-only period should not carry the profile note")
	}

	buf.Reset()
	usage = []store.ProfileUse{
		{ID: "standard", Name: "Standard", SharePct: 60, Estimate: standard},
		{ID: "lax", Name: "Lax", SharePct: 40, Estimate: lax},
	}
	if err := export.GenerateISPReport(&buf, meta, sampleEvents(), store.StatsSummary{}, usage, "gw", "hop"); err != nil {
		t.Fatal(err)
	}
	out = buf.String()
	for _, want := range []string{"Lax", "40.0%", "depend on the monitoring profile"} {
		if !strings.Contains(out, want) {
			t.Fatalf("report missing %q when two profiles were used:\n%s", want, out)
		}
	}
}

func TestISPReportWithoutProfileHistory(t *testing.T) {
	meta := export.ExportMeta{FromMS: 1_700_000_000_000, ToMS: 1_700_600_000_000}
	var buf bytes.Buffer
	if err := export.GenerateISPReport(&buf, meta, nil, store.StatsSummary{}, nil, "gw", "hop"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "No profile was recorded for this period") {
		t.Fatalf("report did not explain the missing profile history:\n%s", buf.String())
	}
}
