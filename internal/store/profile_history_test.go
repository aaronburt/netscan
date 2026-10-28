package store_test

import (
	"context"
	"database/sql"
	"math"
	"path/filepath"
	"testing"
	"time"

	"github.com/aaronburt/netscan/internal/config"
	"github.com/aaronburt/netscan/internal/detector"
	"github.com/aaronburt/netscan/internal/store"
)

// openProfileDB returns a schema 2 database with its writer running. The writer
// is stopped when the test ends.
func openProfileDB(t *testing.T) (*sql.DB, *store.StoreWriter) {
	t.Helper()
	db, err := store.OpenDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := store.InitSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	writer := store.NewStoreWriter(db, config.DefaultConfig())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = writer.Run(ctx)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return db, writer
}

func ptrTo(v int64) *int64 {
	return &v
}

func TestProfileHistoryRecordsEachSwitch(t *testing.T) {
	db, writer := openProfileDB(t)
	t0 := time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC)

	history, err := store.NewProfileHistory(db, writer, t0)
	if err != nil {
		t.Fatal(err)
	}
	standard := history.Switch(config.Standard(), t0)
	aggressive := history.Switch(config.Aggressive(), t0.Add(time.Hour))
	again := history.Switch(config.Aggressive(), t0.Add(2*time.Hour))
	history.Close(t0.Add(3 * time.Hour))
	writer.FlushSync()

	if aggressive == standard {
		t.Fatalf("a switch should get a new row id, got %d twice", standard)
	}
	if again != aggressive {
		t.Fatalf("switching to unchanged settings gave row %d, want %d", again, aggressive)
	}

	rows, err := store.NewStoreReader(db).QueryProfiles(t0.UnixMilli(), t0.Add(4*time.Hour).UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %+v, want two", rows)
	}
	if rows[0].Profile != config.ProfileStandard || rows[0].EndMS == nil || *rows[0].EndMS != t0.Add(time.Hour).UnixMilli() {
		t.Fatalf("first row = %+v, want standard ending at the switch", rows[0])
	}
	if rows[1].Profile != config.ProfileAggressive || rows[1].ProfileName != "Aggressive" || rows[1].EndMS == nil || *rows[1].EndMS != t0.Add(3*time.Hour).UnixMilli() {
		t.Fatalf("second row = %+v, want aggressive ending at shutdown", rows[1])
	}
	if rows[1].SettingsHash == "" || rows[1].SettingsJSON == "" {
		t.Fatalf("second row has no settings snapshot: %+v", rows[1])
	}
}

// A run that ended without closing its row leaves that row open. The next run
// closes it where it starts, so an open row always means the monitor is running.
func TestRestartClosesRowLeftOpenByACrash(t *testing.T) {
	db, writer := openProfileDB(t)
	t0 := time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC)

	crashed, err := store.NewProfileHistory(db, writer, t0)
	if err != nil {
		t.Fatal(err)
	}
	first := crashed.Switch(config.Standard(), t0)
	writer.FlushSync()

	t1 := t0.Add(time.Hour)
	restarted, err := store.NewProfileHistory(db, writer, t1)
	if err != nil {
		t.Fatal(err)
	}
	second := restarted.Switch(config.Lax(), t1)
	writer.FlushSync()

	if second <= first {
		t.Fatalf("the restarted run reused row id %d, last used %d", second, first)
	}
	rows, err := store.NewStoreReader(db).QueryProfiles(0, t1.Add(time.Hour).UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].EndMS == nil || *rows[0].EndMS != t1.UnixMilli() {
		t.Fatalf("rows = %+v, want the crashed row closed at restart", rows)
	}
	if rows[1].EndMS != nil {
		t.Fatalf("the row for the restarted run should be open: %+v", rows[1])
	}
}

// Resetting history removes finished profile rows but keeps the open one, which
// the running monitor still writes events under.
func TestResetHistoryKeepsTheOpenProfileRow(t *testing.T) {
	db, writer := openProfileDB(t)
	t0 := time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC)

	history, err := store.NewProfileHistory(db, writer, t0)
	if err != nil {
		t.Fatal(err)
	}
	history.Switch(config.Standard(), t0)
	open := history.Switch(config.Lax(), t0.Add(time.Hour))
	writer.FlushSync()

	if err := writer.ResetHistory(); err != nil {
		t.Fatalf("reset failed: %v", err)
	}
	rows, err := store.NewStoreReader(db).QueryProfiles(0, t0.Add(2*time.Hour).UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].ID != open || rows[0].EndMS != nil {
		t.Fatalf("after reset rows = %+v, want only the open row %d", rows, open)
	}
}

// A database from before profile history gains the profile_log table and the
// events.profile_id column in place. Its events keep working and read as no
// profile.
func TestSchemaUpgradesAVersionOneDatabase(t *testing.T) {
	db, err := store.OpenDB(filepath.Join(t.TempDir(), "v1.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	for _, q := range []string{
		`CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);`,
		`INSERT INTO meta (key, value) VALUES ('schema_version', '1');`,
		`CREATE TABLE events (
			id INTEGER PRIMARY KEY,
			kind TEXT NOT NULL,
			classification TEXT NOT NULL,
			network_id INTEGER,
			start_ms INTEGER NOT NULL,
			start_uncert_ms INTEGER NOT NULL,
			end_ms INTEGER,
			end_uncert_ms INTEGER,
			duration_ms INTEGER,
			layers_down INTEGER NOT NULL DEFAULT 0,
			flags INTEGER NOT NULL DEFAULT 0,
			gateway_ok_pct REAL,
			isp_hop_ok_pct REAL,
			context TEXT
		);`,
		`INSERT INTO events (id, kind, classification, network_id, start_ms, start_uncert_ms, end_ms, duration_ms)
			VALUES (1, 'outage', 'WAN', 1, 1700000000000, 1000, 1700000004000, 4000);`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("setup: %v", err)
		}
	}

	if err := store.InitSchema(db); err != nil {
		t.Fatalf("upgrade failed: %v", err)
	}
	if err := store.InitSchema(db); err != nil {
		t.Fatalf("opening an upgraded database again failed: %v", err)
	}

	var version string
	if err := db.QueryRow(`SELECT value FROM meta WHERE key = 'schema_version';`).Scan(&version); err != nil || version != "2" {
		t.Fatalf("schema_version = %q, %v; want 2", version, err)
	}

	reader := store.NewStoreReader(db)
	events, err := reader.QueryEvents(store.EventFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].ID != 1 || events[0].ProfileID != 0 {
		t.Fatalf("old event after upgrade = %+v, want event 1 with no profile", events)
	}

	writer := store.NewStoreWriter(db, config.DefaultConfig())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = writer.Run(ctx)
		close(done)
	}()
	defer func() {
		cancel()
		<-done
	}()

	writer.QueueEvent(detector.Event{ID: 2, Kind: detector.EventKindBlip, Classification: detector.ClassWAN, StartMS: 1700000100000, StartUncertMS: 1000, ProfileID: 5})
	writer.FlushSync()
	detail, err := reader.QueryEventByID(2)
	if err != nil {
		t.Fatal(err)
	}
	if detail.Event.ProfileID != 5 {
		t.Fatalf("new event profile = %d, want 5", detail.Event.ProfileID)
	}
}

func TestSummarizeProfiles(t *testing.T) {
	standardHash, standardJSON := config.Standard().Fingerprint()
	edited := config.Standard()
	edited.Intervals.NormalMS = 2000
	editedHash, editedJSON := edited.Fingerprint()

	rows := []store.ProfileRecord{
		{ID: 1, StartMS: 0, EndMS: ptrTo(2000), Profile: "standard", ProfileName: "Standard", SettingsHash: standardHash, SettingsJSON: standardJSON},
		{ID: 2, StartMS: 2000, EndMS: ptrTo(6000), Profile: "standard", ProfileName: "Standard", SettingsHash: editedHash, SettingsJSON: editedJSON},
		{ID: 3, StartMS: 6000, Profile: "standard", ProfileName: "Standard", SettingsHash: standardHash, SettingsJSON: standardJSON},
		{ID: 4, StartMS: 20000, Profile: "lax", ProfileName: "Lax", SettingsHash: "later", SettingsJSON: "{}"},
	}
	// The period is 1s to 10s. Row 3 is still open, so it runs to the end.
	usage := store.SummarizeProfiles(rows, 1000, 10000)

	if len(usage) != 2 {
		t.Fatalf("usage = %+v, want the standard settings and the edited ones", usage)
	}
	if usage[0].SettingsHash != standardHash || usage[0].DurationMS != 5000 {
		t.Fatalf("standard = %+v, want 5000ms across rows 1 and 3", usage[0])
	}
	if usage[1].SettingsHash != editedHash || usage[1].DurationMS != 4000 {
		t.Fatalf("edited = %+v, want 4000ms", usage[1])
	}
	if sum := usage[0].SharePct + usage[1].SharePct; math.Abs(sum-100) > 1e-9 {
		t.Fatalf("shares add up to %.3f, want 100", sum)
	}
	if usage[0].Estimate.ProbesPerSec == 0 {
		t.Fatal("standard has no load estimate")
	}
}

func TestSummarizeProfilesWithoutHistory(t *testing.T) {
	if usage := store.SummarizeProfiles(nil, 0, 1000); usage == nil || len(usage) != 0 {
		t.Fatalf("usage = %#v, want an empty list", usage)
	}
}

func TestSummarizeProfilesSnapshotThatDoesNotParse(t *testing.T) {
	rows := []store.ProfileRecord{{ID: 1, StartMS: 0, Profile: "odd", ProfileName: "Odd", SettingsHash: "h", SettingsJSON: "not json"}}
	usage := store.SummarizeProfiles(rows, 0, 1000)
	if len(usage) != 1 || usage[0].DurationMS != 1000 || usage[0].SharePct != 100 || usage[0].Estimate.ProbesPerSec != 0 {
		t.Fatalf("usage = %+v, want the time counted with a zero estimate", usage)
	}
}
