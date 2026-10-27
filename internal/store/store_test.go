package store_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/aaronburt/netscan/internal/config"
	"github.com/aaronburt/netscan/internal/detector"
	"github.com/aaronburt/netscan/internal/probe"
	"github.com/aaronburt/netscan/internal/store"
)

func TestStoreLifecycle(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := store.OpenDB(dbPath)
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer db.Close()

	if err := store.InitSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	if err := store.QuickCheck(db); err != nil {
		t.Fatalf("quick check failed: %v", err)
	}

	cfg := config.DefaultConfig()
	writer := store.NewStoreWriter(db, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		_ = writer.Run(ctx)
	}()

	now := time.Now().UTC()
	target := probe.Target{
		ID:      10,
		Layer:   probe.LayerWANICMP,
		Address: "1.1.1.1",
		Label:   "Cloudflare ICMP",
	}
	writer.QueueTarget(target)

	for i := 0; i < 10; i++ {
		res := probe.ProbeResult{
			TargetID:    10,
			Target:      target,
			Seq:         uint64(i + 1),
			SendTimeUTC: now.Add(time.Duration(i) * time.Second).UnixMilli(),
			Reached:     true,
			OK:          true,
			RTTUS:       15000 + int64(i*500),
		}
		writer.QueueSample(res)
	}

	startMS := now.UnixMilli()
	endMS := now.Add(5 * time.Second).UnixMilli()
	durMS := int64(5000)
	evt := detector.Event{
		ID:             1,
		Kind:           detector.EventKindOutage,
		Classification: detector.ClassWAN,
		StartMS:        startMS,
		EndMS:          &endMS,
		DurationMS:     &durMS,
		GatewayOKPct:   100.0,
	}
	writer.QueueEvent(evt)

	writer.FlushSync()
	cancel()

	reader := store.NewStoreReader(db)
	events, err := reader.QueryEvents(store.EventFilter{})
	if err != nil {
		t.Fatalf("failed to query events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Classification != detector.ClassWAN {
		t.Fatalf("expected ClassWAN, got %s", events[0].Classification)
	}

	samples, err := reader.QuerySamplesRange(now.UnixMilli()-1000, now.Add(15*time.Second).UnixMilli(), 10, false, 100)
	if err != nil {
		t.Fatalf("failed to query samples: %v", err)
	}
	if len(samples) < 10 {
		t.Fatalf("expected at least 10 samples, got %d", len(samples))
	}
}

func TestCompactorPreservesEventWindows(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "compact.db")

	db, err := store.OpenDB(dbPath)
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer db.Close()

	if err := store.InitSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	cfg := config.DefaultConfig()
	cfg.Retention.RawPartitions = 1

	oldDay := time.Now().UTC().AddDate(0, 0, -3)
	oldTable := store.PartitionTableName(oldDay)
	if err := store.EnsurePartitionTable(db, oldTable); err != nil {
		t.Fatalf("failed to ensure old partition: %v", err)
	}

	startMS := oldDay.Add(12 * time.Hour).UnixMilli()
	endMS := oldDay.Add(12*time.Hour + 10*time.Second).UnixMilli()
	durMS := int64(10000)

	evt := detector.Event{
		ID:             100,
		Kind:           detector.EventKindOutage,
		Classification: detector.ClassWAN,
		StartMS:        startMS,
		EndMS:          &endMS,
		DurationMS:     &durMS,
	}
	writer := store.NewStoreWriter(db, cfg)
	writer.QueueEvent(evt)

	inWindowSample := probe.ProbeResult{
		TargetID:    10,
		SendTimeUTC: startMS + 2000,
		Reached:     false,
		OK:          false,
		RTTUS:       0,
	}
	outWindowSample := probe.ProbeResult{
		TargetID:    10,
		SendTimeUTC: oldDay.Add(2 * time.Hour).UnixMilli(),
		Reached:     true,
		OK:          true,
		RTTUS:       12000,
	}

	writer.QueueSample(inWindowSample)
	writer.QueueSample(outWindowSample)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		_ = writer.Run(ctx)
	}()
	writer.FlushSync()
	cancel()

	compactor := store.NewCompactor(cfg)
	if err := compactor.Compact(db, time.Now().UTC()); err != nil {
		t.Fatalf("compaction failed: %v", err)
	}

	reader := store.NewStoreReader(db)
	detail, err := reader.QueryEventByID(100)
	if err != nil {
		t.Fatalf("failed to query event detail: %v", err)
	}
	if len(detail.Samples) == 0 {
		t.Fatalf("expected in-window sample to be preserved in event_samples")
	}
	if detail.Samples[0].Tier != "event_window" {
		t.Fatalf("expected tier event_window, got %s", detail.Samples[0].Tier)
	}
}

func TestStoreResetHistory(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_reset.db")

	db, err := store.OpenDB(dbPath)
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	defer db.Close()

	if err := store.InitSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	cfg := config.DefaultConfig()
	writer := store.NewStoreWriter(db, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		_ = writer.Run(ctx)
	}()
	defer cancel()

	dur := int64(2000)
	evt := detector.Event{
		ID:             1,
		Kind:           detector.EventKindOutage,
		Classification: "wan",
		StartMS:        time.Now().UnixMilli() - 5000,
		DurationMS:     &dur,
	}
	writer.QueueEvent(evt)
	writer.FlushSync()

	reader := store.NewStoreReader(db)
	events, err := reader.QueryEvents(store.EventFilter{Limit: 10})
	if err != nil || len(events) == 0 {
		t.Fatalf("expected events before reset")
	}

	if err := writer.ResetHistory(); err != nil {
		t.Fatalf("ResetHistory failed: %v", err)
	}

	eventsAfter, err := reader.QueryEvents(store.EventFilter{Limit: 10})
	if err != nil {
		t.Fatalf("query after reset failed: %v", err)
	}
	if len(eventsAfter) != 0 {
		t.Fatalf("expected 0 events after reset, got %d", len(eventsAfter))
	}
}

// FlushSync used to block forever when called after Run had returned,
// which hung every shutdown path.
func TestFlushSyncAfterStopReturns(t *testing.T) {
	db, err := store.OpenDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	if err := store.InitSchema(db); err != nil {
		t.Fatalf("init schema: %v", err)
	}

	writer := store.NewStoreWriter(db, config.DefaultConfig())
	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() {
		_ = writer.Run(ctx)
		close(runDone)
	}()

	end := int64(2000)
	writer.QueueEvent(detector.Event{ID: 7, Kind: detector.EventKindOutage, Classification: detector.ClassWAN, StartMS: 1000, EndMS: &end})
	cancel()
	<-runDone

	flushed := make(chan struct{})
	go func() {
		writer.FlushSync()
		close(flushed)
	}()
	select {
	case <-flushed:
	case <-time.After(2 * time.Second):
		t.Fatal("FlushSync blocked after Run stopped")
	}

	maxID, err := store.NewStoreReader(db).MaxEventID()
	if err != nil {
		t.Fatalf("MaxEventID: %v", err)
	}
	if maxID != 7 {
		t.Fatalf("MaxEventID = %d, want 7", maxID)
	}
}

// Write failures used to be thrown away without a trace.
func TestWriteErrorsAreCounted(t *testing.T) {
	db, err := store.OpenDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := store.InitSchema(db); err != nil {
		t.Fatalf("init schema: %v", err)
	}
	writer := store.NewStoreWriter(db, config.DefaultConfig())
	_ = db.Close() // every write from here on fails

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = writer.Run(ctx) }()

	writer.QueueEvent(detector.Event{ID: 1, Kind: detector.EventKindBlip, Classification: detector.ClassWAN})
	writer.FlushSync()

	if st := writer.Stats(); st.WriteErrors == 0 || st.LastError == "" {
		t.Fatalf("expected a counted write error, got %+v", st)
	}
}

// A database written before ids were stable must keep its history attached to
// the same hosts when the host lists change.
func TestKnownTargetsKeepHistoryAcrossHostChanges(t *testing.T) {
	db, err := store.OpenDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := store.InitSchema(db); err != nil {
		t.Fatal(err)
	}

	// Legacy rows: positional ids for a customised ICMP list.
	for _, row := range []struct {
		id   int
		addr string
	}{{10, "10.1.1.1"}, {11, "1.1.1.1"}} {
		if _, err := db.Exec(`INSERT INTO targets (id, layer, address, label, first_seen_ms) VALUES (?, 'wan_icmp', ?, 'old', 0)`, row.id, row.addr); err != nil {
			t.Fatal(err)
		}
	}

	reader := store.NewStoreReader(db)
	known, err := reader.KnownTargets()
	if err != nil {
		t.Fatal(err)
	}
	if len(known) != 2 {
		t.Fatalf("got %d known targets, want 2", len(known))
	}

	prof := config.Standard()
	prof.Targets.WANICMP = []string{"1.1.1.1", "8.8.8.8", "10.1.1.1"}
	reg := probe.NewTargetRegistryWithIDs(prof, probe.NewIDAllocator(known))

	got := map[string]int{}
	for _, tg := range reg.GetWANICMP() {
		got[tg.Address] = tg.ID
	}
	if got["10.1.1.1"] != 10 || got["1.1.1.1"] != 11 {
		t.Fatalf("history ids moved: %v", got)
	}
	// 8.8.8.8's old id 11 now belongs to 1.1.1.1, so it gets a fresh one.
	if got["8.8.8.8"] < 1000 {
		t.Fatalf("8.8.8.8 id %d, want a fresh id >= 1000", got["8.8.8.8"])
	}

	// Persisting the registry must not relabel the existing ids.
	writer := store.NewStoreWriter(db, config.DefaultConfig())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = writer.Run(ctx); close(done) }()
	for _, tg := range reg.GetAllTargets() {
		writer.QueueTarget(tg)
	}
	time.Sleep(2500 * time.Millisecond)
	cancel()
	<-done

	var addr string
	if err := db.QueryRow(`SELECT address FROM targets WHERE id = 10`).Scan(&addr); err != nil || addr != "10.1.1.1" {
		t.Fatalf("id 10 = %q, %v; want 10.1.1.1", addr, err)
	}
}
