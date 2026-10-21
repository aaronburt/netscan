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
