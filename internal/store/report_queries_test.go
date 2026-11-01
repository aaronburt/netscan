package store_test

import (
	"testing"
	"time"

	"github.com/aaronburt/netscan/internal/netenv"
	"github.com/aaronburt/netscan/internal/probe"
	"github.com/aaronburt/netscan/internal/store"
)

func TestForEachRollupAndSystemEvents(t *testing.T) {
	db, writer := openProfileDB(t)

	// Old enough that the writer treats the minutes as finished.
	base := time.Now().Add(-3 * time.Hour).Truncate(time.Minute)
	gw := probe.Target{ID: 1, Layer: probe.LayerGateway, Address: "192.168.1.1", Label: "Router"}
	wan := probe.Target{ID: 2, Layer: probe.LayerWANICMP, Address: "1.1.1.1", Label: "Ping"}
	writer.QueueTarget(gw)
	writer.QueueTarget(wan)
	for m := 0; m < 3; m++ {
		for i := 0; i < 4; i++ {
			at := base.Add(time.Duration(m)*time.Minute + time.Duration(i)*time.Second).UnixMilli()
			for _, tg := range []probe.Target{gw, wan} {
				writer.QueueSample(probe.ProbeResult{TargetID: tg.ID, Target: tg, Seq: uint64(m*10 + i), SendTimeUTC: at, Reached: true, OK: true, RTTUS: 10000 + int64(i)*1000})
			}
		}
	}
	writer.QueueSystemEvent(netenv.SystemEvent{Timestamp: base.Add(2 * time.Hour).UnixMilli(), Kind: netenv.SysEventResume, Detail: "later"})
	writer.QueueSystemEvent(netenv.SystemEvent{Timestamp: base.Add(time.Hour).UnixMilli(), Kind: netenv.SysEventSuspend, Detail: "earlier"})
	writer.FlushSync()

	reader := store.NewStoreReader(db)
	from, to := base.Add(-time.Hour).UnixMilli(), time.Now().UnixMilli()

	var rows []store.RollupRow
	if err := reader.ForEachRollup(from, to, func(r store.RollupRow) { rows = append(rows, r) }); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 6 {
		t.Fatalf("got %d rollup rows, want 6 (3 minutes x 2 targets)", len(rows))
	}
	addr := map[int]string{}
	for i, r := range rows {
		addr[r.TargetID] = r.Address
		if r.Sent != 4 || r.OK != 4 {
			t.Errorf("row %d: sent %d ok %d, want 4 and 4", i, r.Sent, r.OK)
		}
		if i > 0 && r.BucketMS < rows[i-1].BucketMS {
			t.Errorf("rows are not in time order")
		}
	}
	if addr[1] != "192.168.1.1" || addr[2] != "1.1.1.1" {
		t.Errorf("addresses not joined from targets: %v", addr)
	}

	// The older query returns the same rows.
	old, err := reader.QueryRollups(from, to, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(old) != len(rows) {
		t.Errorf("QueryRollups returned %d rows, ForEachRollup %d", len(old), len(rows))
	}
	if one, _ := reader.QueryRollups(from, to, 2, ""); len(one) != 3 {
		t.Errorf("filter by target gave %d rows, want 3", len(one))
	}

	// A window with nothing in it calls back never.
	called := false
	_ = reader.ForEachRollup(0, 1000, func(store.RollupRow) { called = true })
	if called {
		t.Error("callback ran for an empty window")
	}

	sys, err := reader.QuerySystemEvents(from, to)
	if err != nil {
		t.Fatal(err)
	}
	if len(sys) != 2 || sys[0].Detail != "earlier" || sys[1].Detail != "later" {
		t.Fatalf("system events = %+v, want earlier then later", sys)
	}
	if sys, _ := reader.QuerySystemEvents(base.Add(90*time.Minute).UnixMilli(), to); len(sys) != 1 || sys[0].Detail != "later" {
		t.Errorf("window filter wrong: %+v", sys)
	}
}
