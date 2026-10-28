package server_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/aaronburt/netscan/internal/config"
	"github.com/aaronburt/netscan/internal/detector"
	"github.com/aaronburt/netscan/internal/hub"
	"github.com/aaronburt/netscan/internal/netenv"
	"github.com/aaronburt/netscan/internal/probe"
	"github.com/aaronburt/netscan/internal/scheduler"
	"github.com/aaronburt/netscan/internal/server"
	"github.com/aaronburt/netscan/internal/store"
)

func TestProfileHistoryEndpoint(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("NETSCAN_DATA_DIR", tmpDir)

	db, err := store.OpenDB(filepath.Join(tmpDir, "profiles.db"))
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := store.InitSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	cfg := config.DefaultConfig()
	cfg.HTTP.Port = 19096
	writer := store.NewStoreWriter(db, cfg)
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

	// Standard ran for half an hour, then Lax has been running since.
	start := time.Now().UTC().Add(-time.Hour)
	history, err := store.NewProfileHistory(db, writer, start)
	if err != nil {
		t.Fatalf("failed to start profile history: %v", err)
	}
	history.Switch(config.Standard(), start)
	history.Switch(config.Lax(), start.Add(30*time.Minute))
	writer.FlushSync()

	det := detector.NewDetector(cfg, config.Standard(), nil, nil)
	reg := probe.NewTargetRegistry(config.Standard())
	outCh := make(chan probe.ProbeResult, 10)
	sched := scheduler.NewScheduler(config.Standard(), reg, outCh, "test", nil)
	ne := netenv.NewNetEnv(reg, make(chan netenv.SystemEvent, 10))
	srv, err := server.NewServer(cfg, store.NewStoreReader(db), writer, det, hub.NewHub(), sched, ne, reg, "test")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer srv.Stop()

	url := fmt.Sprintf("http://127.0.0.1:%d/api/profiles/history", srv.Port())
	res, err := http.Get(url)
	if err != nil {
		t.Fatalf("failed to get history: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}

	var body struct {
		Profiles []store.ProfileRecord `json:"profiles"`
		Usage    []store.ProfileUse    `json:"usage"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if len(body.Profiles) != 2 || body.Profiles[0].Profile != config.ProfileStandard || body.Profiles[1].Profile != config.ProfileLax {
		t.Fatalf("profiles = %+v, want standard then lax", body.Profiles)
	}
	if len(body.Usage) != 2 || body.Usage[1].ID != config.ProfileLax || body.Usage[1].Estimate.ProbesPerSec == 0 {
		t.Fatalf("usage = %+v, want two entries with load estimates", body.Usage)
	}

	// PUT gets past the CSRF check, which only covers POST, so this reaches the
	// handler's own method check.
	req, err := http.NewRequest(http.MethodPut, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	bad, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to put history: %v", err)
	}
	defer bad.Body.Close()
	if bad.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("PUT status = %d, want 405", bad.StatusCode)
	}
}
