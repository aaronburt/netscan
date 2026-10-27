package server_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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
	"github.com/aaronburt/netscan/internal/updater"
)

func setupTestServer(t *testing.T) (*server.Server, string) {
	tmpDir := t.TempDir()
	t.Setenv("NETSCAN_DATA_DIR", tmpDir) // keep the port file out of the real data dir
	dbPath := filepath.Join(tmpDir, "srv.db")

	db, err := store.OpenDB(dbPath)
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})

	if err := store.InitSchema(db); err != nil {
		t.Fatalf("failed to init schema: %v", err)
	}

	cfg := config.DefaultConfig()
	cfg.HTTP.Port = 19095

	reader := store.NewStoreReader(db)
	writer := store.NewStoreWriter(db, cfg)
	det := detector.NewDetector(cfg, config.Standard(), nil, nil)
	h := hub.NewHub()
	reg := probe.NewTargetRegistry(config.Standard())
	outCh := make(chan probe.ProbeResult, 10)
	sched := scheduler.NewScheduler(config.Standard(), reg, outCh, "test", nil)
	ne := netenv.NewNetEnv(reg, make(chan netenv.SystemEvent, 10))

	srv, err := server.NewServer(cfg, reader, writer, det, h, sched, ne, reg, "test")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", srv.Port())
	return srv, baseURL
}

func TestServerHealthAndStatic(t *testing.T) {
	srv, baseURL := setupTestServer(t)
	defer srv.Stop()

	res, err := http.Get(baseURL + "/healthz")
	if err != nil {
		t.Fatalf("failed to get /healthz: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", res.StatusCode)
	}

	resIndex, err := http.Get(baseURL + "/")
	if err != nil {
		t.Fatalf("failed to get /: %v", err)
	}
	defer resIndex.Body.Close()
	body, _ := io.ReadAll(resIndex.Body)
	if !strings.Contains(string(body), "NetScan") {
		t.Fatalf("index HTML missing NetScan title")
	}

	resCSS, err := http.Get(baseURL + "/styles.css")
	if err != nil {
		t.Fatalf("failed to get /styles.css: %v", err)
	}
	defer resCSS.Body.Close()
	if resCSS.Header.Get("Content-Type") != "text/css; charset=utf-8" {
		t.Fatalf("expected text/css, got %s", resCSS.Header.Get("Content-Type"))
	}

	resIcon, err := http.Get(baseURL + "/favicon.svg")
	if err != nil {
		t.Fatalf("failed to get /favicon.svg: %v", err)
	}
	defer resIcon.Body.Close()
	if resIcon.Header.Get("Content-Type") != "image/svg+xml" {
		t.Fatalf("expected image/svg+xml, got %s", resIcon.Header.Get("Content-Type"))
	}
}

func TestServerSecurityMiddleware(t *testing.T) {
	srv, baseURL := setupTestServer(t)
	defer srv.Stop()

	req, _ := http.NewRequest(http.MethodGet, baseURL+"/healthz", nil)
	req.Host = "malicious-site.com"
	client := &http.Client{Timeout: 2 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for bad host header, got %d", res.StatusCode)
	}

	reqPost, _ := http.NewRequest(http.MethodPost, baseURL+"/api/pause", nil)
	resPost, err := client.Do(reqPost)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resPost.Body.Close()
	if resPost.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for POST without CSRF token, got %d", resPost.StatusCode)
	}
}

func TestServerISPReportExport(t *testing.T) {
	srv, baseURL := setupTestServer(t)
	defer srv.Stop()

	res, err := http.Get(baseURL + "/api/export/isp-report.txt")
	if err != nil {
		t.Fatalf("failed to get isp report: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", res.StatusCode)
	}

	body, _ := io.ReadAll(res.Body)
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "NETSCAN ISP EVIDENCE REPORT") {
		t.Fatalf("expected report header in output")
	}
	if !strings.Contains(bodyStr, "MEASUREMENT METHODOLOGY") {
		t.Fatalf("expected methodology section in output")
	}
}

func TestServerSSEStream(t *testing.T) {
	srv, baseURL := setupTestServer(t)
	defer srv.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/api/stream", nil)
	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("stream failed: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
	if !strings.Contains(res.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("expected text/event-stream, got %s", res.Header.Get("Content-Type"))
	}
}

func TestServerUpdateEndpoints(t *testing.T) {
	srv, baseURL := setupTestServer(t)
	defer srv.Stop()

	resIndex, err := http.Get(baseURL + "/")
	if err != nil {
		t.Fatalf("failed to get index: %v", err)
	}
	defer resIndex.Body.Close()
	bodyBytes, _ := io.ReadAll(resIndex.Body)
	bodyStr := string(bodyBytes)

	tokenPrefix := `<meta name="csrf-token" content="`
	idx := strings.Index(bodyStr, tokenPrefix)
	if idx == -1 {
		t.Fatalf("missing csrf token in index html")
	}
	tokenStart := idx + len(tokenPrefix)
	tokenEnd := strings.Index(bodyStr[tokenStart:], `"`)
	if tokenEnd == -1 {
		t.Fatalf("malformed csrf meta tag")
	}
	token := bodyStr[tokenStart : tokenStart+tokenEnd]

	resStatus, err := http.Get(baseURL + "/api/update/status")
	if err != nil {
		t.Fatalf("failed to get update status: %v", err)
	}
	defer resStatus.Body.Close()
	if resStatus.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resStatus.StatusCode)
	}

	mgr := updater.NewManager("test-repo", "0.1.0", nil)
	srv.SetUpdaterManager(mgr)

	reqCheck, _ := http.NewRequest(http.MethodPost, baseURL+"/api/update/check", nil)
	reqCheck.Header.Set("X-NetScan-Token", token)
	client := &http.Client{Timeout: 2 * time.Second}
	resCheck, err := client.Do(reqCheck)
	if err != nil {
		t.Fatalf("failed to post update check: %v", err)
	}
	defer resCheck.Body.Close()
	if resCheck.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resCheck.StatusCode)
	}
}

func TestServerResetHistory(t *testing.T) {
	srv, baseURL := setupTestServer(t)
	defer srv.Stop()

	res, err := http.Get(baseURL + "/")
	if err != nil {
		t.Fatalf("failed to fetch index: %v", err)
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()

	token := ""
	for _, line := range strings.Split(string(body), "\n") {
		if strings.Contains(line, "csrf-token") {
			parts := strings.Split(line, `content="`)
			if len(parts) > 1 {
				token = strings.Split(parts[1], `"`)[0]
			}
		}
	}

	req, _ := http.NewRequest(http.MethodPost, baseURL+"/api/history/reset", nil)
	req.Header.Set("X-NetScan-Token", token)
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed to post reset: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

// Pause and resume change state, so they must not be reachable with a GET
// (which skips the CSRF check and can be triggered by any web page).
func TestPauseResumeRejectGET(t *testing.T) {
	srv, baseURL := setupTestServer(t)
	defer srv.Stop()

	for _, path := range []string{"/api/pause", "/api/resume"} {
		res, err := http.Get(baseURL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("GET %s = %d, want 405", path, res.StatusCode)
		}
	}
}

func TestTargetsEndpoint(t *testing.T) {
	srv, baseURL := setupTestServer(t)
	defer srv.Stop()

	res, err := http.Get(baseURL + "/api/targets")
	if err != nil {
		t.Fatalf("GET /api/targets: %v", err)
	}
	defer res.Body.Close()
	var targets []probe.Target
	if err := json.NewDecoder(res.Body).Decode(&targets); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(targets) == 0 {
		t.Fatal("expected the configured targets")
	}
	for i := 1; i < len(targets); i++ {
		if targets[i-1].ID >= targets[i].ID {
			t.Fatal("targets should be sorted by id")
		}
	}
}

func TestServerStopAndRestart(t *testing.T) {
	srv, baseURL := setupTestServer(t)
	defer srv.Stop()

	if !srv.Running() {
		t.Fatal("expected server to be running after Start")
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("second Start should be a no-op, got %v", err)
	}

	if err := srv.Stop(); err != nil {
		t.Fatalf("stop failed: %v", err)
	}
	if srv.Running() {
		t.Fatal("expected server to be stopped")
	}
	if _, err := os.Stat(config.PortPath()); !os.IsNotExist(err) {
		t.Fatalf("expected port file removed after Stop, got %v", err)
	}
	if _, err := http.Get(baseURL + "/healthz"); err == nil {
		t.Fatal("expected connection to fail while stopped")
	}
	if err := srv.Stop(); err != nil {
		t.Fatalf("stopping twice should be harmless, got %v", err)
	}

	if err := srv.Start(); err != nil {
		t.Fatalf("restart failed: %v", err)
	}
	res, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/healthz", srv.Port()))
	if err != nil {
		t.Fatalf("healthz after restart: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 after restart, got %d", res.StatusCode)
	}
}
