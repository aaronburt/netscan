package server

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aaronburt/netscan/internal/config"
	"github.com/aaronburt/netscan/internal/detector"
	"github.com/aaronburt/netscan/internal/export"
	"github.com/aaronburt/netscan/internal/hub"
	"github.com/aaronburt/netscan/internal/netenv"
	"github.com/aaronburt/netscan/internal/scheduler"
	"github.com/aaronburt/netscan/internal/store"
	"github.com/aaronburt/netscan/internal/updater"
)

//go:embed web/*
var webFS embed.FS

type Server struct {
	cfg         config.Config
	storeReader *store.StoreReader
	detector    *detector.Detector
	hub         *hub.Hub
	scheduler   *scheduler.Scheduler
	netEnv      *netenv.NetEnv
	updaterMgr  *updater.Manager
	version     string

	port      int
	csrfToken string
	server    *http.Server
	listener  net.Listener
	lock      sync.Mutex
}

func NewServer(
	cfg config.Config,
	storeReader *store.StoreReader,
	det *detector.Detector,
	h *hub.Hub,
	sched *scheduler.Scheduler,
	ne *netenv.NetEnv,
	version string,
) (*Server, error) {
	tokenBytes := make([]byte, 16)
	_, _ = rand.Read(tokenBytes)
	token := hex.EncodeToString(tokenBytes)

	return &Server{
		cfg:         cfg,
		storeReader: storeReader,
		detector:    det,
		hub:         h,
		scheduler:   sched,
		netEnv:      ne,
		version:     version,
		csrfToken:   token,
	}, nil
}

func (s *Server) Port() int {
	s.lock.Lock()
	defer s.lock.Unlock()
	return s.port
}

func (s *Server) SetUpdaterManager(mgr *updater.Manager) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.updaterMgr = mgr
}

func (s *Server) Start() error {
	basePort := s.cfg.HTTP.Port
	if basePort <= 0 {
		basePort = 9095
	}

	var listener net.Listener
	var chosenPort int
	var err error

	for p := basePort; p <= basePort+10; p++ {
		addr := fmt.Sprintf("%s:%d", s.cfg.HTTP.Addr, p)
		listener, err = net.Listen("tcp", addr)
		if err == nil {
			chosenPort = p
			break
		}
	}
	if listener == nil {
		return fmt.Errorf("unable to bind to any port between %d and %d: %w", basePort, basePort+10, err)
	}

	s.lock.Lock()
	s.port = chosenPort
	s.listener = listener
	s.lock.Unlock()

	_ = os.WriteFile(config.PortPath(), []byte(strconv.Itoa(chosenPort)), 0644)

	mux := http.NewServeMux()
	s.registerRoutes(mux)

	handler := s.securityMiddleware(mux)
	s.server = &http.Server{
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	go func() {
		_ = s.server.Serve(listener)
	}()

	return nil
}

func (s *Server) Stop() error {
	if s.server != nil {
		return s.server.Close()
	}
	return nil
}

func (s *Server) securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if strings.Contains(host, ":") {
			h, _, err := net.SplitHostPort(host)
			if err == nil {
				host = h
			}
		}

		if host != "127.0.0.1" && host != "localhost" {
			http.Error(w, "Forbidden host", http.StatusForbidden)
			return
		}

		w.Header().Set("Content-Security-Policy", "default-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data:; connect-src 'self';")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")

		if r.Method == http.MethodPost {
			token := r.Header.Get("X-NetScan-Token")
			if token != s.csrfToken {
				http.Error(w, "Invalid CSRF token", http.StatusForbidden)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) registerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/styles.css", s.handleStyles)
	mux.HandleFunc("/app.js", s.handleAppJS)
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/stream", s.handleStream)
	mux.HandleFunc("/api/events", s.handleEvents)
	mux.HandleFunc("/api/events/", s.handleEventDetail)
	mux.HandleFunc("/api/samples", s.handleSamples)
	mux.HandleFunc("/api/rollups", s.handleRollups)
	mux.HandleFunc("/api/pause", s.handlePause)
	mux.HandleFunc("/api/resume", s.handleResume)
	mux.HandleFunc("/api/export/isp-report.txt", s.handleExportISPReport)
	mux.HandleFunc("/api/export/events.csv", s.handleExportEventsCSV)
	mux.HandleFunc("/api/export/samples.csv", s.handleExportSamplesCSV)
	mux.HandleFunc("/api/export/rollups.csv", s.handleExportRollupsCSV)
	mux.HandleFunc("/api/export/rollups.json", s.handleExportRollupsJSON)
	mux.HandleFunc("/api/update/status", s.handleUpdateStatus)
	mux.HandleFunc("/api/update/check", s.handleUpdateCheck)
	mux.HandleFunc("/api/update/apply", s.handleUpdateApply)
	mux.HandleFunc("/api/update/restart", s.handleUpdateRestart)
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"app":"netscan"}`))
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	content, err := webFS.ReadFile("web/index.html")
	if err != nil {
		http.Error(w, "Failed to load index.html", http.StatusInternalServerError)
		return
	}

	htmlStr := strings.ReplaceAll(string(content), "{{CSRF_TOKEN}}", s.csrfToken)
	htmlStr = strings.ReplaceAll(htmlStr, "{{VERSION}}", s.version)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	_, _ = w.Write([]byte(htmlStr))
}

func (s *Server) handleStyles(w http.ResponseWriter, _ *http.Request) {
	content, err := webFS.ReadFile("web/styles.css")
	if err != nil {
		http.Error(w, "Failed to load styles.css", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	_, _ = w.Write(content)
}

func (s *Server) handleAppJS(w http.ResponseWriter, _ *http.Request) {
	content, err := webFS.ReadFile("web/app.js")
	if err != nil {
		http.Error(w, "Failed to load app.js", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	_, _ = w.Write(content)
}

func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	snap := s.detector.GetSnapshot()
	netInfo := s.netEnv.GetNetworkInfo()

	payload := map[string]any{
		"version":  s.version,
		"snapshot": snap,
		"network": map[string]any{
			"gateway_ip":  netInfo.GatewayIP.String(),
			"gateway_mac": netInfo.GatewayMAC,
			"is_vpn":      netInfo.IsVPN,
			"interface":   netInfo.InterfaceName,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	sub := s.hub.Subscribe()
	defer s.hub.Unsubscribe(sub)

	initialSnap := s.detector.GetSnapshot()
	initMsg, _ := json.Marshal(map[string]any{
		"kind":     "snapshot",
		"snapshot": initialSnap,
	})
	_, _ = fmt.Fprintf(w, "data: %s\n\n", initMsg)
	flusher.Flush()

	heartbeatTicker := time.NewTicker(15 * time.Second)
	defer heartbeatTicker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-heartbeatTicker.C:
			_, _ = fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()
		case msg := <-sub.Channel():
			data, err := json.Marshal(msg)
			if err == nil {
				_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
				flusher.Flush()
			}
		}
	}
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	fromMS, _ := strconv.ParseInt(q.Get("from"), 10, 64)
	toMS, _ := strconv.ParseInt(q.Get("to"), 10, 64)

	filter := store.EventFilter{
		FromMS:         fromMS,
		ToMS:           toMS,
		Kind:           q.Get("kind"),
		Classification: q.Get("classification"),
		Limit:          limit,
	}

	events, err := s.storeReader.QueryEvents(filter)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(events)
}

func (s *Server) handleEventDetail(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/events/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid event id", http.StatusBadRequest)
		return
	}

	detail, err := s.storeReader.QueryEventByID(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(detail)
}

func (s *Server) handleSamples(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	fromMS, _ := strconv.ParseInt(q.Get("from"), 10, 64)
	toMS, _ := strconv.ParseInt(q.Get("to"), 10, 64)
	targetID, _ := strconv.Atoi(q.Get("target_id"))
	failedOnly := q.Get("failed_only") == "true"
	limit, _ := strconv.Atoi(q.Get("limit"))

	samples, err := s.storeReader.QuerySamplesRange(fromMS, toMS, targetID, failedOnly, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(samples)
}

func (s *Server) handleRollups(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	fromMS, _ := strconv.ParseInt(q.Get("from"), 10, 64)
	toMS, _ := strconv.ParseInt(q.Get("to"), 10, 64)
	targetID, _ := strconv.Atoi(q.Get("target_id"))
	layer := q.Get("layer")

	rollups, err := s.storeReader.QueryRollups(fromMS, toMS, targetID, layer)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rollups)
}

func (s *Server) handlePause(w http.ResponseWriter, _ *http.Request) {
	s.scheduler.Pause()
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"paused"}`))
}

func (s *Server) handleResume(w http.ResponseWriter, _ *http.Request) {
	s.scheduler.Resume()
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"resumed"}`))
}

func (s *Server) handleExportISPReport(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	toMS := now.UnixMilli()
	fromMS := now.AddDate(0, 0, -7).UnixMilli()

	events, _ := s.storeReader.QueryEvents(store.EventFilter{FromMS: fromMS, ToMS: toMS, Limit: 1000})
	stats, _ := s.storeReader.QueryStats(now)

	meta := export.ExportMeta{
		FromMS:       fromMS,
		ToMS:         toMS,
		GeneratedAt:  time.Now().Local().Format(time.RFC3339),
		AppVersion:   s.version,
		NetworkLabel: s.netEnv.GetFingerprint(),
	}

	netInfo := s.netEnv.GetNetworkInfo()
	gwStr := "N/A"
	if netInfo.GatewayIP != nil {
		gwStr = netInfo.GatewayIP.String()
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\"netscan-isp-evidence-report.txt\"")
	_ = export.GenerateISPReport(w, meta, events, stats, gwStr, "Detected ISP Gateway")
}

func (s *Server) handleExportEventsCSV(w http.ResponseWriter, _ *http.Request) {
	now := time.Now().UTC()
	fromMS := now.AddDate(0, 0, -7).UnixMilli()

	events, _ := s.storeReader.QueryEvents(store.EventFilter{FromMS: fromMS, ToMS: now.UnixMilli(), Limit: 5000})
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\"netscan-events-7d.csv\"")
	_ = export.ExportEventsCSV(w, events)
}

func (s *Server) handleExportSamplesCSV(w http.ResponseWriter, _ *http.Request) {
	now := time.Now().UTC()
	fromMS := now.Add(-6 * time.Hour).UnixMilli()

	samples, _ := s.storeReader.QuerySamplesRange(fromMS, now.UnixMilli(), 0, false, 5000)
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\"netscan-samples-6h.csv\"")
	_ = export.ExportSamplesCSV(w, samples)
}

func (s *Server) handleExportRollupsCSV(w http.ResponseWriter, _ *http.Request) {
	now := time.Now().UTC()
	fromMS := now.AddDate(0, 0, -7).UnixMilli()

	rollups, _ := s.storeReader.QueryRollups(fromMS, now.UnixMilli(), 0, "")
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\"netscan-rollups-7d.csv\"")
	_ = export.ExportRollupsCSV(w, rollups)
}

func (s *Server) handleExportRollupsJSON(w http.ResponseWriter, _ *http.Request) {
	now := time.Now().UTC()
	fromMS := now.AddDate(0, 0, -7).UnixMilli()

	rollups, _ := s.storeReader.QueryRollups(fromMS, now.UnixMilli(), 0, "")
	meta := export.ExportMeta{
		FromMS:      fromMS,
		ToMS:        now.UnixMilli(),
		GeneratedAt: time.Now().Local().Format(time.RFC3339),
		AppVersion:  s.version,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=\"netscan-rollups-7d.json\"")
	_ = export.ExportJSON(w, meta, rollups)
}

func (s *Server) handleUpdateStatus(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	s.lock.Lock()
	mgr := s.updaterMgr
	s.lock.Unlock()

	if mgr == nil {
		_ = json.NewEncoder(w).Encode(updater.StatusResponse{
			State:          updater.StateIdle,
			CurrentVersion: s.version,
		})
		return
	}

	_ = json.NewEncoder(w).Encode(mgr.Status())
}

func (s *Server) handleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.lock.Lock()
	mgr := s.updaterMgr
	s.lock.Unlock()

	if mgr == nil {
		http.Error(w, "Updater not initialized", http.StatusBadRequest)
		return
	}

	_, _ = mgr.Check(r.Context())
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(mgr.Status())
}

func (s *Server) handleUpdateApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.lock.Lock()
	mgr := s.updaterMgr
	s.lock.Unlock()

	if mgr == nil {
		http.Error(w, "Updater not initialized", http.StatusBadRequest)
		return
	}

	go func() {
		_ = mgr.Apply(context.Background())
	}()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(mgr.Status())
}

func (s *Server) handleUpdateRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.lock.Lock()
	mgr := s.updaterMgr
	s.lock.Unlock()

	if mgr == nil {
		http.Error(w, "Updater not initialized", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "restarting"})

	go func() {
		time.Sleep(200 * time.Millisecond)
		_ = mgr.Restart()
	}()
}
