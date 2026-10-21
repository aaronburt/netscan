package updater

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

type UpdateState string

const (
	StateIdle           UpdateState = "idle"
	StateChecking       UpdateState = "checking"
	StateAvailable      UpdateState = "available"
	StateUpToDate       UpdateState = "up_to_date"
	StateDownloading    UpdateState = "downloading"
	StateReadyToRestart UpdateState = "ready_to_restart"
	StateError          UpdateState = "error"
)

type StatusResponse struct {
	State           UpdateState `json:"state"`
	CurrentVersion  string      `json:"current_version"`
	LatestVersion   string      `json:"latest_version,omitempty"`
	UpdateAvailable bool        `json:"update_available"`
	Release         *Release    `json:"release,omitempty"`
	ProgressPct     int         `json:"progress_pct"`
	BytesDownloaded int64       `json:"bytes_downloaded"`
	BytesTotal      int64       `json:"bytes_total"`
	Error           string      `json:"error,omitempty"`
	LastCheckedMS   int64       `json:"last_checked_ms,omitempty"`
}

type Manager struct {
	mu              sync.RWMutex
	repo            string
	currentVersion  string
	onBeforeRestart func()
	onStatusChange  func(StatusResponse)

	state           UpdateState
	latestRelease   *Release
	progressPct     int
	bytesDownloaded int64
	bytesTotal      int64
	lastError       string
	lastCheckedMS   int64
	httpClient      *http.Client
}

func NewManager(repo, currentVersion string, onBeforeRestart func()) *Manager {
	return &Manager{
		repo:            repo,
		currentVersion:  currentVersion,
		onBeforeRestart: onBeforeRestart,
		state:           StateIdle,
		httpClient:      &http.Client{Timeout: 30 * time.Second},
	}
}

func (m *Manager) SetHTTPClient(client *http.Client) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.httpClient = client
}

func (m *Manager) SetOnStatusChange(fn func(StatusResponse)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onStatusChange = fn
}

func (m *Manager) Status() StatusResponse {
	m.mu.RLock()
	defer m.mu.RUnlock()

	latestVer := ""
	if m.latestRelease != nil {
		latestVer = m.latestRelease.Version
	}

	return StatusResponse{
		State:           m.state,
		CurrentVersion:  m.currentVersion,
		LatestVersion:   latestVer,
		UpdateAvailable: m.state == StateAvailable || (m.latestRelease != nil && m.state == StateReadyToRestart),
		Release:         m.latestRelease,
		ProgressPct:     m.progressPct,
		BytesDownloaded: m.bytesDownloaded,
		BytesTotal:      m.bytesTotal,
		Error:           m.lastError,
		LastCheckedMS:   m.lastCheckedMS,
	}
}

func (m *Manager) notifyStatusChanged() {
	status := m.Status()
	m.mu.RLock()
	cb := m.onStatusChange
	m.mu.RUnlock()
	if cb != nil {
		cb(status)
	}
}

func (m *Manager) Check(ctx context.Context) (*CheckResult, error) {
	m.mu.Lock()
	m.state = StateChecking
	m.lastError = ""
	client := m.httpClient
	repo := m.repo
	currVer := m.currentVersion
	m.mu.Unlock()

	m.notifyStatusChanged()

	res, err := CheckForUpdate(ctx, client, repo, currVer)
	m.mu.Lock()
	m.lastCheckedMS = time.Now().UTC().UnixMilli()
	if err != nil {
		m.state = StateError
		m.lastError = err.Error()
		m.mu.Unlock()
		m.notifyStatusChanged()
		return nil, err
	}

	m.latestRelease = res.Release
	if res.UpdateAvailable {
		m.state = StateAvailable
	} else {
		m.state = StateUpToDate
	}
	m.mu.Unlock()

	m.notifyStatusChanged()
	return res, nil
}

func (m *Manager) Apply(ctx context.Context) error {
	m.mu.Lock()
	if m.state != StateAvailable || m.latestRelease == nil || m.latestRelease.AssetURL == "" {
		m.mu.Unlock()
		return errors.New("no update available for download")
	}

	m.state = StateDownloading
	m.progressPct = 0
	m.bytesDownloaded = 0
	m.bytesTotal = m.latestRelease.AssetSize
	m.lastError = ""
	assetURL := m.latestRelease.AssetURL
	expectedHash := m.latestRelease.ExpectedHash
	client := m.httpClient
	m.mu.Unlock()

	m.notifyStatusChanged()

	exePath, err := os.Executable()
	if err != nil {
		m.mu.Lock()
		m.state = StateError
		m.lastError = err.Error()
		m.mu.Unlock()
		m.notifyStatusChanged()
		return err
	}

	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		m.mu.Lock()
		m.state = StateError
		m.lastError = err.Error()
		m.mu.Unlock()
		m.notifyStatusChanged()
		return err
	}

	targetDir := filepath.Dir(exePath)

	downloadedPath, err := DownloadAndExtract(ctx, client, assetURL, targetDir, expectedHash, func(downloaded, total int64) {
		m.mu.Lock()
		m.bytesDownloaded = downloaded
		m.bytesTotal = total
		if total > 0 {
			m.progressPct = int(float64(downloaded) / float64(total) * 100)
		}
		m.mu.Unlock()
	})

	if err != nil {
		m.mu.Lock()
		m.state = StateError
		m.lastError = err.Error()
		m.mu.Unlock()
		m.notifyStatusChanged()
		return err
	}

	if err := ValidateExecutable(downloadedPath); err != nil {
		_ = os.Remove(downloadedPath)
		m.mu.Lock()
		m.state = StateError
		m.lastError = err.Error()
		m.mu.Unlock()
		m.notifyStatusChanged()
		return err
	}

	if err := ReplaceCurrentBinary(downloadedPath); err != nil {
		_ = os.Remove(downloadedPath)
		m.mu.Lock()
		m.state = StateError
		m.lastError = err.Error()
		m.mu.Unlock()
		m.notifyStatusChanged()
		return err
	}

	m.mu.Lock()
	m.state = StateReadyToRestart
	m.progressPct = 100
	m.mu.Unlock()

	m.notifyStatusChanged()
	return nil
}

func (m *Manager) Restart() error {
	m.mu.RLock()
	st := m.state
	beforeRestart := m.onBeforeRestart
	m.mu.RUnlock()

	if st != StateReadyToRestart {
		return errors.New("cannot restart: update has not been downloaded and prepared")
	}

	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		return err
	}

	if beforeRestart != nil {
		beforeRestart()
	}

	cmd := exec.Command(exePath, os.Args[1:]...)
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start updated application: %w", err)
	}

	go func() {
		time.Sleep(150 * time.Millisecond)
		os.Exit(0)
	}()

	return nil
}

func (m *Manager) StartBackgroundChecker(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 24 * time.Hour
	}

	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
			_, _ = m.Check(ctx)
		}

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_, _ = m.Check(ctx)
			}
		}
	}()
}
