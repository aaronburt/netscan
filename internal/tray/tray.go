package tray

import (
	"context"
	"fmt"
	"os/exec"

	"fyne.io/systray"
	"github.com/aaronburt/netscan/internal/config"
	"github.com/aaronburt/netscan/internal/detector"
	"github.com/aaronburt/netscan/internal/hub"
	"github.com/aaronburt/netscan/internal/updater"
	"github.com/aaronburt/netscan/internal/winapi"
)

type TrayManager struct {
	port          func() int
	webUIEnabled  bool
	onWebUIToggle func(enable bool) (bool, error)
	hub           *hub.Hub
	updaterMgr    *updater.Manager
	onExit        func()
	onPauseToggle func() bool
	onReset       func()
	ready         bool
}

func NewTrayManager(port func() int, h *hub.Hub, updaterMgr *updater.Manager, onExit func(), onPauseToggle func() bool, onReset func()) *TrayManager {
	return &TrayManager{
		port:          port,
		hub:           h,
		updaterMgr:    updaterMgr,
		onExit:        onExit,
		onPauseToggle: onPauseToggle,
		onReset:       onReset,
	}
}

// SetWebUI sets the initial dashboard state and the callback behind the
// "Enable WebUI" item. The callback returns whether the dashboard is running
// afterwards. Call before Run.
func (tm *TrayManager) SetWebUI(enabled bool, toggle func(enable bool) (bool, error)) {
	tm.webUIEnabled = enabled
	tm.onWebUIToggle = toggle
}

func (tm *TrayManager) dashboardURL(path string) string {
	return fmt.Sprintf("http://127.0.0.1:%d%s", tm.port(), path)
}

func (tm *TrayManager) Run(ctx context.Context) {
	systray.Run(func() {
		tm.ready = true
		tm.onReady(ctx)
	}, func() {
		if tm.ready && tm.onExit != nil {
			tm.onExit()
		}
	})
}

func (tm *TrayManager) onReady(ctx context.Context) {
	systray.SetIcon(GenerateIcon(detector.StateHealthy))
	systray.SetTooltip("NetScan: Initializing...")

	mStatus := systray.AddMenuItem("NetScan: Healthy · Connecting", "")
	mStatus.Disable()

	systray.AddSeparator()

	mOpen := systray.AddMenuItem("Open Dashboard", "Open browser dashboard")
	mExportReport := systray.AddMenuItem("Export ISP Report (Last 7 Days)", "Download plain-text evidence report")
	mExportCSV := systray.AddMenuItem("Export Outages (CSV)", "Download CSV of outages")
	mUpdate := systray.AddMenuItem("Check for Updates...", "Check GitHub for new NetScan releases")

	systray.AddSeparator()

	mPause := systray.AddMenuItem("Pause Monitoring", "Temporarily stop polling")
	isAuto := winapi.IsAutostartEnabled()
	mAutostart := systray.AddMenuItemCheckbox("Start with Windows", "Run automatically at logon", isAuto)
	if isAuto {
		mAutostart.Check()
	} else {
		mAutostart.Uncheck()
	}

	mWebUI := systray.AddMenuItemCheckbox("Enable WebUI", "Serve the browser dashboard", tm.webUIEnabled)
	if tm.webUIEnabled {
		mWebUI.Check()
	} else {
		mWebUI.Uncheck()
	}
	dashItems := []*systray.MenuItem{mOpen, mExportReport, mExportCSV, mUpdate}
	setDashItems := func(on bool) {
		for _, it := range dashItems {
			if on {
				it.Enable()
			} else {
				it.Disable()
			}
		}
	}
	setDashItems(tm.webUIEnabled)

	mReset := systray.AddMenuItem("Reset Timeline History...", "Clear all timeline and probe history")
	mOpenFolder := systray.AddMenuItem("Open Data Folder", "Open logs and database location")

	systray.AddSeparator()

	mExit := systray.AddMenuItem("Exit NetScan", "Stop monitoring and quit")

	sub := tm.hub.Subscribe()

	if tm.updaterMgr != nil {
		tm.updaterMgr.SetOnStatusChange(func(st updater.StatusResponse) {
			if st.State == updater.StateAvailable && st.Release != nil {
				mUpdate.SetTitle(fmt.Sprintf("Update Available: %s", st.Release.Version))
			} else if st.State == updater.StateReadyToRestart {
				mUpdate.SetTitle("Update Ready (Restart Required)")
			} else if st.State == updater.StateUpToDate {
				mUpdate.SetTitle("NetScan is Up to Date")
			}
		})
	}

	go func() {
		defer tm.hub.Unsubscribe(sub)

		for {
			select {
			case <-ctx.Done():
				systray.Quit()
				return

			case msg := <-sub.Channel():
				if msg.Kind == hub.MessageSnapshot && msg.Snapshot != nil {
					snap := msg.Snapshot
					systray.SetIcon(GenerateIcon(snap.State))

					rttMS := 0.0
					if snap.LatestRTTUS != nil {
						if rtt, ok := snap.LatestRTTUS[10]; ok {
							rttMS = float64(rtt) / 1000.0
						}
					}

					statusText := fmt.Sprintf("NetScan: %s · %.1f ms", snap.StateString, rttMS)
					if len(statusText) > 120 {
						statusText = statusText[:120]
					}
					systray.SetTooltip(statusText)
					mStatus.SetTitle(statusText)
				}

			case <-mOpen.ClickedCh:
				url := tm.dashboardURL("")
				_ = winapi.OpenDashboard(url)

			case <-mUpdate.ClickedCh:
				url := tm.dashboardURL("/#update")
				_ = winapi.OpenDashboard(url)

			case <-mExportReport.ClickedCh:
				url := tm.dashboardURL("/api/export/isp-report.txt")
				_ = winapi.OpenDashboard(url)

			case <-mExportCSV.ClickedCh:
				url := tm.dashboardURL("/api/export/events.csv")
				_ = winapi.OpenDashboard(url)

			case <-mPause.ClickedCh:
				if tm.onPauseToggle != nil {
					isPaused := tm.onPauseToggle()
					if isPaused {
						mPause.SetTitle("Resume Monitoring")
						mStatus.SetTitle("NetScan: PAUSED")
						systray.SetIcon(GenerateIcon(detector.StatePaused))
					} else {
						mPause.SetTitle("Pause Monitoring")
						mStatus.SetTitle("NetScan: Resumed")
					}
				}

			case <-mAutostart.ClickedCh:
				curr := winapi.IsAutostartEnabled()
				newVal := !curr
				_ = winapi.SetAutostart(newVal)
				if newVal {
					mAutostart.Check()
				} else {
					mAutostart.Uncheck()
				}

			case <-mWebUI.ClickedCh:
				if tm.onWebUIToggle == nil {
					continue
				}
				running, _ := tm.onWebUIToggle(!mWebUI.Checked())
				if running {
					mWebUI.Check()
				} else {
					mWebUI.Uncheck()
				}
				setDashItems(running)

			case <-mReset.ClickedCh:
				if tm.onReset != nil {
					tm.onReset()
				}

			case <-mOpenFolder.ClickedCh:
				dataDir := config.DataDir()
				_ = exec.Command("explorer.exe", dataDir).Start()

			case <-mExit.ClickedCh:
				systray.Quit()
				return
			}
		}
	}()
}
