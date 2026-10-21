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
	port          int
	hub           *hub.Hub
	updaterMgr    *updater.Manager
	onExit        func()
	onPauseToggle func() bool
}

func NewTrayManager(port int, h *hub.Hub, updaterMgr *updater.Manager, onExit func(), onPauseToggle func() bool) *TrayManager {
	return &TrayManager{
		port:          port,
		hub:           h,
		updaterMgr:    updaterMgr,
		onExit:        onExit,
		onPauseToggle: onPauseToggle,
	}
}

func (tm *TrayManager) Run(ctx context.Context) {
	systray.Run(func() {
		tm.onReady(ctx)
	}, func() {
		if tm.onExit != nil {
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
				url := fmt.Sprintf("http://127.0.0.1:%d", tm.port)
				_ = winapi.OpenDashboard(url)

			case <-mUpdate.ClickedCh:
				url := fmt.Sprintf("http://127.0.0.1:%d/#update", tm.port)
				_ = winapi.OpenDashboard(url)

			case <-mExportReport.ClickedCh:
				url := fmt.Sprintf("http://127.0.0.1:%d/api/export/isp-report.txt", tm.port)
				_ = winapi.OpenDashboard(url)

			case <-mExportCSV.ClickedCh:
				url := fmt.Sprintf("http://127.0.0.1:%d/api/export/events.csv", tm.port)
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
