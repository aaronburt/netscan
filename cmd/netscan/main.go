package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/aaronburt/netscan/internal/app"
	"github.com/aaronburt/netscan/internal/config"
	"github.com/aaronburt/netscan/internal/detector"
	"github.com/aaronburt/netscan/internal/hub"
	"github.com/aaronburt/netscan/internal/netenv"
	"github.com/aaronburt/netscan/internal/platform"
	"github.com/aaronburt/netscan/internal/probe"
	"github.com/aaronburt/netscan/internal/scheduler"
	"github.com/aaronburt/netscan/internal/server"
	"github.com/aaronburt/netscan/internal/store"
	"github.com/aaronburt/netscan/internal/tray"
	"github.com/aaronburt/netscan/internal/updater"
)

var version = "dev"

func init() {
	runtime.LockOSThread()
}

func main() {
	checkUpdateFlag := flag.Bool("check-update", false, "check github for latest release")
	updateFlag := flag.Bool("update", false, "download and install latest release if available")
	resetFlag := flag.Bool("reset", false, "reset all timeline history and exit")
	headlessFlag := flag.Bool("headless", false, "run without system tray in console mode")
	configFlag := flag.String("config", "", "path to custom configuration file")
	flag.Parse()

	service := app.UnderSystemd(os.Getenv)
	headless := *headlessFlag || app.ShouldRunHeadless(runtime.GOOS, os.Getenv)

	if *checkUpdateFlag {
		platform.AttachConsoleToParent()
		cfg, _ := config.LoadConfig(*configFlag)
		repo := cfg.Update.Repo
		if repo == "" {
			repo = "aaronburt/netscan"
		}
		fmt.Printf("Checking for updates from %s...\n", repo)
		res, err := updater.CheckForUpdate(context.Background(), nil, repo, version)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Update check failed: %v\n", err)
			os.Exit(1)
		}
		if res.UpdateAvailable && res.Release != nil {
			fmt.Printf("Update available: %s -> %s\n", version, res.Release.Version)
			if res.Release.Name != "" {
				fmt.Printf("Release: %s\n", res.Release.Name)
			}
			if res.Release.HTMLURL != "" {
				fmt.Printf("URL: %s\n", res.Release.HTMLURL)
			}
		} else {
			fmt.Printf("NetScan is up to date (%s).\n", version)
		}
		os.Exit(0)
	}

	if *updateFlag {
		platform.AttachConsoleToParent()
		cfg, _ := config.LoadConfig(*configFlag)
		repo := cfg.Update.Repo
		if repo == "" {
			repo = "aaronburt/netscan"
		}
		fmt.Printf("Checking for updates from %s...\n", repo)
		res, err := updater.CheckForUpdate(context.Background(), nil, repo, version)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Update check failed: %v\n", err)
			os.Exit(1)
		}
		if !res.UpdateAvailable || res.Release == nil || res.Release.AssetURL == "" {
			fmt.Printf("NetScan is already up to date (%s).\n", version)
			os.Exit(0)
		}
		fmt.Printf("Downloading %s (%s)...\n", res.Release.Version, res.Release.AssetName)
		exePath, err := os.Executable()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to resolve executable path: %v\n", err)
			os.Exit(1)
		}
		exePath, _ = filepath.EvalSymlinks(exePath)
		targetDir := filepath.Dir(exePath)
		tmpPath, err := updater.DownloadAndExtract(context.Background(), nil, res.Release.AssetURL, targetDir, res.Release.ExpectedHash, func(down, tot int64) {
			if tot > 0 {
				pct := float64(down) / float64(tot) * 100
				fmt.Printf("\rProgress: %.1f%% (%d / %d bytes)", pct, down, tot)
			}
		})
		fmt.Println()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Download failed: %v\n", err)
			os.Exit(1)
		}
		if err := updater.ValidateExecutable(tmpPath); err != nil {
			_ = os.Remove(tmpPath)
			fmt.Fprintf(os.Stderr, "Validation failed: %v\n", err)
			os.Exit(1)
		}
		if updater.HasUpdaterBinary(targetDir) {
			fmt.Printf("Handing off update (%s) to updater.exe and relaunching...\n", res.Release.Version)
			if err := updater.LaunchUpdaterHelper(updater.UpdaterBinaryPath(targetDir), exePath, tmpPath, os.Getpid(), os.Args[1:]); err != nil {
				_ = os.Remove(tmpPath)
				fmt.Fprintf(os.Stderr, "Failed to launch updater.exe: %v\n", err)
				os.Exit(1)
			}
			os.Exit(0)
		}
		if err := updater.ReplaceCurrentBinary(tmpPath); err != nil {
			_ = os.Remove(tmpPath)
			fmt.Fprintf(os.Stderr, "Failed to replace executable: %v\n", err)
			os.Exit(1)
		}
		if runtime.GOOS == "linux" {
			fmt.Printf("Successfully updated to %s. Restart NetScan to run it (sudo systemctl restart netscan).\n", res.Release.Version)
			os.Exit(0)
		}
		fmt.Printf("Successfully updated to %s! Relaunching NetScan...\n", res.Release.Version)
		if err := updater.RelaunchExecutable(os.Args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to relaunch executable: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	if *resetFlag {
		platform.AttachConsoleToParent()
		cfg, _ := config.LoadConfig(*configFlag)
		db, err := store.OpenDB(config.DBPath())
		if err != nil {
			fmt.Fprintf(os.Stderr, "netscan: failed to open database: %v\n", err)
			os.Exit(1)
		}
		writer := store.NewStoreWriter(db, cfg)
		err = writer.ResetHistory()
		_ = db.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "netscan: failed to reset timeline history: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("NetScan timeline history successfully reset.")
		os.Exit(0)
	}

	updater.CleanupOldBinary()

	if headless {
		platform.AttachConsoleToParent()
	}

	mutexHandle, acquired, err := platform.AcquireSingleInstance(`Local\NetScan.SingleInstance`)
	if err != nil {
		fmt.Fprintln(os.Stderr, "netscan: single-instance mutex:", err)
		os.Exit(1)
	}
	if !acquired {
		tmp := slog.New(slog.NewTextHandler(os.Stderr, nil))
		if app.HandleExistingInstance(tmp) {
			os.Exit(0)
		}
		for i := 0; i < 30; i++ {
			time.Sleep(200 * time.Millisecond)
			mutexHandle, acquired, err = platform.AcquireSingleInstance(`Local\NetScan.SingleInstance`)
			if err == nil && acquired {
				break
			}
		}
		if !acquired {
			os.Exit(1)
		}
	}

	logger, logCloser := app.SetupLogger(headless, service)

	logger.Info("starting netscan", "version", version, "headless", headless, "service", service)

	cfg, err := config.LoadConfig(*configFlag)
	if err != nil {
		logger.Warn("loaded config with fallback defaults", "error", err)
	}
	for _, w := range cfg.LoadWarnings {
		logger.Warn("config", "warning", w)
	}
	profile := cfg.Active()
	logger.Info("polling profile", "id", profile.ID, "name", profile.Name, "mode", profile.Mode)

	dbPath := config.DBPath()
	db, err := store.OpenDB(dbPath)
	if err != nil {
		logger.Error("failed to open database, attempting quarantine", "error", err)
		_ = store.QuarantineCorruptDB(dbPath)
		db, err = store.OpenDB(dbPath)
		if err != nil {
			logger.Error("failed to open fresh database", "error", err)
			os.Exit(1)
		}
	}

	if err := store.QuickCheck(db); err != nil {
		logger.Error("quick check failed, quarantining corrupt database", "error", err)
		_ = db.Close()
		_ = store.QuarantineCorruptDB(dbPath)
		db, err = store.OpenDB(dbPath)
		if err != nil {
			logger.Error("failed to open fresh database", "error", err)
			os.Exit(1)
		}
	}

	if err := store.InitSchema(db); err != nil {
		logger.Error("failed to initialize schema", "error", err)
		os.Exit(1)
	}

	storeWriter := store.NewStoreWriter(db, cfg)
	storeReader := store.NewStoreReader(db)

	known, err := storeReader.KnownTargets()
	if err != nil {
		logger.Warn("could not read known targets", "error", err)
	}
	registry := probe.NewTargetRegistryWithIDs(profile, probe.NewIDAllocator(known))

	for _, t := range registry.GetAllTargets() {
		storeWriter.QueueTarget(t)
	}

	sysEventCh := make(chan netenv.SystemEvent, 64)
	netEnv := netenv.NewNetEnv(registry, sysEventCh)

	h := hub.NewHub()

	var sched *scheduler.Scheduler
	det := detector.NewDetector(cfg, profile, nil, func(fast bool) {
		if sched != nil {
			sched.SetFastMode(fast)
		}
	})
	if maxID, err := storeReader.MaxEventID(); err != nil {
		logger.Warn("could not read last event id", "error", err)
	} else {
		det.SetNextEventID(maxID + 1)
	}

	probeOutCh := make(chan probe.ProbeResult, 1024)
	sched = scheduler.NewScheduler(profile, registry, probeOutCh, version, func(gap time.Duration) {
		logger.Warn("scheduler gap detected", "gap", gap)
		sysEventCh <- netenv.SystemEvent{
			Timestamp: time.Now().UTC().UnixMilli(),
			Kind:      netenv.SysEventSuspend,
			Detail:    fmt.Sprintf("scheduler gap of %v", gap),
		}
		sysEventCh <- netenv.SystemEvent{
			Timestamp: time.Now().UTC().UnixMilli(),
			Kind:      netenv.SysEventResume,
			Detail:    fmt.Sprintf("scheduler resumed after gap of %v", gap),
		}
	})

	srv, err := server.NewServer(cfg, storeReader, storeWriter, det, h, sched, netEnv, registry, version)
	if err != nil {
		logger.Error("failed to create server", "error", err)
		os.Exit(1)
	}
	if cfg.HTTP.Enabled {
		if err := srv.Start(); err != nil {
			logger.Error("failed to start server", "error", err)
			os.Exit(1)
		}
	} else {
		logger.Info("web UI disabled in config, monitoring without dashboard")
	}

	rootCtx, rootCancel := context.WithCancel(context.Background())
	supervisor := app.NewSupervisor(logger)

	// shutdown is the single way out once everything is running. The store
	// writer flushes its queue when its context is cancelled, so stopping the
	// supervisor is enough to get pending data onto disk.
	var shuttingDown atomic.Bool
	var shutdownOnce sync.Once
	shutdown := func(reason string) {
		shuttingDown.Store(true)
		shutdownOnce.Do(func() {
			logger.Info("shutting down netscan", "reason", reason)
			if evt := det.CloseForShutdown(); evt != nil {
				storeWriter.QueueEvent(*evt)
				h.PublishEvent(*evt)
			}
			rootCancel()
			if !supervisor.Stop(5 * time.Second) {
				logger.Warn("components did not stop in time")
			}
			_ = srv.Stop()
			_ = db.Close()
			_ = os.Remove(config.PortPath())
			_ = logCloser.Close()
			_ = mutexHandle.Close()
		})
	}

	updaterMgr := updater.NewManager(cfg.Update.Repo, version, func() {
		shutdown("restarting for update")
	})
	srv.SetUpdaterManager(updaterMgr)
	if cfg.Update.CheckOnStartup {
		updaterMgr.StartBackgroundChecker(rootCtx, time.Duration(cfg.Update.AutoCheckHours)*time.Hour)
	}

	supervisor.Run("store_writer", func(ctx context.Context) error {
		return storeWriter.Run(ctx)
	})

	supervisor.Run("net_env", func(ctx context.Context) error {
		return netEnv.Run(ctx)
	})

	supervisor.Run("scheduler", func(ctx context.Context) error {
		return sched.Run(ctx)
	})

	supervisor.Run("probe_processor", func(ctx context.Context) error {
		tickInterval := time.Duration(profile.Intervals.NormalMS) * time.Millisecond
		ticker := time.NewTicker(tickInterval)
		defer ticker.Stop()

		snapTicker := time.NewTicker(500 * time.Millisecond)
		defer snapTicker.Stop()

		for {
			select {
			case <-ctx.Done():
				return nil

			case res := <-probeOutCh:
				annotated, created, closed := det.ProcessProbe(res)
				storeWriter.QueueSample(annotated)
				if created != nil {
					storeWriter.QueueEvent(*created)
					h.PublishEvent(*created)
				}
				if closed != nil {
					storeWriter.QueueEvent(*closed)
					h.PublishEvent(*closed)
				}

			case evt := <-sysEventCh:
				storeWriter.QueueSystemEvent(evt)
				created, closed := det.ProcessSystemEvent(evt)
				if created != nil {
					storeWriter.QueueEvent(*created)
					h.PublishEvent(*created)
				}
				if closed != nil {
					storeWriter.QueueEvent(*closed)
					h.PublishEvent(*closed)
				}

			case <-ticker.C:
				created, closed := det.Tick(time.Now())
				if created != nil {
					storeWriter.QueueEvent(*created)
					h.PublishEvent(*created)
				}
				if closed != nil {
					storeWriter.QueueEvent(*closed)
					h.PublishEvent(*closed)
				}

			case <-snapTicker.C:
				snap := det.GetSnapshot()
				h.PublishSnapshot(snap)
			}
		}
	})

	if headless {
		// Under a service manager stdout is the structured log, so skip the
		// human-readable banner.
		if !service {
			if srv.Running() {
				serverURL := fmt.Sprintf("http://127.0.0.1:%d", srv.Port())
				fmt.Printf("NetScan %s active on %s\n", version, serverURL)
				fmt.Printf("Dashboard & Log Viewer: %s\n", serverURL)
			} else {
				fmt.Printf("NetScan %s active (web UI disabled)\n", version)
			}
			fmt.Println("Press Ctrl+C to stop.")
		}

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		<-sigCh

		shutdown("signal")
		return
	}

	trayMgr := tray.NewTrayManager(
		srv.Port,
		h,
		updaterMgr,
		func() {
			if shuttingDown.Load() {
				return // an update restart is already in progress
			}
			shutdown("tray exit")
			os.Exit(0)
		},
		func() bool {
			if sched.IsPaused() {
				sched.Resume()
				return false
			}
			sched.Pause()
			return true
		},
	)

	trayMgr.SetWebUI(srv.Running(), func(enable bool) (bool, error) {
		if enable {
			if err := srv.Start(); err != nil {
				return srv.Running(), err
			}
		} else if err := srv.Stop(); err != nil {
			logger.Warn("error stopping web UI", "error", err)
		}
		if err := config.SetWebUIEnabled(*configFlag, enable); err != nil {
			logger.Warn("could not persist web UI setting", "error", err)
			return srv.Running(), err
		}
		logger.Info("web UI toggled", "enabled", enable)
		return srv.Running(), nil
	})

	trayMgr.Run(rootCtx)

	if shuttingDown.Load() {
		// The tray loop ends because shutdown cancelled rootCtx. When that
		// was for an update, the updater manager is still about to launch the
		// helper and exit on its own, so returning here would kill the
		// process before the relaunch. Every other exit path calls os.Exit.
		time.Sleep(30 * time.Second)
		return
	}

	if !shuttingDown.Load() {
		logger.Warn("tray loop exited or unavailable, continuing in headless mode")
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		<-sigCh
		shutdown("signal")
	}
}
