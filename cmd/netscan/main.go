package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/aaronburt/netscan/internal/app"
	"github.com/aaronburt/netscan/internal/config"
	"github.com/aaronburt/netscan/internal/detector"
	"github.com/aaronburt/netscan/internal/hub"
	"github.com/aaronburt/netscan/internal/netenv"
	"github.com/aaronburt/netscan/internal/probe"
	"github.com/aaronburt/netscan/internal/scheduler"
	"github.com/aaronburt/netscan/internal/server"
	"github.com/aaronburt/netscan/internal/store"
	"github.com/aaronburt/netscan/internal/tray"
	"github.com/aaronburt/netscan/internal/winapi"
)

var version = "0.1.0-dev"

func init() {
	runtime.LockOSThread()
}

func main() {
	headlessFlag := flag.Bool("headless", false, "run without system tray in console mode")
	configFlag := flag.String("config", "", "path to custom configuration file")
	flag.Parse()

	if *headlessFlag {
		winapi.AttachConsoleToParent()
	}

	mutexHandle, acquired, err := winapi.AcquireSingleInstance(`Local\NetScan.SingleInstance`)
	if err != nil {
		fmt.Fprintln(os.Stderr, "netscan: single-instance mutex:", err)
		os.Exit(1)
	}
	if !acquired {
		tmp := slog.New(slog.NewTextHandler(os.Stderr, nil))
		if app.HandleExistingInstance(tmp) {
			os.Exit(0)
		}
		os.Exit(1)
	}
	defer mutexHandle.Close()

	logger, logCloser := app.SetupLogger(*headlessFlag)
	defer logCloser.Close()

	logger.Info("starting netscan", "version", version, "headless", *headlessFlag)

	cfg, err := config.LoadConfig(*configFlag)
	if err != nil {
		logger.Warn("loaded config with fallback defaults", "error", err)
	}

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
	defer db.Close()

	if err := store.QuickCheck(db); err != nil {
		logger.Error("quick check failed, quarantining corrupt database", "error", err)
		_ = db.Close()
		_ = store.QuarantineCorruptDB(dbPath)
		db, _ = store.OpenDB(dbPath)
	}

	if err := store.InitSchema(db); err != nil {
		logger.Error("failed to initialize schema", "error", err)
		os.Exit(1)
	}

	registry := probe.NewTargetRegistry(cfg)
	storeWriter := store.NewStoreWriter(db, cfg)
	storeReader := store.NewStoreReader(db)

	for _, t := range registry.GetAllTargets() {
		storeWriter.QueueTarget(t)
	}

	sysEventCh := make(chan netenv.SystemEvent, 64)
	netEnv := netenv.NewNetEnv(registry, sysEventCh)

	h := hub.NewHub()

	var sched *scheduler.Scheduler
	det := detector.NewDetector(cfg, nil, func(fast bool) {
		if sched != nil {
			sched.SetFastMode(fast)
		}
	})

	probeOutCh := make(chan probe.ProbeResult, 1024)
	sched = scheduler.NewScheduler(cfg, registry, probeOutCh, version, func(gap time.Duration) {
		logger.Warn("scheduler gap detected", "gap", gap)
		sysEventCh <- netenv.SystemEvent{
			Timestamp: time.Now().UTC().UnixMilli(),
			Kind:      netenv.SysEventSuspend,
			Detail:    fmt.Sprintf("scheduler gap of %v", gap),
		}
	})

	srv, err := server.NewServer(cfg, storeReader, det, h, sched, netEnv, version)
	if err != nil {
		logger.Error("failed to create server", "error", err)
		os.Exit(1)
	}
	if err := srv.Start(); err != nil {
		logger.Error("failed to start server", "error", err)
		os.Exit(1)
	}
	defer srv.Stop()

	rootCtx, rootCancel := context.WithCancel(context.Background())
	supervisor := app.NewSupervisor(logger)

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
		tickInterval := time.Duration(cfg.Intervals.NormalMS) * time.Millisecond
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

	serverURL := fmt.Sprintf("http://127.0.0.1:%d", srv.Port())
	if *headlessFlag {
		fmt.Printf("NetScan %s active on %s\n", version, serverURL)
		fmt.Printf("Dashboard & Log Viewer: %s\n", serverURL)
		fmt.Println("Press Ctrl+C to stop.")

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		<-sigCh

		logger.Info("shutting down netscan")
		rootCancel()
		supervisor.Stop(5 * time.Second)
		storeWriter.FlushSync()
		return
	}

	trayMgr := tray.NewTrayManager(
		srv.Port(),
		h,
		func() {
			logger.Info("tray requested exit")
			rootCancel()
			supervisor.Stop(5 * time.Second)
			storeWriter.FlushSync()
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

	trayMgr.Run(rootCtx)
}
