package scheduler_test

import (
	"context"
	"testing"
	"time"

	"github.com/aaronburt/netscan/internal/config"
	"github.com/aaronburt/netscan/internal/probe"
	"github.com/aaronburt/netscan/internal/scheduler"
)

func TestSchedulerHealthyFlow(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Intervals.NormalMS = 100
	cfg.Intervals.FastMS = 50
	cfg.Targets.WANICMP = []string{"127.0.0.1"}
	cfg.Targets.WANTCP = []string{"127.0.0.1:80"}
	cfg.Targets.DNS = []string{"127.0.0.1:53"}
	cfg.Targets.HTTP = []config.HTTPTargetConfig{}

	reg := probe.NewTargetRegistry(cfg)
	outCh := make(chan probe.ProbeResult, 100)

	sched := scheduler.NewScheduler(cfg, reg, outCh, "test", nil)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		_ = sched.Run(ctx)
	}()

	results := make([]probe.ProbeResult, 0)
	deadline := time.After(400 * time.Millisecond)

loop:
	for {
		select {
		case r := <-outCh:
			results = append(results, r)
			if len(results) >= 3 {
				break loop
			}
		case <-deadline:
			break loop
		}
	}

	cancel()

	if len(results) == 0 {
		t.Fatalf("expected at least 1 probe result, got 0")
	}

	for _, r := range results {
		if r.TargetID == 0 {
			t.Fatalf("target id should not be 0")
		}
		if r.SendTimeUTC == 0 {
			t.Fatalf("send time should not be 0")
		}
	}
}

func TestSchedulerFastMode(t *testing.T) {
	cfg := config.DefaultConfig()
	reg := probe.NewTargetRegistry(cfg)
	outCh := make(chan probe.ProbeResult, 10)

	sched := scheduler.NewScheduler(cfg, reg, outCh, "test", nil)
	if sched.IsFastMode() {
		t.Fatalf("expected healthy mode initially")
	}

	sched.SetFastMode(true)
	if !sched.IsFastMode() {
		t.Fatalf("expected fast mode after SetFastMode(true)")
	}

	sched.Pause()
	if !sched.IsPaused() {
		t.Fatalf("expected paused state")
	}

	sched.Resume()
	if sched.IsPaused() {
		t.Fatalf("expected resumed state")
	}
}
