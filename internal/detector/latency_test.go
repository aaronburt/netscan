package detector_test

import (
	"testing"
	"time"

	"github.com/aaronburt/netscan/internal/config"
	"github.com/aaronburt/netscan/internal/detector"
)

func TestLatencyTracker(t *testing.T) {
	cfg := config.DefaultConfig().Latency
	cfg.WarmupSamples = 10
	cfg.BaselineWindowS = 60
	cfg.LongWindowS = 120
	cfg.FloorMS = 10.0
	cfg.FloorPct = 20.0
	cfg.MADK = 2.0
	cfg.SpikeMS = 100.0
	cfg.SpikeX = 3.0
	cfg.SustainOf = 5
	cfg.SustainHits = 3

	tracker := detector.NewLatencyTracker(cfg)
	start := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)

	for i := 0; i < 15; i++ {
		now := start.Add(time.Duration(i) * time.Second)
		lat, spike, rebase := tracker.Record(10, 20000, now)
		if lat || spike || rebase {
			t.Fatalf("unexpected flag during warmup/baseline: lat=%v spike=%v rebase=%v", lat, spike, rebase)
		}
	}

	spikeTime := start.Add(16 * time.Second)
	lat, spike, _ := tracker.Record(10, 150000, spikeTime)
	if !lat || !spike {
		t.Fatalf("expected spike to be flagged: lat=%v spike=%v", lat, spike)
	}

	for i := 0; i < 4; i++ {
		now := start.Add(time.Duration(20+i) * time.Second)
		lat, _, _ = tracker.Record(10, 50000, now)
	}
	if !lat {
		t.Fatalf("expected sustained latency to be flagged after 3/5 hits")
	}
}
