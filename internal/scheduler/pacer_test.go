package scheduler

import (
	"testing"
	"time"
)

// run steps the pacer for the given duration, sleeping exactly as asked,
// and fails if any single wait is longer than maxWait or a gap is reported.
func run(t *testing.T, p *pacer, now time.Time, d, interval, maxWait time.Duration) time.Time {
	t.Helper()
	end := now.Add(d)
	for now.Before(end) {
		wait, gap := p.step(now, interval)
		if gap > 0 {
			t.Fatalf("unexpected gap of %v at %v", gap, now)
		}
		if wait > maxWait {
			t.Fatalf("wait of %v at interval %v (max %v)", wait, interval, maxWait)
		}
		if wait > 0 {
			now = now.Add(wait)
		}
	}
	return now
}

// Leaving fast mode used to schedule the next tick roughly "uptime" into the
// future, so probing stopped for minutes and a fake suspend was logged.
func TestPacerSwitchingIntervalsKeepsTicking(t *testing.T) {
	var p pacer
	now := time.Unix(1_700_000_000, 0)
	now = run(t, &p, now, 10*time.Minute, time.Second, time.Second)
	now = run(t, &p, now, time.Minute, 500*time.Millisecond, 500*time.Millisecond)
	_ = run(t, &p, now, 10*time.Minute, time.Second, time.Second)
}

func TestPacerPauseIsNotAGap(t *testing.T) {
	var p pacer
	now := time.Unix(1_700_000_000, 0)
	now = run(t, &p, now, time.Minute, time.Second, time.Second)

	p.reset()
	now = now.Add(10 * time.Minute)
	if _, gap := p.step(now, time.Second); gap != 0 {
		t.Fatalf("resume after pause reported a gap of %v", gap)
	}
}

func TestPacerReportsRealGap(t *testing.T) {
	var p pacer
	now := time.Unix(1_700_000_000, 0)
	now = run(t, &p, now, time.Minute, time.Second, time.Second)

	now = now.Add(30 * time.Second)
	_, gap := p.step(now, time.Second)
	if gap < 30*time.Second {
		t.Fatalf("gap = %v, want about 30s", gap)
	}
	// After a gap the grid restarts, so the next wait is one interval.
	if wait, gap := p.step(now.Add(time.Second), time.Second); gap != 0 || wait > time.Second {
		t.Fatalf("after gap: wait=%v gap=%v", wait, gap)
	}
}

func TestPacerSkipsMissedTicks(t *testing.T) {
	var p pacer
	now := time.Unix(1_700_000_000, 0)
	p.step(now, time.Second)
	// Run 2.5s late (under the gap threshold): the next wait should line up
	// with the grid, not burst through the missed ticks.
	wait, gap := p.step(now.Add(3500*time.Millisecond), time.Second)
	if gap != 0 {
		t.Fatalf("unexpected gap %v", gap)
	}
	if wait <= 0 || wait > time.Second {
		t.Fatalf("wait = %v, want within one interval", wait)
	}
}
