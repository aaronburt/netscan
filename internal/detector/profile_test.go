package detector_test

import (
	"testing"
	"time"

	"github.com/aaronburt/netscan/internal/config"
	"github.com/aaronburt/netscan/internal/detector"
)

func TestOutageRecordsTheProfileItStartedUnder(t *testing.T) {
	clock := &MockClock{curr: time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)}
	d, _ := setupDetector(clock)
	d.SetProfileID(7)
	openOutage(t, d, clock)

	if open := d.GetSnapshot().OpenEvent; open == nil || open.ProfileID != 7 {
		t.Fatalf("open event = %+v, want profile 7", open)
	}
}

// An outage still open when the profile changes keeps the profile it started
// under and is flagged as spanning the change. The flag is kept when it closes.
func TestSwitchDuringOutageFlagsTheEvent(t *testing.T) {
	clock := &MockClock{curr: time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)}
	d, _ := setupDetector(clock)
	d.SetProfileID(7)
	openOutage(t, d, clock)

	d.Apply(config.Lax(), 8)
	open := d.GetSnapshot().OpenEvent
	if open == nil || open.Flags&detector.EventFlagProfileChanged == 0 {
		t.Fatalf("open event not flagged after the switch: %+v", open)
	}
	if open.ProfileID != 7 {
		t.Fatalf("open event moved to profile %d, want it to keep 7", open.ProfileID)
	}

	var closed *detector.Event
	for i := 0; i < 6 && closed == nil; i++ {
		clock.Advance(time.Second)
		_, closed = sendTick(d, clock, true, true, true)
	}
	if closed == nil {
		t.Fatal("outage should close after healthy results on the new profile")
	}
	if closed.Flags&detector.EventFlagProfileChanged == 0 || closed.ProfileID != 7 {
		t.Fatalf("closed event flags=%d profile=%d, want the change flag and profile 7", closed.Flags, closed.ProfileID)
	}
}

// Switching to a profile row with the same id is not a change, so nothing is
// flagged.
func TestSwitchToTheSameProfileRowDoesNotFlag(t *testing.T) {
	clock := &MockClock{curr: time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)}
	d, _ := setupDetector(clock)
	d.SetProfileID(7)
	openOutage(t, d, clock)

	d.Apply(config.Standard(), 7)
	if flags := d.GetSnapshot().OpenEvent.Flags; flags&detector.EventFlagProfileChanged != 0 {
		t.Fatalf("a switch to the same profile row flagged the event: flags=%d", flags)
	}
}
