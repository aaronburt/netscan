package hub_test

import (
	"testing"
	"time"

	"github.com/aaronburt/netscan/internal/detector"
	"github.com/aaronburt/netscan/internal/hub"
)

// A subscriber that stops reading gets dropped. It must be told, otherwise
// the stream handler waits forever and the dashboard silently freezes.
func TestSlowSubscriberIsToldItWasDropped(t *testing.T) {
	h := hub.NewHub()
	sub := h.Subscribe()

	for i := 0; i < 200; i++ {
		h.PublishSnapshot(detector.Snapshot{})
	}

	select {
	case <-sub.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("dropped subscriber's Done channel was never closed")
	}

	// Unsubscribing afterwards must not panic.
	h.Unsubscribe(sub)
}
