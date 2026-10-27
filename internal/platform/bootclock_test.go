package platform

import (
	"testing"
	"time"
)

func TestBootElapsedAdvances(t *testing.T) {
	a := BootElapsed()
	time.Sleep(5 * time.Millisecond)
	b := BootElapsed()
	if a <= 0 || b < a+4*time.Millisecond {
		t.Fatalf("BootElapsed did not advance: %v then %v", a, b)
	}
}
