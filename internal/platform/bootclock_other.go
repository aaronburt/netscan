//go:build !linux

package platform

import "time"

var processStart = time.Now()

// BootElapsed returns a steady clock reading that ignores wall-clock steps.
// time.Since uses the runtime's monotonic clock.
func BootElapsed() time.Duration { return time.Since(processStart) }
