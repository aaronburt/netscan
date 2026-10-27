//go:build linux

package platform

import (
	"time"

	"golang.org/x/sys/unix"
)

// BootElapsed returns time since boot on CLOCK_BOOTTIME. Unlike wall time it
// is immune to NTP steps (a Pi without an RTC jumps by years after boot), and
// unlike CLOCK_MONOTONIC it keeps counting while the machine is suspended.
func BootElapsed() time.Duration {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return time.Since(processStart)
	}
	return time.Duration(ts.Nano())
}

var processStart = time.Now()
