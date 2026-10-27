//go:build linux

package platform

import (
	"errors"
	"net"
	"time"
)

// Linux stubs. The real implementations arrive in a follow-up change; until
// then they let the platform-independent packages build and test on Linux.

var errUnsupported = errors.New("platform: not supported on this platform")

type MutexHandle struct{}

func (m *MutexHandle) Close() error { return nil }

func AcquireSingleInstance(name string) (*MutexHandle, bool, error) {
	return &MutexHandle{}, true, nil
}

func AttachConsoleToParent() bool { return false }

func OpenBrowser(targetURL string) error { return errUnsupported }

func OpenDashboard(targetURL string) error { return errUnsupported }

func SetAutostart(enabled bool) error { return errUnsupported }

func IsAutostartEnabled() bool { return false }

func SendEcho(ip net.IP, ttl byte, timeout time.Duration, seq uint64) (EchoResult, error) {
	return EchoResult{}, errUnsupported
}

func DiscoverNetworkInfo() (NetworkInfo, error) {
	return NetworkInfo{}, errUnsupported
}

func ResolveMAC(ip net.IP) string { return "" }
