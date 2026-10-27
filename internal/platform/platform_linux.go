//go:build linux

package platform

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

var errUnsupported = errors.New("platform: not supported on this platform")

// MutexHandle holds the flock that marks this process as the running instance.
type MutexHandle struct {
	file *os.File
}

func (m *MutexHandle) Close() error {
	if m == nil || m.file == nil {
		return nil
	}
	// Closing the descriptor releases the lock.
	err := m.file.Close()
	m.file = nil
	return err
}

// AcquireSingleInstance takes an exclusive, non-blocking flock on a lock file
// named after the instance. The kernel drops the lock when the process dies,
// so a crash never leaves a stale lock behind.
func AcquireSingleInstance(name string) (*MutexHandle, bool, error) {
	f, err := os.OpenFile(lockPath(name), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, false, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return &MutexHandle{file: f}, true, nil
}

func lockPath(name string) string {
	dir := runtimeDir(os.Getenv)
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			return r
		}
		return '_'
	}, name)
	return filepath.Join(dir, safe+".lock")
}

// runtimeDir picks where the lock file goes. A system service has no
// XDG_RUNTIME_DIR, but systemd's RuntimeDirectory= sets RUNTIME_DIRECTORY.
func runtimeDir(getenv func(string) string) string {
	if dir := getenv("RUNTIME_DIRECTORY"); dir != "" {
		// systemd may list several directories separated by a colon.
		return strings.SplitN(dir, ":", 2)[0]
	}
	if dir := getenv("XDG_RUNTIME_DIR"); dir != "" {
		return dir
	}
	return os.TempDir()
}

func AttachConsoleToParent() bool { return false }

// OpenBrowser opens the URL with xdg-open. The helper is started and
// reaped in the background so a slow browser launch never blocks the caller.
func OpenBrowser(targetURL string) error {
	path, err := exec.LookPath("xdg-open")
	if err != nil {
		return fmt.Errorf("xdg-open not found: %w", err)
	}
	cmd := exec.Command(path, targetURL)
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}

func OpenDashboard(targetURL string) error { return OpenBrowser(targetURL) }

// Autostart on Linux is handled by the systemd unit, not by the app.
func SetAutostart(enabled bool) error { return errUnsupported }

func IsAutostartEnabled() bool { return false }
