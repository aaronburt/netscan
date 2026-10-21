package winapi

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	kernel32       = windows.NewLazySystemDLL("kernel32.dll")
	shell32        = windows.NewLazySystemDLL("shell32.dll")
	procAttachCons = kernel32.NewProc("AttachConsole")
	procShellExecW = shell32.NewProc("ShellExecuteW")
)

const (
	AttachParentProcess = ^uint32(0)
)

type MutexHandle struct {
	handle windows.Handle
}

func (m *MutexHandle) Close() error {
	if m == nil || m.handle == 0 {
		return nil
	}
	err := windows.CloseHandle(m.handle)
	m.handle = 0
	return err
}

func AcquireSingleInstance(name string) (*MutexHandle, bool, error) {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, false, err
	}

	h, err := windows.CreateMutex(nil, false, namePtr)
	if err != nil {
		if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			_ = windows.CloseHandle(h)
			return nil, false, nil
		}
		return nil, false, err
	}

	return &MutexHandle{handle: h}, true, nil
}

func AttachConsoleToParent() bool {
	r, _, _ := procAttachCons.Call(uintptr(AttachParentProcess))
	if r != 0 {
		stdout, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
		if err == nil && stdout != windows.InvalidHandle {
			os.Stdout = os.NewFile(uintptr(stdout), "/dev/stdout")
		}
		stderr, err := windows.GetStdHandle(windows.STD_ERROR_HANDLE)
		if err == nil && stderr != windows.InvalidHandle {
			os.Stderr = os.NewFile(uintptr(stderr), "/dev/stderr")
		}
		return true
	}
	return false
}

func OpenBrowser(targetURL string) error {
	verbPtr, err := windows.UTF16PtrFromString("open")
	if err != nil {
		return err
	}
	urlPtr, err := windows.UTF16PtrFromString(targetURL)
	if err != nil {
		return err
	}
	r, _, _ := procShellExecW.Call(
		0,
		uintptr(unsafe.Pointer(verbPtr)),
		uintptr(unsafe.Pointer(urlPtr)),
		0,
		0,
		windows.SW_SHOWNORMAL,
	)
	if r <= 32 {
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", targetURL).Start()
	}
	return nil
}

func OpenDashboard(targetURL string) error {
	return OpenBrowser(targetURL)
}

func SetAutostart(enabled bool) error {
	key, _, err := registry.CreateKey(
		registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Run`,
		registry.SET_VALUE|registry.QUERY_VALUE,
	)
	if err != nil {
		return err
	}
	defer key.Close()

	if !enabled {
		err := key.DeleteValue("NetScan")
		if err != nil && !errors.Is(err, registry.ErrNotExist) {
			return err
		}
		return nil
	}

	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	cleanPath := filepath.Clean(exePath)
	quoted := fmt.Sprintf("\"%s\"", cleanPath)
	return key.SetStringValue("NetScan", quoted)
}

func IsAutostartEnabled() bool {
	key, err := registry.OpenKey(
		registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Run`,
		registry.QUERY_VALUE,
	)
	if err != nil {
		return false
	}
	defer key.Close()

	val, _, err := key.GetStringValue("NetScan")
	if err != nil || val == "" {
		return false
	}

	exePath, err := os.Executable()
	if err != nil {
		return true
	}
	registered := strings.Trim(strings.TrimSpace(val), `"`)
	return strings.EqualFold(filepath.Clean(registered), filepath.Clean(exePath))
}
