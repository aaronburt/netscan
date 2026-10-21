package updater

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func WaitForPIDExit(pid int, timeout time.Duration) {
	if pid <= 0 {
		return
	}
	h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return
	}
	defer windows.CloseHandle(h)

	event, _ := windows.WaitForSingleObject(h, uint32(timeout.Milliseconds()))
	if event == uint32(windows.WAIT_TIMEOUT) {
		_ = windows.TerminateProcess(h, 0)
		_, _ = windows.WaitForSingleObject(h, 3000)
	}
}

func StopRunningProcessByName(exeName string, timeout time.Duration) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return
	}
	defer windows.CloseHandle(snap)

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	if err := windows.Process32First(snap, &pe); err != nil {
		return
	}

	selfPID := uint32(os.Getpid())
	targetName := strings.ToLower(filepath.Base(exeName))

	for {
		name := strings.ToLower(windows.UTF16ToString(pe.ExeFile[:]))
		if name == targetName && pe.ProcessID != selfPID {
			h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_TERMINATE, false, pe.ProcessID)
			if err == nil {
				event, _ := windows.WaitForSingleObject(h, uint32(timeout.Milliseconds()))
				if event == uint32(windows.WAIT_TIMEOUT) {
					_ = windows.TerminateProcess(h, 0)
					_, _ = windows.WaitForSingleObject(h, 3000)
				}
				_ = windows.CloseHandle(h)
			}
		}
		if err := windows.Process32Next(snap, &pe); err != nil {
			break
		}
	}
}

func StartDetachedProcess(cmd *exec.Cmd) error {
	cmd.SysProcAttr = &windows.SysProcAttr{
		CreationFlags: windows.DETACHED_PROCESS,
	}
	return cmd.Start()
}
