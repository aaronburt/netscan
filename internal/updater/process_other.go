//go:build !windows

package updater

import (
	"os/exec"
	"time"
)

// Non-Windows stubs so the package builds and its tests run on other platforms.

func WaitForPIDExit(pid int, timeout time.Duration) {}

func StopRunningProcessByName(exeName string, timeout time.Duration) {}

func StartDetachedProcess(cmd *exec.Cmd) error {
	return cmd.Start()
}
