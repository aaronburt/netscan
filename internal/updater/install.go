package updater

import (
	"fmt"
	"os"
	"time"
)

// InstallBinaryWithRetry moves sourcePath over targetPath, retrying while the
// old binary is still locked by an exiting process.
func InstallBinaryWithRetry(sourcePath, targetPath string) error {
	var lastErr error
	oldPath := targetPath + ".old"

	for i := 0; i < 25; i++ {
		if i > 0 {
			time.Sleep(200 * time.Millisecond)
		}

		_ = os.Remove(oldPath)

		if err := os.Rename(sourcePath, targetPath); err == nil {
			_ = os.Remove(oldPath)
			return nil
		} else {
			lastErr = err
		}

		if err := os.Rename(targetPath, oldPath); err == nil {
			if err := os.Rename(sourcePath, targetPath); err == nil {
				_ = os.Remove(oldPath)
				return nil
			} else {
				_ = os.Rename(oldPath, targetPath)
				lastErr = err
			}
		}
	}

	return fmt.Errorf("failed to install binary to %s: %w", targetPath, lastErr)
}
