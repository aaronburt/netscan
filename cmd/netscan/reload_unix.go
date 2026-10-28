//go:build !windows

package main

import (
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

// reloadProfilesOnSignal re-reads the profiles from config.json on SIGHUP, so a
// hand edit applies without a restart. Other settings still need a restart.
func reloadProfilesOnSignal(logger *slog.Logger, reload func() ([]string, error)) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	go func() {
		for range ch {
			warnings, err := reload()
			for _, w := range warnings {
				logger.Warn("config", "warning", w)
			}
			if err != nil {
				logger.Error("reload: profiles not applied", "error", err)
			}
		}
	}()
}
