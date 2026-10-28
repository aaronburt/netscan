//go:build !windows

package main

import (
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/aaronburt/netscan/internal/config"
	"github.com/aaronburt/netscan/internal/switcher"
)

// reloadProfileOnSignal re-reads the config file on SIGHUP and switches to
// its active profile without a restart. Only the polling profile is applied;
// other settings still need a restart.
func reloadProfileOnSignal(logger *slog.Logger, configPath string, sw *switcher.Switcher) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	go func() {
		for range ch {
			cfg, err := config.LoadConfig(configPath)
			if err != nil {
				logger.Warn("reload: config loaded with fallback defaults", "error", err)
			}
			if err := sw.Apply(cfg.Active()); err != nil {
				logger.Error("reload: profile not applied", "error", err)
			}
		}
	}()
}
