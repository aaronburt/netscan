package main

import (
	"log/slog"

	"github.com/aaronburt/netscan/internal/switcher"
)

// reloadProfileOnSignal does nothing on Windows, which has no SIGHUP. The
// profile is read at start; a reload button is added with the profiles API.
func reloadProfileOnSignal(*slog.Logger, string, *switcher.Switcher) {}
