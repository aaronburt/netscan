package main

import "log/slog"

// reloadProfilesOnSignal does nothing on Windows, which has no SIGHUP. Profiles
// are read at start and reloaded with POST /api/profiles/reload.
func reloadProfilesOnSignal(*slog.Logger, func() ([]string, error)) {}
