//go:build notray

package tray

import (
	"context"

	"github.com/aaronburt/netscan/internal/hub"
	"github.com/aaronburt/netscan/internal/updater"
)

// TrayManager is a no-op in builds made with -tags notray, which drop the
// systray dependency for headless-only deployments. Run returns at once, so
// the caller falls through to its headless signal loop.
type TrayManager struct{}

func NewTrayManager(port func() int, h *hub.Hub, updaterMgr *updater.Manager, onExit func(), onPauseToggle func() bool) *TrayManager {
	return &TrayManager{}
}

func (tm *TrayManager) SetWebUI(enabled bool, toggle func(enable bool) (bool, error)) {}

func (tm *TrayManager) Run(ctx context.Context) {}
