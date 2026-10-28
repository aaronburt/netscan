package updater_test

import (
	"context"
	"strings"
	"testing"

	"github.com/aaronburt/netscan/internal/updater"
)

func TestManagerInContainer(t *testing.T) {
	mgr := updater.NewManager("aaronburt/netscan", "0.9.0", nil)
	if mgr.Status().Container {
		t.Fatal("a fresh manager must not report a container")
	}

	mgr.SetContainer(true)
	status := mgr.Status()
	if !status.Container {
		t.Fatal("expected the status to report a container")
	}
	if status.CanApply {
		t.Fatal("a container must not offer to replace its binary")
	}

	err := mgr.Apply(context.Background())
	if err == nil || !strings.Contains(err.Error(), "container") {
		t.Fatalf("expected Apply to refuse in a container, got %v", err)
	}
}
