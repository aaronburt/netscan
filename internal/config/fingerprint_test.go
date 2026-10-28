package config_test

import (
	"testing"

	"github.com/aaronburt/netscan/internal/config"
)

// Renaming a profile changes the snapshot it is saved with but not its settings
// hash, so history can tell a rename from a change in how it polls.
func TestFingerprintIgnoresTheName(t *testing.T) {
	p := config.Standard()
	hash, snapshot := p.Fingerprint()

	p.Name, p.Description = "Renamed", "Other words"
	renamedHash, renamedSnapshot := p.Fingerprint()
	if renamedHash != hash {
		t.Fatal("renaming a profile changed its settings hash")
	}
	if renamedSnapshot == snapshot {
		t.Fatal("the snapshot should record the new name")
	}
}

func TestFingerprintChangesWithSettings(t *testing.T) {
	p := config.Standard()
	hash, _ := p.Fingerprint()

	p.Intervals.NormalMS = 2000
	if changed, _ := p.Fingerprint(); changed == hash {
		t.Fatal("changing an interval did not change the settings hash")
	}
}
