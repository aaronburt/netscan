package config_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/aaronburt/netscan/internal/config"
)

func write(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func customProfile(id string) config.Profile {
	p := config.Standard()
	p.ID = id
	p.Name = "Custom " + id
	p.BuiltIn = false
	return p
}

func TestBuiltInsAreValidAndInsideLimits(t *testing.T) {
	for _, p := range config.BuiltInProfiles() {
		c := p.Validate()
		if len(c.Errors) > 0 || len(c.Warnings) > 0 {
			t.Errorf("%s: errors %v warnings %v", p.ID, c.Errors, c.Warnings)
		}
		if !p.BuiltIn || !config.IsReservedProfileID(p.ID) {
			t.Errorf("%s should be built-in and reserved", p.ID)
		}
	}
}

func TestBuiltInValues(t *testing.T) {
	a, l := config.Aggressive(), config.Lax()
	if a.Mode != config.ModeParallel || a.Intervals.NormalMS != 500 || a.Intervals.HTTPMS != 5000 || a.TimeoutsMS.ICMP != 800 {
		t.Errorf("aggressive: %+v", a)
	}
	if l.Mode != config.ModeRotating || l.Intervals.NormalMS != 5000 || l.Intervals.HTTPMS != 60000 || l.TimeoutsMS.HTTP != 4000 {
		t.Errorf("lax: %+v", l)
	}
	// Built-ins don't share slices, so editing a copy can't change them.
	s := config.Standard()
	s.Targets.WANICMP[0] = "10.0.0.1"
	if config.Standard().Targets.WANICMP[0] != "1.1.1.1" {
		t.Error("Standard() shares host slices between calls")
	}
}

func TestValidateRules(t *testing.T) {
	tests := []struct {
		name   string
		mut    func(*config.Profile)
		field  string
		isWarn bool
	}{
		{"bad id", func(p *config.Profile) { p.ID = "Bad ID" }, "id", false},
		{"no name", func(p *config.Profile) { p.Name = " " }, "name", false},
		{"bad mode", func(p *config.Profile) { p.Mode = "turbo" }, "mode", false},
		{"one layer", func(p *config.Profile) { p.Targets.DNS = nil; p.Targets.HTTP = nil }, "targets", false},
		{"one host", func(p *config.Profile) { p.Targets.WANTCP = p.Targets.WANTCP[:1] }, "targets.wan_tcp", false},
		{"duplicate", func(p *config.Profile) { p.Targets.DNS = []string{"1.1.1.1:53", "1.1.1.1:53"} }, "targets.dns[1]", false},
		{"bad url", func(p *config.Profile) { p.Targets.HTTP[0].URL = "ftp://x" }, "targets.http[0].url", false},
		{"fast too fast", func(p *config.Profile) { p.Intervals.FastMS = 100 }, "intervals.fast_ms", true},
		{"icmp too fast", func(p *config.Profile) { p.Intervals.NormalMS = 200 }, "hosts.1.1.1.1", true},
		{"http too fast", func(p *config.Profile) { p.Mode = config.ModeParallel; p.Intervals.HTTPMS = 1000 }, "hosts.http://connectivitycheck.gstatic.com/generate_204", true},
		{"too many hosts", func(p *config.Profile) {
			for i := 0; i < 9; i++ {
				p.Targets.WANICMP = append(p.Targets.WANICMP, "203.0.113."+string(rune('1'+i)))
			}
		}, "targets.wan_icmp", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := customProfile("c")
			tc.mut(&p)
			c := p.Validate()
			issues := c.Errors
			if tc.isWarn {
				issues = c.Warnings
			}
			for _, is := range issues {
				if is.Field == tc.field {
					return
				}
			}
			t.Fatalf("no issue on %q: %+v", tc.field, c)
		})
	}
}

func TestPrivateHostsExemptFromWarnings(t *testing.T) {
	p := customProfile("lan")
	p.Mode = config.ModeParallel
	p.Intervals.NormalMS = 200
	p.Intervals.WANICMPSecondaryMS = 200
	p.Targets.WANICMP = []string{"192.168.1.1", "10.0.0.2", "127.0.0.1"}
	p.Intervals.ISPHopMS = 2000
	for _, w := range p.Validate().Warnings {
		if strings.HasPrefix(w.Field, "hosts.") {
			t.Fatalf("private host warned: %+v", w)
		}
	}
}

func TestEstimate(t *testing.T) {
	e := config.Standard().Estimate()
	// gateway 1/s + ISP 0.5/s + first ping 1/s + 2 secondaries 0.1/s each,
	// then tcp/dns 0.2/s and http 1/15s per layer.
	want := 1 + 0.5 + 1 + 0.2 + 0.2 + 0.2 + 1.0/15
	if d := e.ProbesPerSec - want; d > 0.001 || d < -0.001 {
		t.Errorf("probes/s = %.4f, want %.4f", e.ProbesPerSec, want)
	}
	if e.RemoteProbesPerSec >= e.ProbesPerSec {
		t.Errorf("gateway should not count as remote: %+v", e)
	}
	if e.RowsPerDay != int64(e.ProbesPerSec*86400+0.5) {
		t.Errorf("rows/day = %d", e.RowsPerDay)
	}
	if e.MinDetectableOutageMS != 1000+500+2000 {
		t.Errorf("min detectable = %d", e.MinDetectableOutageMS)
	}

	// Parallel probes every host each period, so it costs more than the same
	// periods rotating.
	rot := config.Aggressive()
	rot.Mode = config.ModeRotating
	if config.Aggressive().Estimate().ProbesPerSec <= rot.Estimate().ProbesPerSec {
		t.Error("parallel should cost more than rotating")
	}
	if config.Lax().Estimate().ProbesPerSec >= e.ProbesPerSec {
		t.Error("lax should cost less than standard")
	}
}

func TestMigrationUnedited(t *testing.T) {
	// A config with the stock values, as older versions wrote it.
	old := config.Standard()
	body, _ := json.Marshal(map[string]any{
		"http":        map[string]any{"enabled": true, "addr": "127.0.0.1", "port": 9095},
		"intervals":   old.Intervals,
		"timeouts_ms": old.TimeoutsMS,
		"targets":     old.Targets,
	})
	cfg, err := config.LoadConfig(write(t, string(body)))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ActiveProfile != config.ProfileStandard || len(cfg.Profiles) != 0 {
		t.Fatalf("active %q, custom %d; want standard and none", cfg.ActiveProfile, len(cfg.Profiles))
	}
}

func TestMigrationEdited(t *testing.T) {
	path := write(t, `{"intervals":{"normal_ms":2000},"targets":{"wan_icmp":["9.9.9.9","8.8.8.8"]}}`)
	cfg, err := config.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ActiveProfile != config.LegacyProfileID || len(cfg.Profiles) != 1 {
		t.Fatalf("active %q, custom %d", cfg.ActiveProfile, len(cfg.Profiles))
	}
	p := cfg.Active()
	if p.Name != config.LegacyProfileName || p.BuiltIn {
		t.Errorf("profile = %+v", p)
	}
	if p.Intervals.NormalMS != 2000 || p.Intervals.FastMS != 500 || len(p.Targets.WANICMP) != 2 || len(p.Targets.DNS) != 3 {
		t.Errorf("settings not carried over with defaults filled in: %+v", p)
	}

	// Nothing is written until the first save, which backs up the old file.
	before, _ := os.ReadFile(path)
	if !strings.Contains(string(before), `"intervals"`) || strings.Contains(string(before), "active_profile") {
		t.Fatalf("load rewrote the file: %s", before)
	}
	if err := config.SaveConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	bak, err := os.ReadFile(path + ".bak")
	if err != nil || string(bak) != string(before) {
		t.Fatalf("backup missing or different: %v %q", err, bak)
	}
	after, _ := os.ReadFile(path)
	if strings.Contains(string(after), `"intervals":{"normal_ms"`) || !strings.Contains(string(after), "active_profile") {
		t.Fatalf("new shape not written: %s", after)
	}
	again, err := config.LoadConfig(path)
	if err != nil || again.ActiveProfile != config.LegacyProfileID || again.Active().Intervals.NormalMS != 2000 {
		t.Fatalf("round trip lost the profile: %v %+v", err, again.ActiveProfile)
	}

	// A second save must not overwrite the backup with the new shape.
	if err := config.SaveConfig(path, again); err != nil {
		t.Fatal(err)
	}
	if bak2, _ := os.ReadFile(path + ".bak"); string(bak2) != string(before) {
		t.Fatal("backup was overwritten")
	}
}

func TestMigrationKeepsLegacyEvenIfRulesBroken(t *testing.T) {
	cfg, err := config.LoadConfig(write(t, `{"targets":{"wan_tcp":["1.1.1.1:443"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ActiveProfile != config.LegacyProfileID || len(cfg.Active().Targets.WANTCP) != 1 {
		t.Fatalf("legacy settings dropped: %q", cfg.ActiveProfile)
	}
	if len(cfg.LoadWarnings) == 0 {
		t.Error("expected a warning")
	}
}

func TestNewShapeLoad(t *testing.T) {
	good := customProfile("home")
	bad := customProfile("broken")
	bad.Targets.DNS, bad.Targets.HTTP = nil, nil
	reserved := customProfile("lax")
	dup := customProfile("home")
	body, _ := json.Marshal(config.Config{
		ActiveProfile: "home",
		Profiles:      []config.Profile{good, bad, reserved, dup},
	})
	cfg, err := config.LoadConfig(write(t, string(body)))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Profiles) != 1 || cfg.Profiles[0].ID != "home" {
		t.Fatalf("profiles = %+v", cfg.Profiles)
	}
	if len(cfg.LoadWarnings) != 3 {
		t.Errorf("warnings = %v", cfg.LoadWarnings)
	}
	if cfg.Active().ID != "home" {
		t.Errorf("active = %q", cfg.Active().ID)
	}
	if _, ok := cfg.FindProfile(config.ProfileAggressive); !ok {
		t.Error("built-ins should always be found")
	}
	if n := len(cfg.AllProfiles()); n != 4 {
		t.Errorf("AllProfiles = %d, want 3 built-in + 1 custom", n)
	}
}

func TestUnknownActiveProfileFallsBack(t *testing.T) {
	cfg, err := config.LoadConfig(write(t, `{"active_profile":"gone"}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ActiveProfile != config.ProfileStandard || len(cfg.LoadWarnings) != 1 {
		t.Fatalf("active %q warnings %v", cfg.ActiveProfile, cfg.LoadWarnings)
	}
}

func TestSelectBuiltInActive(t *testing.T) {
	cfg, _ := config.LoadConfig(write(t, `{"active_profile":"aggressive"}`))
	if p := cfg.Active(); p.ID != config.ProfileAggressive || p.Mode != config.ModeParallel {
		t.Fatalf("active = %+v", p)
	}
}

func TestSaveLeavesNoTempFilesAndSurvivesConcurrentSaves(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cfg := config.DefaultConfig()
			cfg.Profiles = []config.Profile{customProfile("p")}
			if err := config.SaveConfig(path, cfg); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()

	entries, _ := os.ReadDir(filepath.Dir(path))
	for _, e := range entries {
		if e.Name() != "config.json" {
			t.Errorf("stray file %s", e.Name())
		}
	}
	if _, err := config.LoadConfig(path); err != nil {
		t.Fatalf("config unreadable after concurrent saves: %v", err)
	}
}

func TestSaveFailureKeepsOldFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := config.SaveConfig(path, config.DefaultConfig()); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)

	bad := config.DefaultConfig()
	bad.Latency.MADK = nan()
	if err := config.SaveConfig(path, bad); err == nil {
		t.Fatal("expected a marshal error")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("failed save changed the file")
	}
}

func nan() float64 {
	z := 0.0
	return z / z
}
