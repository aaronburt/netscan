package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aaronburt/netscan/internal/config"
)

func TestDefaultConfig(t *testing.T) {
	cfg := config.DefaultConfig()
	if cfg.HTTP.Port != 9095 {
		t.Fatalf("expected port 9095, got %d", cfg.HTTP.Port)
	}
	if cfg.ActiveProfile != config.ProfileStandard {
		t.Fatalf("expected standard profile, got %q", cfg.ActiveProfile)
	}
	if cfg.Active().Intervals.NormalMS != 1000 {
		t.Fatalf("expected normal interval 1000, got %d", cfg.Active().Intervals.NormalMS)
	}
	if cfg.Retention.RawPartitions != 2 {
		t.Fatalf("expected raw partitions 2, got %d", cfg.Retention.RawPartitions)
	}
}

func TestValidateAndApplyMinimums(t *testing.T) {
	cfg := config.Config{}
	cfg.HTTP.Addr = "0.0.0.0"
	cfg.ValidateAndApplyMinimums()

	if cfg.HTTP.Addr != "127.0.0.1" {
		t.Fatalf("expected non-loopback addr to reset to 127.0.0.1, got %s", cfg.HTTP.Addr)
	}
	if cfg.HTTP.Port != 9095 {
		t.Fatalf("expected port 9095, got %d", cfg.HTTP.Port)
	}
	if cfg.ActiveProfile != config.ProfileStandard {
		t.Fatalf("expected empty active profile to become standard, got %q", cfg.ActiveProfile)
	}
	if cfg.Retention.RollupDays != 7 {
		t.Fatalf("expected 7 days minimum rollup retention, got %d", cfg.Retention.RollupDays)
	}
}

func TestSaveAndLoadConfig(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.json")

	original := config.DefaultConfig()
	original.HTTP.Port = 9999

	err := config.SaveConfig(cfgPath, original)
	if err != nil {
		t.Fatalf("failed to save config: %v", err)
	}

	loaded, err := config.LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if loaded.HTTP.Port != 9999 {
		t.Fatalf("expected port 9999, got %d", loaded.HTTP.Port)
	}

	t.Setenv("NETSCAN_DATA_DIR", tmpDir)
	if config.DataDir() != tmpDir {
		t.Fatalf("expected DataDir to be %s, got %s", tmpDir, config.DataDir())
	}
	ensureDir, err := config.EnsureDataDir()
	if err != nil {
		t.Fatalf("failed to ensure data dir: %v", err)
	}
	if ensureDir != tmpDir {
		t.Fatalf("expected ensure dir to be %s, got %s", tmpDir, ensureDir)
	}
	if _, err := os.Stat(filepath.Join(tmpDir, "logs")); err != nil {
		t.Fatalf("expected logs dir to exist: %v", err)
	}
}

func TestLoadConfigMissingFileWritesDefaults(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	cfg, err := config.LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTP.Port != 9095 {
		t.Fatalf("port = %d", cfg.HTTP.Port)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("defaults not written: %v", err)
	}
}

func TestLoadConfigMalformedJSON(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	_ = os.WriteFile(p, []byte("{not json"), 0o644)
	cfg, err := config.LoadConfig(p)
	if err == nil {
		t.Fatal("expected an error")
	}
	if cfg.HTTP.Port != 9095 {
		t.Fatalf("expected defaults, got port %d", cfg.HTTP.Port)
	}
}

func TestNormalModePeriodDefaults(t *testing.T) {
	iv := config.Standard().Intervals
	if iv.ISPHopMS != 2000 || iv.WANICMPSecondaryMS != 5000 || iv.WANTCPMS != 5000 || iv.DNSMS != 5000 || iv.HTTPMS != 15000 {
		t.Fatalf("unexpected default periods: %+v", iv)
	}
}

// Configs written by older versions don't have the period keys; they should
// pick up the defaults instead of ending up with zero.
func TestOldConfigGetsPeriodDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	old := `{"intervals":{"normal_ms":1000,"fast_ms":500,"fast_exit_healthy_s":10,"fast_max_outage_s":120}}`
	if err := os.WriteFile(path, []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	iv := cfg.Active().Intervals
	if iv.DNSMS != 5000 || iv.HTTPMS != 15000 {
		t.Fatalf("periods not defaulted: %+v", iv)
	}
}

func TestPeriodsNeverBelowNormalInterval(t *testing.T) {
	p := config.Standard()
	p.Intervals.NormalMS = 2000
	p.Intervals.DNSMS = 500
	p.Intervals.HTTPMS = 0
	p.Normalize()
	if p.Intervals.DNSMS != 2000 {
		t.Fatalf("DNSMS = %d, want it raised to 2000", p.Intervals.DNSMS)
	}
	if p.Intervals.HTTPMS != 15000 {
		t.Fatalf("HTTPMS = %d, want the default for an unset value", p.Intervals.HTTPMS)
	}
}

// A custom "http" list must not inherit body_prefix from the default entry
// at the same position, or every check against it would fail.
func TestCustomHTTPTargetsDoNotInheritDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	custom := `{"targets":{"http":[{"url":"http://a.test/x","status":204},{"url":"http://b.test/y","status":200}]}}`
	if err := os.WriteFile(path, []byte(custom), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.Active().Targets.HTTP) != 2 {
		t.Fatalf("got %d http targets, want 2", len(cfg.Active().Targets.HTTP))
	}
	for _, h := range cfg.Active().Targets.HTTP {
		if h.BodyPrefix != "" {
			t.Fatalf("%s inherited body_prefix %q from a default", h.URL, h.BodyPrefix)
		}
	}

	// Leaving "http" out still gives the defaults.
	if err := os.WriteFile(path, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, _ = config.LoadConfig(path)
	if h := cfg.Active().Targets.HTTP; len(h) != 3 || h[1].BodyPrefix == "" {
		t.Fatalf("default http targets not restored: %+v", h)
	}
}

func TestWebUIEnabledDefaultsOnAndPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")

	// A config written before the field existed keeps the dashboard on.
	if err := os.WriteFile(path, []byte(`{"http":{"addr":"127.0.0.1","port":9100}}`), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.HTTP.Enabled || cfg.HTTP.Port != 9100 {
		t.Fatalf("expected enabled with port 9100, got %+v", cfg.HTTP)
	}

	if err := config.SetWebUIEnabled(path, false); err != nil {
		t.Fatal(err)
	}
	cfg, err = config.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTP.Enabled || cfg.HTTP.Port != 9100 {
		t.Fatalf("expected disabled with port kept, got %+v", cfg.HTTP)
	}
}
