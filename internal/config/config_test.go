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
	if cfg.Intervals.NormalMS != 1000 {
		t.Fatalf("expected normal interval 1000, got %d", cfg.Intervals.NormalMS)
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
	if cfg.Intervals.NormalMS != 1000 {
		t.Fatalf("expected 1000ms minimum, got %d", cfg.Intervals.NormalMS)
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
